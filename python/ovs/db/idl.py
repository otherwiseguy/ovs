# Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import enum
import functools
import uuid

import ovs.db.cs
import ovs.db.data as data
import ovs.db.schema
import ovs.jsonrpc
import ovs.ovsuuid
import ovs.poller
import ovs.vlog
from ovs.db import custom_index
from ovs.db import error

vlog = ovs.vlog.Vlog("idl")

__pychecker__ = 'no-classattr no-objattrs'

ROW_CREATE = "create"
ROW_UPDATE = "update"
ROW_DELETE = "delete"

OVSDB_UPDATE = "update"
OVSDB_UPDATE2 = "update2"
OVSDB_UPDATE3 = "update3"

# Result of processing a single <row-update>.
OVSDB_IDL_UPDATE_DB_CHANGED = 0
OVSDB_IDL_UPDATE_NO_CHANGES = 1
OVSDB_IDL_UPDATE_INCONSISTENT = 2

CLUSTERED = "clustered"
RELAY = "relay"


Notice = collections.namedtuple('Notice', ('event', 'row', 'updates'))
Notice.__new__.__defaults__ = (None,)  # default updates=None


class ColumnDefaultDict(dict):
    """A column dictionary with on-demand generated default values

    This object acts like the Row._data column dictionary, but without the
    necessity of populating column default values. These values are generated
    on-demand and therefore only use memory once they are accessed.
    """
    __slots__ = ('_table', )

    def __init__(self, table):
        self._table = table
        super().__init__()

    def __missing__(self, column):
        column = self._table.columns[column]
        return ovs.db.data.Datum.default(column.type)

    def keys(self):
        return self._table.columns.keys()

    def values(self):
        return iter(self[k] for k in self)

    def __iter__(self):
        return iter(self.keys())

    def __contains__(self, item):
        return item in self.keys()


class Monitor(enum.Enum):
    monitor = OVSDB_UPDATE
    monitor_cond = OVSDB_UPDATE2
    monitor_cond_since = OVSDB_UPDATE3


class ConditionState(object):
    def __init__(self):
        self._ack_cond = [True]
        self._req_cond = None
        self._new_cond = None

    def __iter__(self):
        return iter([self._new_cond, self._req_cond, self._ack_cond])

    @property
    def new(self):
        """The latest freshly initialized condition change"""
        return self._new_cond

    @property
    def acked(self):
        """The last condition change that has been accepted by the server"""
        return self._ack_cond

    @property
    def requested(self):
        """A condition that's been requested, but not acked by the server"""
        return self._req_cond

    @property
    def latest(self):
        """The most recent condition change"""
        return next(cond for cond in self if cond is not None)

    @staticmethod
    def is_true(condition):
        return condition == [True]

    def init(self, cond):
        """Signal that a condition change is being initiated"""
        self._new_cond = cond

    def ack(self):
        """Signal that a condition change has been acked"""
        if self._req_cond is not None:
            self._ack_cond, self._req_cond = (self._req_cond, None)

    def request(self):
        """Signal that a condition change has been requested"""
        if self._new_cond is not None:
            self._req_cond, self._new_cond = (self._new_cond, None)


class IdlTable(object):
    def __init__(self, idl, table):
        assert isinstance(table, ovs.db.schema.TableSchema)
        self._table = table
        self.need_table = False
        self.rows = custom_index.IndexedRows(self)
        self.idl = idl
        self.columns = {k: IdlColumn(v) for k, v in table.columns.items()}

    def __getattr__(self, attr):
        return getattr(self._table, attr)

    @property
    def condition_state(self):
        # The condition state lives in the CS layer.  Read-only, no setter.
        return self.idl.cs.data.tables[self.name].condition_state

    @property
    def condition(self):
        return self.condition_state.latest

    @condition.setter
    def condition(self, condition):
        assert isinstance(condition, list)
        self.idl.cond_change(self.name, condition)

    @classmethod
    def schema_tables(cls, idl, schema):
        return {k: cls(idl, v) for k, v in schema.tables.items()}


class IdlColumn(object):
    def __init__(self, column):
        self._column = column
        self.alert = True

    def __getattr__(self, attr):
        return getattr(self._column, attr)


class Idl(object):
    """Open vSwitch Database Interface Definition Language (OVSDB IDL).

    The OVSDB IDL maintains an in-memory replica of a database.  It issues RPC
    requests to an OVSDB database server and parses the responses, converting
    raw JSON into data structures that are easier for clients to digest.

    The IDL also assists with issuing database transactions.  The client
    creates a transaction, manipulates the IDL data structures, and commits or
    aborts the transaction.  The IDL then composes and issues the necessary
    JSON-RPC requests and reports to the client whether the transaction
    completed successfully.

    The client is allowed to access the following attributes directly, in a
    read-only fashion:

    - 'tables': This is the 'tables' map in the ovs.db.schema.DbSchema provided
      to the Idl constructor.  Each ovs.db.schema.TableSchema in the map is
      annotated with a new attribute 'rows', which is a dict from a uuid.UUID
      to a Row object.

      The client may directly read and write the Row objects referenced by the
      'rows' map values.  Refer to Row for more details.

    - 'change_seqno': A number that represents the IDL's state.  When the IDL
      is updated (by Idl.run()), its value changes.  The sequence number can
      occasionally change even if the database does not.  This happens if the
      connection to the database drops and reconnects, which causes the
      database contents to be reloaded even if they didn't change.  (It could
      also happen if the database server sends out a "change" that reflects
      what the IDL already thought was in the database.  The database server is
      not supposed to do that, but bugs could in theory cause it to do so.)

    - 'lock_name': The name of the lock configured with Idl.set_lock(), or None
      if no lock is configured.

    - 'has_lock': True, if the IDL is configured to obtain a lock and owns that
      lock, and False otherwise.

      Locking and unlocking happens asynchronously from the database client's
      point of view, so the information is only useful for optimization
      (e.g. if the client doesn't have the lock then there's no point in trying
      to write to the database).

    - 'is_lock_contended': True, if the IDL is configured to obtain a lock but
      the database server has indicated that some other client already owns the
      requested lock, and False otherwise.

    - 'txn': The ovs.db.idl.Transaction object for the database transaction
      currently being constructed, if there is one, or None otherwise.
"""

    IDL_S_INITIAL = 0
    IDL_S_SERVER_SCHEMA_REQUESTED = 1
    IDL_S_SERVER_MONITOR_REQUESTED = 2
    IDL_S_DATA_MONITOR_REQUESTED = 3
    IDL_S_DATA_MONITOR_COND_REQUESTED = 4
    IDL_S_DATA_MONITOR_COND_SINCE_REQUESTED = 5
    IDL_S_MONITORING = 6

    monitor_map = {
        Monitor.monitor: IDL_S_SERVER_MONITOR_REQUESTED,
        Monitor.monitor_cond: IDL_S_DATA_MONITOR_COND_REQUESTED,
        Monitor.monitor_cond_since: IDL_S_DATA_MONITOR_COND_SINCE_REQUESTED}

    def __init__(self, remote, schema_helper, probe_interval=None,
                 leader_only=True):
        """Creates and returns a connection to the database named 'db_name' on
        'remote', which should be in a form acceptable to
        ovs.jsonrpc.session.open().  The connection will maintain an in-memory
        replica of the remote database.

        'remote' can be comma separated multiple remotes and each remote
        should be in a form acceptable to ovs.jsonrpc.session.open().

        'schema_helper' should be an instance of the SchemaHelper class which
        generates schema for the remote database. The caller may have cut it
        down by removing tables or columns that are not of interest.  The IDL
        will only replicate the tables and columns that remain.  The caller may
        also add an attribute named 'alert' to selected remaining columns,
        setting its value to False; if so, then changes to those columns will
        not be considered changes to the database for the purpose of the return
        value of Idl.run() and Idl.change_seqno.  This is useful for columns
        that the IDL's client will write but not read.

        As a convenience to users, 'schema' may also be an instance of the
        SchemaHelper class.

        The IDL uses and modifies 'schema' directly.

        If 'leader_only' is set to True (default value) the IDL will only
        monitor and transact with the leader of the cluster.

        If "probe_interval" is zero it disables the connection keepalive
        feature. If non-zero the value will be forced to at least 1000
        milliseconds. If None it will just use the default value in OVS.
        """

        assert isinstance(schema_helper, SchemaHelper)
        schema = schema_helper.get_idl_schema()

        self.tables = IdlTable.schema_tables(self, schema)
        self.readonly = schema.readonly
        self._db = schema

        # The client-synchronization layer owns the jsonrpc session, the
        # connection/monitor state machine, the _Server/cluster monitor,
        # locking, and the condition engine.  The IDL registers itself as the
        # CS layer's 'ops' so that CS can call back into
        # compose_monitor_requests() to learn which columns to replicate.
        self.cs = ovs.db.cs.Cs(remote, schema.name, list(self.tables.keys()),
                               self, probe_interval=probe_interval,
                               leader_only=leader_only)

        self.change_seqno = 0

        # Transaction support.
        self.txn = None
        self._outstanding_txns = {}

    # --- Thin delegations to the CS layer (preserve the public interface) ---

    @property
    def _session(self):
        return self.cs.session

    @property
    def state(self):
        return self.cs.state

    @property
    def lock_name(self):
        return self.cs.get_lock()

    @property
    def has_lock(self):
        return self.cs.has_lock()

    @property
    def is_lock_contended(self):
        return self.cs.is_lock_contended()

    @property
    def cond_seqno(self):
        return self.cs.get_condition_seqno()

    @property
    def cluster_id(self):
        return self.cs.cluster_id

    def set_cluster_id(self, cluster_id):
        """Set the id of the cluster that this idl must connect to."""
        self.cs.set_cluster_id(cluster_id)

    def set_remote(self, remote, retry=True):
        """Makes the IDL reconnect to 'remote' in place of its current target,
        or disconnect entirely if 'remote' is None.  If 'retry' is false, the
        IDL makes a single pass through the remotes and then gives up."""
        self.cs.set_remote(remote, retry)

    def set_shuffle_remotes(self, shuffle):
        """Set whether the IDL shuffles the order of the remotes each time it
        (re)connects, for load balancing."""
        self.cs.set_shuffle_remotes(shuffle)

    def enable_reconnect(self):
        """Re-enables reconnection to the database after it was disabled by a
        set_remote() call with retry=False."""
        self.cs.enable_reconnect()

    def set_leader_only(self, leader_only):
        """Set whether this idl must connect to the cluster leader."""
        self.cs.set_leader_only(leader_only)

    def reset_min_index(self):
        """Resets the minimum index that the IDL will accept from the database,
        allowing a new server with a lower index to be used."""
        self.cs.reset_min_index()

    def flag_inconsistency(self):
        """Tells the IDL that the client detected an inconsistency in the
        database, so it must reconnect and re-download the whole database."""
        self.cs.flag_inconsistency()

    def set_db_change_aware(self, db_change_aware):
        """Passes 'db_change_aware' to Cs.set_db_change_aware().  See that
        method for documentation."""
        self.cs.set_db_change_aware(db_change_aware)

    def set_jsonrpc_options(self, probe_interval=None, max_backoff=None):
        """Passes the given JSON-RPC session options to
        Cs.set_jsonrpc_options().  See that method for documentation."""
        self.cs.set_jsonrpc_options(probe_interval=probe_interval,
                                    max_backoff=max_backoff)

    def index_create(self, table, name):
        """Create a named multi-column index on a table"""
        return self.tables[table].rows.index_create(name)

    def index_irange(self, table, name, start, end):
        """Return items in a named index between start/end inclusive"""
        return self.tables[table].rows.indexes[name].irange(start, end)

    def index_equal(self, table, name, value):
        """Return items in a named index matching a value"""
        return self.tables[table].rows.indexes[name].irange(value, value)

    def close(self):
        """Closes the connection to the database.  The IDL will no longer
        update."""
        self.cs.close()

    def compose_monitor_requests(self, server_schema=None):
        """Down-call from the CS layer: returns the <monitor-requests> object
        describing the columns the IDL wants to replicate.  The CS layer layers
        the per-table conditions ("where" clauses) on top itself.

        'server_schema' is the server's schema for this database, or None if it
        is not known; it is unused here but present so the CS layer can call
        this uniformly for every database."""
        monitor_requests = {}
        for table in self.tables.values():
            columns = []
            for column in table.columns.keys():
                if ((table.name not in self.readonly) or
                        (table.name in self.readonly) and
                        (column not in self.readonly[table.name])):
                    columns.append(column)
            monitor_requests[table.name] = [{"columns": columns}]
        return monitor_requests

    def run(self):
        """Processes a batch of messages from the database server.  Returns
        True if the database as seen through the IDL changed, False if it did
        not change.  The initial fetch of the entire contents of the remote
        database is considered to be one kind of change.  If the IDL has been
        configured to acquire a database lock (with Idl.set_lock()), then
        successfully acquiring the lock is also considered to be a change.

        This function can return occasional false positives, that is, report
        that the database changed even though it didn't.  This happens if the
        connection to the database drops and reconnects, which causes the
        database contents to be reloaded even if they didn't change.  (It could
        also happen if the database server sends out a "change" that reflects
        what we already thought was in the database, but the database server is
        not supposed to do that.)

        As an alternative to checking the return value, the client may check
        for changes in self.change_seqno."""
        assert not self.txn
        initial_change_seqno = self.change_seqno

        for event in self.cs.run():
            if isinstance(event, ovs.db.cs.ReconnectEvent):
                self.__txn_abort_all()
            elif isinstance(event, ovs.db.cs.LockedEvent):
                # If the client couldn't run a transaction because it didn't
                # have the lock, this will encourage it to try again.  But if
                # we're still setting up the session, don't signal that the
                # database changed; finalizing the session (the monitor reply)
                # will increment change_seqno anyhow.
                if self.cs.may_send_transaction():
                    self.change_seqno += 1
            elif isinstance(event, ovs.db.cs.UpdateEvent):
                if event.monitor_reply:
                    # Even if the data is unchanged, a monitor reply signals a
                    # (re)connection, which is considered a change.
                    self.change_seqno += 1
                if event.clear:
                    self._clear()
                self.__parse_update(event.table_updates, event.version)
            elif isinstance(event, ovs.db.cs.TxnReplyEvent):
                self.__txn_process_reply(event.msg)

        return initial_change_seqno != self.change_seqno

    def cond_change(self, table_name, cond):
        """Sets the condition for 'table_name' to 'cond', which should be a
        conditional expression suitable for use directly in the OVSDB
        protocol, with the exception that the empty condition []
        matches no rows (instead of matching every row).  That is, []
        is equivalent to [False], not to [True].
        """
        return self.cs.set_condition(table_name, cond)

    def wait(self, poller):
        """Arranges for poller.block() to wake up when self.run() has something
        to do or when activity occurs on a transaction on 'self'."""
        self.cs.wait(poller)

    def has_ever_connected(self):
        """Returns True, if the IDL successfully connected to the remote
        database and retrieved its contents (even if the connection
        subsequently dropped and is in the process of reconnecting).  If so,
        then the IDL contains an atomic snapshot of the database's contents
        (but it might be arbitrarily old if the connection dropped).

        Returns False if the IDL has never connected or retrieved the
        database's contents.  If so, the IDL is empty."""
        return self.change_seqno != 0

    def force_reconnect(self):
        """Forces the IDL to drop its connection to the database and reconnect.
        In the meantime, the contents of the IDL will not change."""
        self.cs.force_reconnect()

    def session_name(self):
        return self.cs.session_name()

    def set_lock(self, lock_name):
        """If 'lock_name' is not None, configures the IDL to obtain the named
        lock from the database server and to avoid modifying the database when
        the lock cannot be acquired (that is, when another client has the same
        lock).

        If 'lock_name' is None, drops the locking requirement and releases the
        lock."""
        assert not self.txn
        assert not self._outstanding_txns
        self.cs.set_lock(lock_name)

    def notify(self, event, row, updates=None):
        """Hook for implementing create/update/delete notifications

        :param event:   The event that was triggered
        :type event:    ROW_CREATE, ROW_UPDATE, or ROW_DELETE
        :param row:     The row as it is after the operation has occured
        :type row:      Row
        :param updates: For updates, row with only old values of the changed
                        columns
        :type updates:  Row
        """

    def cooperative_yield(self):
        """Hook for cooperatively yielding to eventlet/gevent/asyncio/etc.

        When a block of code is going to spend a lot of time cpu-bound without
        doing any I/O, it can cause greenthread/coroutine libraries to block.
        This call should be added to code where this can happen, but defaults
        to doing nothing to avoid overhead where it is not needed.
        """

    def _clear(self):
        for table in self.tables.values():
            table.rows.clear()

        self.change_seqno += 1

    def __parse_update(self, update, version):
        try:
            self._do_parse_update(update, version, self.tables)
        except error.Error as e:
            vlog.err("%s: error parsing update: %s"
                     % (self.session_name(), e))

    def _do_parse_update(self, table_updates, version, tables):
        # The wire-format parsing (envelope, UUID validation, and the version
        # 1 vs. version 2/3 row-update demux) is shared with the _Server
        # replica in ovs.db.cs, mirroring the C code where both databases go
        # through ovsdb_cs_parse_db_update().
        db_update = ovs.db.cs.parse_db_update(table_updates, version)

        notices = []
        for table_name, row_updates in db_update.items():
            table = tables.get(table_name)
            if not table:
                raise error.Error('<table-updates> includes unknown '
                                  'table "%s"' % table_name)

            for ru in row_updates:
                self.cooperative_yield()
                result, notice = self._process_row_update(table, ru)

                if result == OVSDB_IDL_UPDATE_INCONSISTENT:
                    # The IDL ended up in an inconsistent state, e.g. because
                    # of a bug in the ovsdb-server/ovsdb-idl.  Even though the
                    # client could recover, it's best to reconnect and resync
                    # the whole database (potentially from a different server).
                    self.flag_inconsistency()
                    raise error.Error("<row-update> received for inconsistent "
                                      "IDL: reconnecting IDL and resync all "
                                      "data")

                if result == OVSDB_IDL_UPDATE_DB_CHANGED:
                    notices.append(notice)
                    self.change_seqno += 1
        for notice in notices:
            self.notify(*notice)

    def _process_row_update(self, table, ru):
        """Applies a single parsed ovs.db.cs.RowUpdate 'ru' to 'table'.
        Returns a tuple (result, notice), mirroring ovsdb_idl_process_update().

        'result' is one of OVSDB_IDL_UPDATE_DB_CHANGED,
        OVSDB_IDL_UPDATE_NO_CHANGES or OVSDB_IDL_UPDATE_INCONSISTENT, and
        'notice' is a Notice describing the change or None.

        Some IDL inconsistencies can be detected when processing updates:
        - trying to insert an already existing row
        - trying to update a missing row
        - trying to delete a non existent row

        In such cases OVSDB_IDL_UPDATE_INCONSISTENT is returned.  Even though
        the client could recover, it's best to report the inconsistent state
        because the state the server is in is unknown, so the safest thing to
        do is to retry (potentially connecting to a new server)."""
        uuid = ru.uuid
        row = table.rows.get(uuid)

        if ru.type == ovs.db.cs.ROW_UPDATE_DELETE:
            if row:
                del table.rows[uuid]
                return OVSDB_IDL_UPDATE_DB_CHANGED, Notice(ROW_DELETE, row)
            # XXX rate-limit
            vlog.err("cannot delete missing row %s from table %s"
                     % (uuid, table.name))
            return OVSDB_IDL_UPDATE_INCONSISTENT, None

        if ru.type == ovs.db.cs.ROW_UPDATE_INSERT:
            if row:
                # XXX rate-limit
                vlog.err("cannot add existing row %s to table %s"
                         % (uuid, table.name))
                return OVSDB_IDL_UPDATE_INCONSISTENT, None
            row = self.__create_row(table, uuid)
            self.__add_default(table, ru.columns)
            changed = self.__row_update(table, row, ru.columns)
            table.rows[uuid] = row
            if changed:
                return OVSDB_IDL_UPDATE_DB_CHANGED, Notice(ROW_CREATE, row)
            return OVSDB_IDL_UPDATE_NO_CHANGES, None

        # ROW_UPDATE_UPDATE (a version 1 "new" <row> with the new values of the
        # changed columns) or ROW_UPDATE_XOR (a version 2/3 "modify" diff).
        # Both modify an existing row.
        if not row:
            # XXX rate-limit
            vlog.err("cannot modify missing row %s in table %s"
                     % (uuid, table.name))
            return OVSDB_IDL_UPDATE_INCONSISTENT, None

        del table.rows[uuid]
        if ru.type == ovs.db.cs.ROW_UPDATE_XOR:
            old_row, changed = self._apply_diff(table, row, ru.columns)
        else:
            changed = self.__row_update(table, row, ru.columns)
        table.rows[uuid] = row
        if changed:
            if ru.type == ovs.db.cs.ROW_UPDATE_XOR:
                old = Row(self, table, uuid, old_row)
            else:
                old = Row.from_json(self, table, uuid, ru.old)
            return OVSDB_IDL_UPDATE_DB_CHANGED, Notice(ROW_UPDATE, row, old)
        return OVSDB_IDL_UPDATE_NO_CHANGES, None

    def __column_name(self, column):
        if column.type.key.type == ovs.db.types.UuidType:
            return ovs.ovsuuid.to_json(column.type.key.type.default)
        else:
            return column.type.key.type.default

    def __add_default(self, table, row_update):
        for column in table.columns.values():
            if column.name not in row_update:
                if ((table.name not in self.readonly) or
                        (table.name in self.readonly) and
                        (column.name not in self.readonly[table.name])):
                    if column.type.n_min != 0 and not column.type.is_map():
                        row_update[column.name] = self.__column_name(column)

    def _apply_diff(self, table, row, row_diff):
        old_row = {}
        changed = False
        for column_name, datum_diff_json in row_diff.items():
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s updating table %s"
                          % (column_name, table.name))
                continue

            try:
                datum_diff = data.Datum.from_json(column.type, datum_diff_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue

            # Datum.diff() mutates the datum in place for sets and maps and
            # returns 'self', so compare the new value against the pre-diff
            # copy rather than against row._data[column_name] (which diff()
            # may already have updated).
            old = row._data[column_name].copy()
            old_row[column_name] = old
            datum = row._data[column_name].diff(datum_diff)
            row._data[column_name] = datum
            if datum != old and column.alert:
                changed = True

        return old_row, changed

    def __row_update(self, table, row, row_json):
        changed = False
        for column_name, datum_json in row_json.items():
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s updating table %s"
                          % (column_name, table.name))
                continue

            try:
                datum = data.Datum.from_json(column.type, datum_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue

            if datum != row._data[column_name]:
                row._data[column_name] = datum
                if column.alert:
                    changed = True
            else:
                # Didn't really change but the OVSDB monitor protocol always
                # includes every value in a row.
                pass
        return changed

    def __create_row(self, table, uuid):
        return Row(self, table, uuid, ColumnDefaultDict(table))

    def __txn_abort_all(self):
        while self._outstanding_txns:
            txn = self._outstanding_txns.popitem()[1]
            txn._status = Transaction.TRY_AGAIN

    def __txn_process_reply(self, msg):
        txn = self._outstanding_txns.pop(msg.id, None)
        if txn:
            txn._process_reply(msg)
            return True


def _row_to_uuid(value):
    if isinstance(value, Row):
        return value.uuid
    else:
        return value


def _rows_to_uuid_str(value):
    if isinstance(value, collections.abc.Mapping):
        try:
            k, v = next(iter(value.items()))
            # Pass through early without iterating if not Rows.
            if isinstance(k, Row) or isinstance(v, Row):
                return {str(_row_to_uuid(x)): str(_row_to_uuid(y))
                        for x, y in value.items()}
        except StopIteration:
            # Empty, return default.
            pass
    elif (isinstance(value, collections.abc.Iterable)
        and not isinstance(value, str)):
        try:
            # Pass through early without iterating if not Rows.
            if value and isinstance(value[0], Row):
                return type(value)(str(_row_to_uuid(x)) for x in value)
        except TypeError:
            # Weird Iterable, pass through.
            pass
    return str(_row_to_uuid(value))


@functools.total_ordering
class Row(object):
    """A row within an IDL.

    The client may access the following attributes directly:

    - 'uuid': a uuid.UUID object whose value is the row's database UUID.

    - An attribute for each column in the Row's table, named for the column,
      whose values are as returned by Datum.to_python() for the column's type.

      If some error occurs (e.g. the database server's idea of the column is
      different from the IDL's idea), then the attribute values is the
      "default" value return by Datum.default() for the column's type.  (It is
      important to know this because the default value may violate constraints
      for the column's type, e.g. the default integer value is 0 even if column
      contraints require the column's value to be positive.)

      When a transaction is active, column attributes may also be assigned new
      values.  Committing the transaction will then cause the new value to be
      stored into the database.

      *NOTE*: In the current implementation, the value of a column is a *copy*
      of the value in the database.  This means that modifying its value
      directly will have no useful effect.  For example, the following:
        row.mycolumn["a"] = "b"              # don't do this
      will not change anything in the database, even after commit.  To modify
      the column, instead assign the modified column value back to the column:
        d = row.mycolumn
        d["a"] = "b"
        row.mycolumn = d
"""
    def __init__(self, idl, table, uuid, data, persist_uuid=False):
        # All of the explicit references to self.__dict__ below are required
        # to set real attributes with invoking self.__getattr__().
        self.__dict__["uuid"] = uuid

        self.__dict__["_idl"] = idl
        self.__dict__["_table"] = table

        # _data is the committed data.  It takes the following values:
        #
        #   - A dictionary that maps every column name to a Datum, if the row
        #     exists in the committed form of the database.
        #
        #   - None, if this row is newly inserted within the active transaction
        #     and thus has no committed form.
        self.__dict__["_data"] = data

        # _changes describes changes to this row within the active transaction.
        # It takes the following values:
        #
        #   - {}, the empty dictionary, if no transaction is active or if the
        #     row has yet not been changed within this transaction.
        #
        #   - A dictionary that maps a column name to its new Datum, if an
        #     active transaction changes those columns' values.
        #
        #   - A dictionary that maps every column name to a Datum, if the row
        #     is newly inserted within the active transaction.
        #
        #   - None, if this transaction deletes this row.
        self.__dict__["_changes"] = {}

        # _mutations describes changes to this row to be handled via a
        # mutate operation on the wire.  It takes the following values:
        #
        #   - {}, the empty dictionary, if no transaction is active or if the
        #     row has yet not been mutated within this transaction.
        #
        #   - A dictionary that contains two keys:
        #
        #     - "_inserts" contains a dictionary that maps column names to
        #       new keys/key-value pairs that should be inserted into the
        #       column
        #     - "_removes" contains a dictionary that maps column names to
        #       the keys/key-value pairs that should be removed from the
        #       column
        #
        #   - None, if this transaction deletes this row.
        self.__dict__["_mutations"] = {}

        # A dictionary whose keys are the names of columns that must be
        # verified as prerequisites when the transaction commits.  The values
        # in the dictionary are all None.
        self.__dict__["_prereqs"] = {}

        # Indicates if the specified 'uuid' should be used as the row uuid
        # or let the server generate it.
        self.__dict__["_persist_uuid"] = persist_uuid

    def __lt__(self, other):
        if not isinstance(other, Row):
            return NotImplemented
        return bool(self.__dict__['uuid'] < other.__dict__['uuid'])

    def __eq__(self, other):
        if not isinstance(other, Row):
            return NotImplemented
        return bool(self.__dict__['uuid'] == other.__dict__['uuid'])

    def __hash__(self):
        return int(self.__dict__['uuid'])

    def __str__(self):
        return "{table}(uuid={uuid}, {data})".format(
            table=self._table.name,
            uuid=self.uuid,
            data=", ".join("{col}={val}".format(
                col=c, val=_rows_to_uuid_str(getattr(self, c)))
                for c in sorted(self._table.columns) if hasattr(self, c)))

    def _uuid_to_row(self, atom, base):
        if base.ref_table:
            try:
                table = self._idl.tables[base.ref_table.name]
            except KeyError as e:
                msg = "Table {} is not registered".format(base.ref_table.name)
                raise AttributeError(msg) from e
            return table.rows.get(atom)
        else:
            return atom

    def __getattr__(self, column_name):
        assert self._changes is not None
        assert self._mutations is not None

        try:
            column = self._table.columns[column_name]
        except KeyError:
            raise AttributeError("%s instance has no attribute '%s'" %
                                 (self.__class__.__name__, column_name))
        datum = self._changes.get(column_name)
        inserts = None
        if '_inserts' in self._mutations.keys():
            inserts = self._mutations['_inserts'].get(column_name)
        removes = None
        if '_removes' in self._mutations.keys():
            removes = self._mutations['_removes'].get(column_name)
        if datum is None:
            if self._data is None:
                if inserts is None:
                    raise AttributeError("%s instance has no attribute '%s'" %
                                         (self.__class__.__name__,
                                          column_name))
                else:
                    datum = data.Datum.from_python(column.type,
                                                   inserts,
                                                   _row_to_uuid)
            elif column_name in self._data:
                datum = self._data[column_name]
                if column.type.is_set():
                    dlist = datum.as_list()
                    if inserts is not None:
                        dlist.extend(list(inserts))
                    if removes is not None:
                        removes_datum = data.Datum.from_python(column.type,
                                                              removes,
                                                              _row_to_uuid)
                        removes_list = removes_datum.as_list()
                        dlist = [x for x in dlist if x not in removes_list]
                    datum = data.Datum.from_python(column.type, dlist,
                                                   _row_to_uuid)
                elif column.type.is_map():
                    dmap = datum.to_python(self._uuid_to_row)
                    if inserts is not None:
                        dmap.update(inserts)
                    if removes is not None:
                        for key in removes:
                            if key not in (inserts or {}):
                                dmap.pop(key, None)
                    datum = data.Datum.from_python(column.type, dmap,
                                                   _row_to_uuid)
            else:
                if inserts is None:
                    raise AttributeError("%s instance has no attribute '%s'" %
                                         (self.__class__.__name__,
                                          column_name))
                else:
                    datum = inserts

        return datum.to_python(self._uuid_to_row)

    def __setattr__(self, column_name, value):
        assert self._changes is not None
        assert self._idl.txn

        if ((self._table.name in self._idl.readonly) and
                (column_name in self._idl.readonly[self._table.name])):
            vlog.warn("attempting to write to readonly column %s"
                      % column_name)
            return

        column = self._table.columns[column_name]
        try:
            datum = data.Datum.from_python(column.type, value, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        # Remove prior version of the Row from the index if it has the indexed
        # column set, and the column changing is an indexed column
        if hasattr(self, column_name):
            for idx in self._table.rows.indexes.values():
                if column_name in (c.column for c in idx.columns):
                    idx.remove(self)
        self._idl.txn._write(self, column, datum)
        for idx in self._table.rows.indexes.values():
            # Only update the index if indexed columns change
            if column_name in (c.column for c in idx.columns):
                idx.add(self)

    def addvalue(self, column_name, key):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, key, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        inserts = self._mutations.setdefault('_inserts', {})
        column_value = inserts.setdefault(column_name, set())
        column_value.add(key)

    def delvalue(self, column_name, key):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, key, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to delete bad value from column %s (%s)"
                     % (column_name, e))
            return
        removes = self._mutations.setdefault('_removes', {})
        column_value = removes.setdefault(column_name, set())
        column_value.add(key)

    def setkey(self, column_name, key, value):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, {key: value}, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        if self._data and column_name in self._data:
            # Remove existing key/value before updating.
            removes = self._mutations.setdefault('_removes', {})
            column_value = removes.setdefault(column_name, set())
            column_value.add(key)
        inserts = self._mutations.setdefault('_inserts', {})
        column_value = inserts.setdefault(column_name, {})
        column_value[key] = value

    def delkey(self, column_name, key, value=None):
        self._idl.txn._txn_rows[self.uuid] = self
        if value:
            try:
                old_value = data.Datum.to_python(self._data[column_name],
                                                 self._uuid_to_row)
            except error.Error:
                return
            if key not in old_value:
                return
            if old_value[key] != value:
                return
        removes = self._mutations.setdefault('_removes', {})
        column_value = removes.setdefault(column_name, set())
        column_value.add(key)
        return

    @classmethod
    def from_json(cls, idl, table, uuid, row_json):
        data = {}
        for column_name, datum_json in row_json.items():
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s in table %s"
                          % (column_name, table.name))
                continue
            try:
                datum = ovs.db.data.Datum.from_json(column.type, datum_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue
            data[column_name] = datum
        return cls(idl, table, uuid, data)

    def verify(self, column_name):
        """Causes the original contents of column 'column_name' in this row to
        be verified as a prerequisite to completing the transaction.  That is,
        if 'column_name' changed in this row (or if this row was deleted)
        between the time that the IDL originally read its contents and the time
        that the transaction commits, then the transaction aborts and
        Transaction.commit() returns Transaction.TRY_AGAIN.

        The intention is that, to ensure that no transaction commits based on
        dirty reads, an application should call Row.verify() on each data item
        read as part of a read-modify-write operation.

        In some cases Row.verify() reduces to a no-op, because the current
        value of the column is already known:

          - If this row is a row created by the current transaction (returned
            by Transaction.insert()).

          - If the column has already been modified within the current
            transaction.

        Because of the latter property, always call Row.verify() *before*
        modifying the column, for a given read-modify-write.

        A transaction must be in progress."""
        assert self._idl.txn
        assert self._changes is not None
        if self._data is None or column_name in self._changes:
            return

        self._prereqs[column_name] = None

    def delete(self):
        """Deletes this row from its table.

        A transaction must be in progress."""
        assert self._idl.txn
        assert self._changes is not None
        if self._data is None:
            del self._idl.txn._txn_rows[self.uuid]
        else:
            self._idl.txn._txn_rows[self.uuid] = self
        del self._table.rows[self.uuid]
        self.__dict__["_changes"] = None

    def fetch(self, column_name):
        self._idl.txn._fetch(self, column_name)

    def increment(self, column_name):
        """Causes the transaction, when committed, to increment the value of
        'column_name' within this row by 1.  'column_name' must have an integer
        type.  After the transaction commits successfully, the client may
        retrieve the final (incremented) value of 'column_name' with
        Transaction.get_increment_new_value().

        The client could accomplish something similar by reading and writing
        and verify()ing columns.  However, increment() will never (by itself)
        cause a transaction to fail because of a verify error.

        The intended use is for incrementing the "next_cfg" column in
        the Open_vSwitch table."""
        self._idl.txn._increment(self, column_name)


def _uuid_name_from_uuid(uuid):
    return "row%s" % str(uuid).replace("-", "_")


def _where_uuid_equals(uuid):
    return [["_uuid", "==", ["uuid", str(uuid)]]]


class _InsertedRow(object):
    def __init__(self, op_index):
        self.op_index = op_index
        self.real = None


class Transaction(object):
    """A transaction may modify the contents of a database by modifying the
    values of columns, deleting rows, inserting rows, or adding checks that
    columns in the database have not changed ("verify" operations), through
    Row methods.

    Reading and writing columns and inserting and deleting rows are all
    straightforward.  The reasons to verify columns are less obvious.
    Verification is the key to maintaining transactional integrity.  Because
    OVSDB handles multiple clients, it can happen that between the time that
    OVSDB client A reads a column and writes a new value, OVSDB client B has
    written that column.  Client A's write should not ordinarily overwrite
    client B's, especially if the column in question is a "map" column that
    contains several more or less independent data items.  If client A adds a
    "verify" operation before it writes the column, then the transaction fails
    in case client B modifies it first.  Client A will then see the new value
    of the column and compose a new transaction based on the new contents
    written by client B.

    When a transaction is complete, which must be before the next call to
    Idl.run(), call Transaction.commit() or Transaction.abort().

    The life-cycle of a transaction looks like this:

    1. Create the transaction and record the initial sequence number:

        seqno = idl.change_seqno(idl)
        txn = Transaction(idl)

    2. Modify the database with Row and Transaction methods.

    3. Commit the transaction by calling Transaction.commit().  The first call
       to this function probably returns Transaction.INCOMPLETE.  The client
       must keep calling again along as this remains true, calling Idl.run() in
       between to let the IDL do protocol processing.  (If the client doesn't
       have anything else to do in the meantime, it can use
       Transaction.commit_block() to avoid having to loop itself.)

    4. If the final status is Transaction.TRY_AGAIN, wait for Idl.change_seqno
       to change from the saved 'seqno' (it's possible that it's already
       changed, in which case the client should not wait at all), then start
       over from step 1.  Only a call to Idl.run() will change the return value
       of Idl.change_seqno.  (Transaction.commit_block() calls Idl.run().)"""

    # Status values that Transaction.commit() can return.

    # Not yet committed or aborted.
    UNCOMMITTED = "uncommitted"
    # Transaction didn't include any changes.
    UNCHANGED = "unchanged"
    # Commit in progress, please wait.
    INCOMPLETE = "incomplete"
    # ovsdb_idl_txn_abort() called.
    ABORTED = "aborted"
    # Commit successful.
    SUCCESS = "success"
    # Commit failed because a "verify" operation
    # reported an inconsistency, due to a network
    # problem, or other transient failure.  Wait
    # for a change, then try again.
    TRY_AGAIN = "try again"
    # Server hasn't given us the lock yet.
    NOT_LOCKED = "not locked"
    # Commit failed due to a hard error.
    ERROR = "error"

    @staticmethod
    def status_to_string(status):
        """Converts one of the status values that Transaction.commit() can
        return into a human-readable string.

        (The status values are in fact such strings already, so
        there's nothing to do.)"""
        return status

    def __init__(self, idl):
        """Starts a new transaction on 'idl' (an instance of ovs.db.idl.Idl).
        A given Idl may only have a single active transaction at a time.

        A Transaction may modify the contents of a database by assigning new
        values to columns (attributes of Row), deleting rows (with
        Row.delete()), or inserting rows (with Transaction.insert()).  It may
        also check that columns in the database have not changed with
        Row.verify().

        When a transaction is complete (which must be before the next call to
        Idl.run()), call Transaction.commit() or Transaction.abort()."""
        assert idl.txn is None

        idl.txn = self
        self._request_id = None
        self.idl = idl
        self.dry_run = False
        self._txn_rows = {}
        self._status = Transaction.UNCOMMITTED
        self._error = None
        self._comments = []

        self._inc_row = None
        self._inc_column = None

        self._fetch_requests = []

        self._inserted_rows = {}  # Map from UUID to _InsertedRow

        self._operations = []

    def add_comment(self, comment):
        """Appends 'comment' to the comments that will be passed to the OVSDB
        server when this transaction is committed.  (The comment will be
        committed to the OVSDB log, which "ovsdb-tool show-log" can print in a
        relatively human-readable form.)"""
        self._comments.append(comment)

    def wait(self, poller):
        """Causes poll_block() to wake up if this transaction has completed
        committing."""
        if self._status not in (Transaction.UNCOMMITTED,
                                Transaction.INCOMPLETE):
            poller.immediate_wake()

    def _substitute_uuids(self, json):
        if isinstance(json, (list, tuple)):
            if (len(json) == 2
                    and json[0] == 'uuid'
                    and ovs.ovsuuid.is_valid_string(json[1])):
                uuid = ovs.ovsuuid.from_string(json[1])
                row = self._txn_rows.get(uuid, None)
                if row and row._data is None and not row._persist_uuid:
                    return ["named-uuid", _uuid_name_from_uuid(uuid)]
            else:
                return [self._substitute_uuids(elem) for elem in json]
        return json

    def __disassemble(self):
        self.idl.txn = None

        for row in self._txn_rows.values():
            if row._changes is None:
                # If we add the deleted row back to rows with _changes == None
                # then __getattr__ will not work for the indexes
                row.__dict__["_changes"] = {}
                row.__dict__["_mutations"] = {}
                row._table.rows[row.uuid] = row
            elif row._data is None:
                del row._table.rows[row.uuid]
            row.__dict__["_changes"] = {}
            row.__dict__["_mutations"] = {}
            row.__dict__["_prereqs"] = {}
        self._txn_rows = {}

    def commit(self):
        """Attempts to commit 'txn'.  Returns the status of the commit
        operation, one of the following constants:

          Transaction.INCOMPLETE:

              The transaction is in progress, but not yet complete.  The caller
              should call again later, after calling Idl.run() to let the
              IDL do OVSDB protocol processing.

          Transaction.UNCHANGED:

              The transaction is complete.  (It didn't actually change the
              database, so the IDL didn't send any request to the database
              server.)

          Transaction.ABORTED:

              The caller previously called Transaction.abort().

          Transaction.SUCCESS:

              The transaction was successful.  The update made by the
              transaction (and possibly other changes made by other database
              clients) should already be visible in the IDL.

          Transaction.TRY_AGAIN:

              The transaction failed for some transient reason, e.g. because a
              "verify" operation reported an inconsistency or due to a network
              problem.  The caller should wait for a change to the database,
              then compose a new transaction, and commit the new transaction.

              Use Idl.change_seqno to wait for a change in the database.  It is
              important to use its value *before* the initial call to
              Transaction.commit() as the baseline for this purpose, because
              the change that one should wait for can happen after the initial
              call but before the call that returns Transaction.TRY_AGAIN, and
              using some other baseline value in that situation could cause an
              indefinite wait if the database rarely changes.

          Transaction.NOT_LOCKED:

              The transaction failed because the IDL has been configured to
              require a database lock (with Idl.set_lock()) but didn't
              get it yet or has already lost it.

        Committing a transaction rolls back all of the changes that it made to
        the IDL's copy of the database.  If the transaction commits
        successfully, then the database server will send an update and, thus,
        the IDL will be updated with the committed changes."""
        # The status can only change if we're the active transaction.
        # (Otherwise, our status will change only in Idl.run().)
        if self != self.idl.txn:
            return self._status

        # The CS layer gates transaction submission on the session being in
        # the MONITORING state and, if a lock is configured, on holding it.
        if not self.idl.cs.may_send_transaction():
            if self.idl.cs.get_lock() and not self.idl.cs.has_lock():
                self._status = Transaction.NOT_LOCKED
            else:
                self._status = Transaction.TRY_AGAIN
            self.__disassemble()
            return self._status

        operations = [self.idl._db.name]

        # Assert that we have the required lock (avoiding a race).
        if self.idl.lock_name:
            operations.append({"op": "assert",
                               "lock": self.idl.lock_name})

        # Add prerequisites and declarations of new rows.
        for row in self._txn_rows.values():
            if row._prereqs:
                rows = {}
                columns = []
                for column_name in row._prereqs:
                    columns.append(column_name)
                    rows[column_name] = row._data[column_name].to_json()
                operations.append({"op": "wait",
                                   "table": row._table.name,
                                   "timeout": 0,
                                   "where": _where_uuid_equals(row.uuid),
                                   "until": "==",
                                   "columns": columns,
                                   "rows": [rows]})

        # Add updates.
        any_updates = bool(self._operations)
        for row in self._txn_rows.values():
            if row._changes is None:
                if row._table.is_root:
                    operations.append({"op": "delete",
                                       "table": row._table.name,
                                       "where": _where_uuid_equals(row.uuid)})
                    any_updates = True
                else:
                    # Let ovsdb-server decide whether to really delete it.
                    pass
            else:
                op = {"table": row._table.name}
                if row._data is None:
                    op["op"] = "insert"
                    if row._persist_uuid:
                        op["uuid"] = str(row.uuid)
                    else:
                        op["uuid-name"] = _uuid_name_from_uuid(row.uuid)

                    any_updates = True

                    op_index = len(operations) - 1
                    self._inserted_rows[row.uuid] = _InsertedRow(op_index)
                else:
                    op["op"] = "update"
                    op["where"] = _where_uuid_equals(row.uuid)

                row_json = {}
                op["row"] = row_json

                for column_name, datum in row._changes.items():
                    if row._data is not None or not datum.is_default():
                        row_json[column_name] = (
                            self._substitute_uuids(datum.to_json()))

                        # If anything really changed, consider it an update.
                        # We can't suppress not-really-changed values earlier
                        # or transactions would become nonatomic (see the big
                        # comment inside Transaction._write()).
                        if (not any_updates and row._data is not None and
                                row._data[column_name] != datum):
                            any_updates = True

                if row._data is None or row_json:
                    operations.append(op)
            if row._mutations:
                addop = False
                op = {"table": row._table.name}
                op["op"] = "mutate"
                if row._data is None:
                    # New row
                    op["where"] = self._substitute_uuids(
                        _where_uuid_equals(row.uuid))
                else:
                    # Existing row
                    op["where"] = _where_uuid_equals(row.uuid)
                op["mutations"] = []
                if '_removes' in row._mutations.keys():
                    for col, dat in row._mutations['_removes'].items():
                        column = row._table.columns[col]
                        if column.type.is_map():
                            opdat = ["set"]
                            opdat.append(list(dat))
                        else:
                            opdat = ["set"]
                            inner_opdat = []
                            for ele in dat:
                                try:
                                    datum = data.Datum.from_python(column.type,
                                        ele, _row_to_uuid)
                                except error.Error:
                                    return
                                inner_opdat.append(
                                    self._substitute_uuids(datum.to_json()))
                            opdat.append(inner_opdat)
                        mutation = [col, "delete", opdat]
                        op["mutations"].append(mutation)
                        addop = True
                if '_inserts' in row._mutations.keys():
                    for col, val in row._mutations['_inserts'].items():
                        column = row._table.columns[col]
                        if column.type.is_map():
                            datum = data.Datum.from_python(column.type, val,
                                                           _row_to_uuid)
                            opdat = self._substitute_uuids(datum.to_json())
                        else:
                            opdat = ["set"]
                            inner_opdat = []
                            for ele in val:
                                try:
                                    datum = data.Datum.from_python(column.type,
                                        ele, _row_to_uuid)
                                except error.Error:
                                    return
                                inner_opdat.append(
                                    self._substitute_uuids(datum.to_json()))
                            opdat.append(inner_opdat)
                        mutation = [col, "insert", opdat]
                        op["mutations"].append(mutation)
                        addop = True
                if addop:
                    operations.append(op)
                    any_updates = True

        if self._fetch_requests:
            for fetch in self._fetch_requests:
                fetch["index"] = len(operations) - 1
                operations.append({"op": "select",
                                   "table": fetch["row"]._table.name,
                                   "where": self._substitute_uuids(
                                       _where_uuid_equals(fetch["row"].uuid)),
                                   "columns": [fetch["column_name"]]})
            any_updates = True

        # Add increment.
        if self._inc_row and any_updates:
            self._inc_index = len(operations) - 1

            operations.append({"op": "mutate",
                               "table": self._inc_row._table.name,
                               "where": self._substitute_uuids(
                                   _where_uuid_equals(self._inc_row.uuid)),
                               "mutations": [[self._inc_column, "+=", 1]]})
            operations.append({"op": "select",
                               "table": self._inc_row._table.name,
                               "where": self._substitute_uuids(
                                   _where_uuid_equals(self._inc_row.uuid)),
                               "columns": [self._inc_column]})

        # Add comment.
        if self._comments:
            operations.append({"op": "comment",
                               "comment": "\n".join(self._comments)})

        operations += self._operations

        # Dry run?
        if self.dry_run:
            operations.append({"op": "abort"})

        if not any_updates:
            self._status = Transaction.UNCHANGED
        else:
            msg = ovs.jsonrpc.Message.create_request("transact", operations)
            self._request_id = msg.id
            if not self.idl.cs.send(msg):
                self.idl._outstanding_txns[self._request_id] = self
                self._status = Transaction.INCOMPLETE
            else:
                self._status = Transaction.TRY_AGAIN

        self.__disassemble()
        return self._status

    def add_op(self, op):
        """Add a raw OVSDB operation to the transaction

        This can be useful for re-using the existing Idl connection to take
        actions that are difficult or expensive to do with the Idl itself, e.g.
        bulk deleting rows from the server without downloading them into a
        local cache.

        All ops are applied after any other operations in the transaction.

        :param op: An "op" for an OVSDB "transact" request (rfc 7047 Sec 5.2)
        :type op:  dict
        """
        self._operations.append(op)

    def commit_block(self):
        """Attempts to commit this transaction, blocking until the commit
        either succeeds or fails.  Returns the final commit status, which may
        be any Transaction.* value other than Transaction.INCOMPLETE.

        This function calls Idl.run() on this transaction'ss IDL, so it may
        cause Idl.change_seqno to change."""
        while True:
            status = self.commit()
            if status != Transaction.INCOMPLETE:
                return status

            self.idl.run()

            poller = ovs.poller.Poller()
            self.idl.wait(poller)
            self.wait(poller)
            poller.block()

    def get_increment_new_value(self):
        """Returns the final (incremented) value of the column in this
        transaction that was set to be incremented by Row.increment.  This
        transaction must have committed successfully."""
        assert self._status == Transaction.SUCCESS
        return self._inc_new_value

    def abort(self):
        """Aborts this transaction.  If Transaction.commit() has already been
        called then the transaction might get committed anyhow."""
        self.__disassemble()
        if self._status in (Transaction.UNCOMMITTED,
                            Transaction.INCOMPLETE):
            self._status = Transaction.ABORTED

    def get_error(self):
        """Returns a string representing this transaction's current status,
        suitable for use in log messages."""
        if self._status != Transaction.ERROR:
            return Transaction.status_to_string(self._status)
        elif self._error:
            return self._error
        else:
            return "no error details available"

    def __set_error_json(self, json):
        if self._error is None:
            self._error = ovs.json.to_string(json)

    def get_insert_uuid(self, uuid):
        """Finds and returns the permanent UUID that the database assigned to a
        newly inserted row, given the UUID that Transaction.insert() assigned
        locally to that row.

        Returns None if 'uuid' is not a UUID assigned by Transaction.insert()
        or if it was assigned by that function and then deleted by Row.delete()
        within the same transaction.  (Rows that are inserted and then deleted
        within a single transaction are never sent to the database server, so
        it never assigns them a permanent UUID.)

        This transaction must have completed successfully."""
        assert self._status in (Transaction.SUCCESS,
                                Transaction.UNCHANGED)
        inserted_row = self._inserted_rows.get(uuid)
        if inserted_row:
            return inserted_row.real
        return None

    def _increment(self, row, column):
        assert not self._inc_row
        self._inc_row = row
        self._inc_column = column

    def _fetch(self, row, column_name):
        self._fetch_requests.append({"row": row, "column_name": column_name})

    def _write(self, row, column, datum):
        assert row._changes is not None
        assert row._mutations is not None

        txn = row._idl.txn

        # If this is a write-only column and the datum being written is the
        # same as the one already there, just skip the update entirely.  This
        # is worth optimizing because we have a lot of columns that get
        # periodically refreshed into the database but don't actually change
        # that often.
        #
        # We don't do this for read/write columns because that would break
        # atomicity of transactions--some other client might have written a
        # different value in that column since we read it.  (But if a whole
        # transaction only does writes of existing values, without making any
        # real changes, we will drop the whole transaction later in
        # ovsdb_idl_txn_commit().)
        if (not column.alert and row._data is not None and
                row._data.get(column.name) == datum):
            new_value = row._changes.get(column.name)
            if new_value is None or new_value == datum:
                return

        txn._txn_rows[row.uuid] = row
        if '_inserts' in row._mutations:
            row._mutations['_inserts'].pop(column.name, None)
        if '_removes' in row._mutations:
            row._mutations['_removes'].pop(column.name, None)
        row._changes[column.name] = datum.copy()

    def insert(self, table, new_uuid=None, persist_uuid=False):
        """Inserts and returns a new row in 'table', which must be one of the
        ovs.db.schema.TableSchema objects in the Idl's 'tables' dict.

        The new row is assigned a provisional UUID.  If 'uuid' is None then one
        is randomly generated; otherwise 'uuid' should specify a randomly
        generated uuid.UUID not otherwise in use.  If 'persist_uuid' is true
        and 'new_uuid' is specified, IDL requests the ovsdb-server to assign
        the same UUID, otherwise ovsdb-server will assign a different UUID when
        'txn' is committed and the IDL will replace any uses of the provisional
        UUID in the data to be committed by the UUID assigned by
        ovsdb-server."""
        assert self._status == Transaction.UNCOMMITTED
        if new_uuid is None:
            new_uuid = uuid.uuid4()
        row = Row(self.idl, table, new_uuid, None, persist_uuid=persist_uuid)
        table.rows[row.uuid] = row
        self._txn_rows[row.uuid] = row
        return row

    def _process_reply(self, msg):
        if msg.type == ovs.jsonrpc.Message.T_ERROR:
            self._status = Transaction.ERROR
        elif not isinstance(msg.result, (list, tuple)):
            # XXX rate-limit
            vlog.warn('reply to "transact" is not JSON array')
        else:
            hard_errors = False
            soft_errors = False
            lock_errors = False

            ops = msg.result
            for op in ops:
                if op is None:
                    # This isn't an error in itself but indicates that some
                    # prior operation failed, so make sure that we know about
                    # it.
                    soft_errors = True
                elif isinstance(op, dict):
                    error = op.get("error")
                    if error is not None:
                        if error == "timed out":
                            soft_errors = True
                        elif error == "not owner":
                            lock_errors = True
                        elif error == "aborted":
                            pass
                        else:
                            hard_errors = True
                            self.__set_error_json(op)
                else:
                    hard_errors = True
                    self.__set_error_json(op)
                    # XXX rate-limit
                    vlog.warn("operation reply is not JSON null or object")

            if not soft_errors and not hard_errors and not lock_errors:
                if self._inc_row and not self.__process_inc_reply(ops):
                    hard_errors = True
                if self._fetch_requests:
                    if self.__process_fetch_reply(ops):
                        self.idl.change_seqno += 1
                    else:
                        hard_errors = True

                for insert in self._inserted_rows.values():
                    if not self.__process_insert_reply(insert, ops):
                        hard_errors = True

            if hard_errors:
                self._status = Transaction.ERROR
            elif lock_errors:
                self._status = Transaction.NOT_LOCKED
            elif soft_errors:
                self._status = Transaction.TRY_AGAIN
            else:
                self._status = Transaction.SUCCESS

    @staticmethod
    def __check_json_type(json, types, name):
        if not json:
            # XXX rate-limit
            vlog.warn("%s is missing" % name)
            return False
        elif not isinstance(json, tuple(types)):
            # XXX rate-limit
            vlog.warn("%s has unexpected type %s" % (name, type(json)))
            return False
        else:
            return True

    def __process_fetch_reply(self, ops):
        update = False
        for fetch_request in self._fetch_requests:
            row = fetch_request["row"]
            column_name = fetch_request["column_name"]
            index = fetch_request["index"]
            table = row._table

            select = ops[index]
            fetched_rows = select.get("rows")
            if not Transaction.__check_json_type(fetched_rows, (list, tuple),
                                                 '"select" reply "rows"'):
                return False
            if len(fetched_rows) != 1:
                # XXX rate-limit
                vlog.warn('"select" reply "rows" has %d elements '
                          'instead of 1' % len(fetched_rows))
                continue
            fetched_row = fetched_rows[0]
            if not Transaction.__check_json_type(fetched_row, (dict,),
                                                 '"select" reply row'):
                continue

            column = table.columns.get(column_name)
            datum_json = fetched_row.get(column_name)
            datum = data.Datum.from_json(column.type, datum_json)

            row._data[column_name] = datum
            update = True

        return update

    def __process_inc_reply(self, ops):
        if self._inc_index + 2 > len(ops):
            # XXX rate-limit
            vlog.warn("reply does not contain enough operations for "
                      "increment (has %d, needs %d)" %
                      (len(ops), self._inc_index + 2))

        # We know that this is a JSON object because the loop in
        # __process_reply() already checked.
        mutate = ops[self._inc_index]
        count = mutate.get("count")
        if not Transaction.__check_json_type(count, (int,),
                                             '"mutate" reply "count"'):
            return False
        if count != 1:
            # XXX rate-limit
            vlog.warn('"mutate" reply "count" is %d instead of 1' % count)
            return False

        select = ops[self._inc_index + 1]
        rows = select.get("rows")
        if not Transaction.__check_json_type(rows, (list, tuple),
                                             '"select" reply "rows"'):
            return False
        if len(rows) != 1:
            # XXX rate-limit
            vlog.warn('"select" reply "rows" has %d elements '
                      'instead of 1' % len(rows))
            return False
        row = rows[0]
        if not Transaction.__check_json_type(row, (dict,),
                                             '"select" reply row'):
            return False
        column = row.get(self._inc_column)
        if not Transaction.__check_json_type(column, (int,),
                                             '"select" reply inc column'):
            return False
        self._inc_new_value = column
        return True

    def __process_insert_reply(self, insert, ops):
        if insert.op_index >= len(ops):
            # XXX rate-limit
            vlog.warn("reply does not contain enough operations "
                      "for insert (has %d, needs %d)"
                      % (len(ops), insert.op_index))
            return False

        # We know that this is a JSON object because the loop in
        # __process_reply() already checked.
        reply = ops[insert.op_index]
        json_uuid = reply.get("uuid")
        if not Transaction.__check_json_type(json_uuid, (tuple, list),
                                             '"insert" reply "uuid"'):
            return False

        try:
            uuid_ = ovs.ovsuuid.from_json(json_uuid)
        except error.Error:
            # XXX rate-limit
            vlog.warn('"insert" reply "uuid" is not a JSON UUID')
            return False

        insert.real = uuid_
        return True


class SchemaHelper(object):
    """IDL Schema helper.

    This class encapsulates the logic required to generate schemas suitable
    for creating 'ovs.db.idl.Idl' objects.  Clients should register columns
    they are interested in using register_columns().  When finished, the
    get_idl_schema() function may be called.

    The location on disk of the schema used may be found in the
    'schema_location' variable."""

    def __init__(self, location=None, schema_json=None):
        """Creates a new Schema object.

        'location' file path to ovs schema. None means default location
        'schema_json' schema in json preresentation in memory
        """

        if location and schema_json:
            raise ValueError("both location and schema_json can't be "
                             "specified. it's ambiguous.")
        if schema_json is None:
            if location is None:
                location = "%s/vswitch.ovsschema" % ovs.dirs.PKGDATADIR
            schema_json = ovs.json.from_file(location)

        self.schema_json = schema_json
        self._tables = {}
        self._readonly = {}
        self._all = False

    def register_columns(self, table, columns, readonly=[]):
        """Registers interest in the given 'columns' of 'table'.  Future calls
        to get_idl_schema() will include 'table':column for each column in
        'columns'. This function automatically avoids adding duplicate entries
        to the schema.
        A subset of 'columns' can be specified as 'readonly'. The readonly
        columns are not replicated but can be fetched on-demand by the user
        with Row.fetch().

        'table' must be a string.
        'columns' must be a list of strings.
        'readonly' must be a list of strings.
        """

        assert isinstance(table, str)
        assert isinstance(columns, list)

        columns = set(columns) | self._tables.get(table, set())
        self._tables[table] = columns
        self._readonly[table] = readonly

    def register_table(self, table):
        """Registers interest in the given all columns of 'table'. Future calls
        to get_idl_schema() will include all columns of 'table'.

        'table' must be a string
        """
        assert isinstance(table, str)
        self._tables[table] = set()  # empty set means all columns in the table

    def register_all(self):
        """Registers interest in every column of every table."""
        self._all = True

    def get_idl_schema(self):
        """Gets a schema appropriate for the creation of an 'ovs.db.id.IDL'
        object based on columns registered using the register_columns()
        function."""

        schema = ovs.db.schema.DbSchema.from_json(self.schema_json)
        self.schema_json = None

        if not self._all:
            schema_tables = {}
            for table, columns in self._tables.items():
                schema_tables[table] = (
                    self._keep_table_columns(schema, table, columns))

            schema.tables = schema_tables
        schema.readonly = self._readonly
        return schema

    def _keep_table_columns(self, schema, table_name, columns):
        assert table_name in schema.tables
        table = schema.tables[table_name]

        if not columns:
            # empty set means all columns in the table
            return table

        new_columns = {}
        for column_name in columns:
            assert isinstance(column_name, str)
            assert column_name in table.columns

            new_columns[column_name] = table.columns[column_name]

        table.columns = new_columns
        return table
