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

"""Open vSwitch Database client synchronization (CS) layer.

This module is the Python counterpart of the C ``lib/ovsdb-cs.c`` library.  It
owns everything below the typed in-memory replica: the JSON-RPC session, the
connection/monitor state machine, the ``_Server`` database mini-replica used
for clustering and relay decisions, database locking, monitor version
negotiation, ``monitor_cond_since`` / ``last_id`` resumption, and the
per-table condition engine.

The CS layer never deals in typed rows.  It hands work up to the IDL as a list
of typed events returned by :meth:`Cs.run`:

    - :class:`ReconnectEvent`  - the session reconnected.
    - :class:`LockedEvent`     - the configured lock was acquired.
    - :class:`UpdateEvent`     - ``<table-updates>`` to apply to the replica.
    - :class:`TxnReplyEvent`   - a reply to a transaction the IDL submitted.

The IDL provides column selection back to the CS layer through the ``ops``
object's ``compose_monitor_requests()`` down-call; the CS layer layers the
monitor conditions on top itself.

Like the C code, both the data database and the ``_Server`` database are
modelled as a :class:`_CsDb`.  A small set of ``_db_*`` helpers are
parameterized by the database they act on, so message processing collapses to a
thin dispatcher (:meth:`Cs._process_msg`) and a state switch
(:meth:`Cs._process_response`).  Server ``UPDATE`` events accumulate on
``self.server.events`` and are drained internally by
:meth:`Cs._check_server_db`; only ``self.data.events`` are returned to the
caller.
"""

import uuid

import ovs.db.data as data
import ovs.db.parser
import ovs.db.schema
import ovs.db.types
import ovs.jsonrpc
import ovs.ovsuuid
import ovs.vlog
from ovs.db import error

vlog = ovs.vlog.Vlog("cs")

OVSDB_UPDATE = "update"
OVSDB_UPDATE2 = "update2"
OVSDB_UPDATE3 = "update3"

CLUSTERED = "clustered"
RELAY = "relay"

# Maps the internal integer monitor version (1/2/3, as used by the C code) to
# the "update"/"update2"/"update3" string the IDL expects in an UpdateEvent.
_UPDATE_VERSION = {1: OVSDB_UPDATE, 2: OVSDB_UPDATE2, 3: OVSDB_UPDATE3}

# Row-update types, mirroring "enum ovsdb_cs_row_update_type" in ovsdb-cs.h.
ROW_UPDATE_DELETE = "delete"
ROW_UPDATE_INSERT = "insert"
ROW_UPDATE_UPDATE = "update"    # <row-update> "new": a full row, overwrite.
ROW_UPDATE_XOR = "xor"          # <row-update2> "modify": a diff, apply as XOR.


class RowUpdate(object):
    """A single parsed <row-update> or <row-update2>, mirroring
    "struct ovsdb_cs_row_update".

    'uuid'    - the row's UUID.
    'type'    - one of ROW_UPDATE_{DELETE,INSERT,UPDATE,XOR}.
    'columns' - the raw JSON <row> holding the operative columns: the "new"
                row for INSERT/UPDATE, the diff for XOR, the "old" row for a
                version 1 DELETE, or None for a version 2/3 DELETE.
    'old'     - the raw JSON "old" <row> for a version 1 UPDATE, else None.
                The C struct has no analog: the C IDL reconstructs the
                pre-change values from its own replica, whereas the Python IDL
                reports the "old" values carried on the wire, so we preserve
                them here."""

    def __init__(self, uuid, type_, columns, old=None):
        self.uuid = uuid
        self.type = type_
        self.columns = columns
        self.old = old


def parse_db_update(table_updates, version):
    """Parses a raw <table-updates> (version == OVSDB_UPDATE) or
    <table-updates2> (OVSDB_UPDATE2 / OVSDB_UPDATE3) JSON object into

        {table_name: [RowUpdate, ...], ...}

    normalizing the version 1 and version 2/3 wire encodings to a common
    RowUpdate.  Mirrors ovsdb_cs_parse_db_update().  Raises ovs.db.error.Error
    on malformed input.

    Like the C function this is schema-agnostic on purpose: the caller looks up
    its own tables and columns.  It is consumed both by the data replica
    (ovs.db.idl) and by the _Server mini-replica in this module."""
    if not isinstance(table_updates, dict):
        raise error.Error("<table-updates> is not an object", table_updates)

    db_update = {}
    for table_name, table_update in table_updates.items():
        db_update[table_name] = _parse_table_update(table_name, table_update,
                                                    version)
    return db_update


def _parse_table_update(table_name, table_update, version):
    suffix = "" if version == OVSDB_UPDATE else "2"
    if not isinstance(table_update, dict):
        raise error.Error('<table-update%s> for table "%s" is not an object'
                           % (suffix, table_name), table_update)

    row_updates = []
    for uuid_string, row_update in table_update.items():
        if not ovs.ovsuuid.is_valid_string(uuid_string):
            raise error.Error('<table-update%s> for table "%s" contains bad '
                               'UUID "%s" as member name'
                               % (suffix, table_name, uuid_string),
                               table_update)
        row_uuid = ovs.ovsuuid.from_string(uuid_string)
        row_updates.append(_parse_row_update(table_name, row_uuid, row_update,
                                             version))
    return row_updates


def _parse_row_update(table_name, row_uuid, row_update, version):
    suffix = "" if version == OVSDB_UPDATE else "2"
    if not isinstance(row_update, dict):
        raise error.Error('<table-update%s> for table "%s" contains a '
                           '<row-update%s> for %s that is not an object'
                           % (suffix, table_name, suffix, row_uuid),
                           row_update)

    if version == OVSDB_UPDATE:
        return _parse_row_update1(row_uuid, row_update)
    else:
        return _parse_row_update2(table_name, row_uuid, row_update)


def _parse_row_update1(row_uuid, row_update):
    parser = ovs.db.parser.Parser(row_update, "row-update")
    old = parser.get_optional("old", [dict])
    new = parser.get_optional("new", [dict])
    parser.finish()

    if not old and not new:
        raise error.Error('<row-update> missing "old" and "new" members',
                           row_update)

    if not new:
        return RowUpdate(row_uuid, ROW_UPDATE_DELETE, old)
    elif not old:
        return RowUpdate(row_uuid, ROW_UPDATE_INSERT, new)
    else:
        return RowUpdate(row_uuid, ROW_UPDATE_UPDATE, new, old)


def _parse_row_update2(table_name, row_uuid, row_update):
    if "delete" in row_update:
        return RowUpdate(row_uuid, ROW_UPDATE_DELETE, None)
    elif "insert" in row_update:
        return RowUpdate(row_uuid, ROW_UPDATE_INSERT, row_update["insert"])
    elif "initial" in row_update:
        return RowUpdate(row_uuid, ROW_UPDATE_INSERT, row_update["initial"])
    elif "modify" in row_update:
        return RowUpdate(row_uuid, ROW_UPDATE_XOR, row_update["modify"])
    else:
        raise error.Error('<row-update2> for table "%s" has no valid '
                           'operation' % table_name, row_update)


class Event(object):
    """Base class for events returned by Cs.run()."""


class ReconnectEvent(Event):
    """The JSON-RPC session reconnected.

    The IDL should abort all outstanding transactions."""


class LockedEvent(Event):
    """The database lock configured with Cs.set_lock() was acquired."""


class UpdateEvent(Event):
    """A ``<table-updates>`` (or ``<table-updates2>``) to apply.

    'clear'         - the replica should be emptied before applying.
    'monitor_reply' - this update came from a monitor reply (initial dump).
    'table_updates' - the raw JSON <table-updates[2]>.
    'version'       - "update", "update2" or "update3" (monitor / monitor_cond
                      / monitor_cond_since).
    'last_id'       - the last transaction id known for the database."""

    def __init__(self, clear, monitor_reply, table_updates, version, last_id):
        self.clear = clear
        self.monitor_reply = monitor_reply
        self.table_updates = table_updates
        self.version = version
        self.last_id = last_id


class TxnReplyEvent(Event):
    """A reply to a transaction the IDL submitted via Cs.send_transaction()."""

    def __init__(self, msg):
        self.msg = msg


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


class _CsDbTable(object):
    """Per-table condition state for a database monitored by the CS layer."""

    def __init__(self):
        self.condition_state = ConditionState()


class _CsDb(object):
    """The CS layer's per-database state (mirrors ``struct ovsdb_cs_db``).

    Both the data database and the ``_Server`` database are represented by a
    ``_CsDb``, so the ``_db_*`` helpers on :class:`Cs` can act on either one.

    'ops' is a callable taking the database's schema and returning the
    <monitor-requests> object (a dict mapping table name to a list containing a
    single dict with a "columns" key); the CS layer adds the "where" clauses.
    'max_version' is the highest monitor method version to attempt (3 =
    monitor_cond_since for the data db, 2 = monitor_cond for _Server)."""

    def __init__(self, db_name, table_names, ops, max_version):
        self.db_name = db_name
        self.tables = {name: _CsDbTable() for name in table_names}
        self.ops = ops
        self.max_version = max_version

        # Monitoring.
        self.monitor_id = uuid.uuid1()
        self.monitor_version = 0
        self.last_id = str(uuid.UUID(int=0))
        # The server's schema for this database (a parsed JSON dict for the
        # data db, an ovs.db.schema.DbSchema for _Server), or None if not yet
        # known.  Used to compose the monitor request.
        self.schema = None

        # Events produced for this database, drained by the caller (data db)
        # or internally by _check_server_db() (_Server db).
        self.events = []

        # Conditions.
        self.cond_changed = False
        self.cond_seqno = 0

        # Locking.
        self.lock_name = None           # Name of lock we need, None if none.
        self.has_lock = False           # Has db server said we have the lock?
        self.is_lock_contended = False  # Has db server said we can't get lock?
        self.lock_request_id = None     # JSON-RPC ID of in-flight lock req.


class Cs(object):
    """Open vSwitch Database client synchronization.

    Maintains the JSON-RPC session with an OVSDB server and drives the monitor
    state machine, handing updates and other events up to a client (typically
    ovs.db.idl.Idl) through the list returned by run().

    'ops' must provide a compose_monitor_requests() method that returns the
    monitor <monitor-requests> object (a dict mapping table name to a list
    containing a single dict with a "columns" key).  The CS layer adds the
    conditions ("where" clauses) itself."""

    # Monitor state machine states.
    S_INITIAL = 0
    S_SERVER_SCHEMA_REQUESTED = 1
    S_SERVER_MONITOR_REQUESTED = 2
    S_DATA_MONITOR_REQUESTED = 3
    S_DATA_MONITOR_COND_REQUESTED = 4
    S_DATA_MONITOR_COND_SINCE_REQUESTED = 5
    S_MONITORING = 6

    _STATE_NAMES = {
        S_INITIAL: "S_INITIAL",
        S_SERVER_SCHEMA_REQUESTED: "S_SERVER_SCHEMA_REQUESTED",
        S_SERVER_MONITOR_REQUESTED: "S_SERVER_MONITOR_REQUESTED",
        S_DATA_MONITOR_REQUESTED: "S_DATA_MONITOR_REQUESTED",
        S_DATA_MONITOR_COND_REQUESTED: "S_DATA_MONITOR_COND_REQUESTED",
        S_DATA_MONITOR_COND_SINCE_REQUESTED:
            "S_DATA_MONITOR_COND_SINCE_REQUESTED",
        S_MONITORING: "S_MONITORING",
    }

    def __init__(self, remote, db_name, table_names, ops,
                 probe_interval=None, leader_only=True):
        """Creates a client-synchronization layer for the database named
        'db_name' on 'remote'.

        'remote' can be comma separated multiple remotes and each remote
        should be in a form acceptable to ovs.jsonrpc.session.open().

        'table_names' is the list of table names in the monitored database (the
        CS layer maintains condition state for each).

        'ops' must implement compose_monitor_requests()."""
        self.db_name = db_name
        self._ops = ops
        self.session = None
        self.remote = None
        self.shuffle_remotes = True
        self._probe_interval = probe_interval

        self.state = self.S_INITIAL
        self._last_seqno = None
        self._request_id = None
        # 'set_db_change_aware' and 'monitor_cancel' are sent fire-and-forget
        # (like the C code), but we remember their ids so their replies are
        # consumed silently rather than logged as unexpected messages (the
        # Python 'cs' logger is captured by tests that forbid "unexpected" in
        # the client's output; the C 'ovsdb_cs' logger is not).
        self._db_change_aware_request_id = None
        self._monitor_cancel_request_id = None

        # The two databases: the data db and '_Server' (for clustering/relay).
        # Both flow through the same _db_* helpers.
        self.data = _CsDb(db_name, table_names,
                          self._ops.compose_monitor_requests, 3)
        self.server = _CsDb('_Server', [],
                            self._compose_server_monitor_requests, 2)

        # The _Server replica: a small self-contained set of rows for the
        # 'Database' table, keyed by UUID.
        self._server_db_table = 'Database'
        self._server_columns = {}
        self._server_rows = {}

        self.leader_only = leader_only
        self.cluster_id = None
        self._min_index = 0
        self.db_change_aware = True

        # Transactions submitted through this layer, by request id.
        self._txns = set()

        # Open the initial session.
        self.set_remote(remote, True)

    def _parse_remotes(self, remote):
        # If remote is -
        # "tcp:10.0.0.1:6641,unix:/tmp/db.sock,t,s,tcp:10.0.0.2:6642"
        # this function returns
        # ["tcp:10.0.0.1:6641", "unix:/tmp/db.sock,t,s", tcp:10.0.0.2:6642"]
        remotes = []
        for r in remote.split(','):
            if remotes and r.find(":") == -1:
                remotes[-1] += "," + r
            else:
                remotes.append(r)
        return remotes

    # Introspection used by the IDL to preserve its public interface.

    def is_alive(self):
        return self.session.is_alive()

    def is_connected(self):
        return self.session.is_connected()

    def get_last_error(self):
        return self.session.get_last_error()

    def session_name(self):
        return self.session.get_name()

    def close(self):
        self.session.close()

    def set_cluster_id(self, cluster_id):
        """Set the id of the cluster that this CS layer must connect to."""
        self.cluster_id = cluster_id
        if self.state != self.S_INITIAL:
            self.force_reconnect()

    def set_leader_only(self, leader_only):
        """Set whether this CS layer must connect to the cluster leader.

        By default, the CS layer accepts any cluster member; when
        'leader_only' is true it insists on the leader."""
        self.leader_only = leader_only
        if leader_only and self.server.monitor_version:
            self.check_server_db()

    def force_reconnect(self):
        """Forces the CS layer to drop its connection and reconnect."""
        if self.state == self.S_MONITORING:
            # The session was in MONITORING state, so we either had data
            # inconsistency on this server, or it stopped being the cluster
            # leader, or the user requested to re-connect.  Avoid backoff in
            # these cases, as we need to re-connect as soon as possible.
            # Connections that are not in MONITORING state should have their
            # backoff to avoid constant flood of re-connection attempts in
            # case there is no suitable database server.
            self.session.reset_backoff()
        self.session.force_reconnect()

    def set_remote(self, remote, retry):
        """Makes the CS layer reconnect to 'remote' in place of its current
        target, or disconnect entirely if 'remote' is None.

        'remote' has the same format as the argument to the constructor.  If
        'retry' is true, the CS layer keeps trying to connect indefinitely;
        otherwise it makes a single pass through the remotes and then gives
        up."""
        if remote == self.remote:
            return

        # Close the old session, if any.
        if self.session is not None:
            self.session.close()
            self.session = None

        # Open the new session, if any.
        if remote is not None:
            remotes = self._parse_remotes(remote)
            self.session = ovs.jsonrpc.Session.open_multiple(
                remotes, probe_interval=self._probe_interval, retry=retry,
                shuffle=self.shuffle_remotes)
            # Force the FSM to restart once (re)connected.
            self._last_seqno = None

        self.remote = remote

    def set_shuffle_remotes(self, shuffle):
        """Set whether the CS layer shuffles the order of the remotes each
        time it (re)connects, for load balancing."""
        self.shuffle_remotes = shuffle

    def enable_reconnect(self):
        """Re-enables reconnection to the database after it was disabled by a
        session opened single-shot (retry=False)."""
        if self.session is not None:
            self.session.enable_reconnect()

    def reset_min_index(self):
        """Resets the minimum index that the CS layer will accept from the
        database, allowing a new server with a lower index to be used."""
        self._min_index = 0

    def flag_inconsistency(self):
        """Tells the CS layer that the client detected an inconsistency in the
        database, so it must reconnect and re-download the whole database."""
        self.data.last_id = str(uuid.UUID(int=0))
        self.force_reconnect()

    # The main pump.

    def run(self):
        """Processes a batch of messages from the database server.  Returns a
        list of Event objects that the caller must handle."""
        if self.session is None:
            return []

        self.send_cond_change()
        self.session.run()

        # Detect (re)connection and restart the FSM.  Unlike the C session,
        # whose seqno bumps only on a successful connection, this session bumps
        # its seqno on every connection *attempt*; gate on is_connected() so we
        # restart the FSM (and send the schema request) only once actually
        # connected.
        seqno = self.session.get_seqno()
        if self.session.is_connected() and seqno != self._last_seqno:
            self._last_seqno = seqno
            self.restart_fsm()
            self._txns.clear()
            self._db_add_event(self.data, ReconnectEvent())
            if self.data.lock_name:
                self._send_lock_request()

        for _ in range(50):
            msg = self.session.recv()
            if msg is None:
                break
            self._process_msg(msg)

        events = self.data.events
        self.data.events = []
        return events

    def wait(self, poller):
        """Arranges for poller.block() to wake up when self.run() has something
        to do."""
        if self.data.cond_changed:
            poller.immediate_wake()
            return
        self.session.wait(poller)
        self.session.recv_wait(poller)

    def restart_fsm(self):
        self._send_schema_request(self.server)
        self.state = self.S_SERVER_SCHEMA_REQUESTED
        self.data.monitor_version = 0
        self.server.monitor_version = 0

    def _process_msg(self, msg):
        """Dispatches a single message (mirrors ovsdb_cs_process_msg)."""
        is_response = msg.type in (ovs.jsonrpc.Message.T_REPLY,
                                   ovs.jsonrpc.Message.T_ERROR)

        # Process a reply to our outstanding request.
        if (is_response and self._request_id is not None
                and self._request_id == msg.id):
            self._request_id = None
            self._process_response(msg)
            return

        # Consume the replies to fire-and-forget requests (see __init__).
        if is_response and msg.id in (self._db_change_aware_request_id,
                                      self._monitor_cancel_request_id):
            return

        # Process database contents updates.
        if self._db_parse_update_rpc(self.data, msg):
            return
        if (self.server.monitor_version
                and self._db_parse_update_rpc(self.server, msg)):
            self.check_server_db()
            return

        if (self._handle_monitor_canceled(self.data, msg)
                or (self.server.monitor_version
                    and self._handle_monitor_canceled(self.server, msg))):
            return

        # Process "lock" replies and related notifications.
        if self._db_process_lock_replies(self.data, msg):
            return

        # Process a reply to a transaction we submitted.
        if is_response and self._db_txn_process_reply(msg):
            return

        # Silently drop the in-flight tail of a server monitor we have already
        # canceled.  The C code lets these fall through to the DBG log below,
        # which its tests don't capture, but the Python 'cs' logger is captured
        # by tests that forbid "unexpected" messages.
        if self._is_stale_server_monitor(msg):
            return

        # Unknown message.  Log at a low level because this can happen if a
        # transaction is destroyed before we receive the reply.
        vlog.dbg("%s: received unexpected %s message"
                 % (self.session_name(),
                    ovs.jsonrpc.Message.type_to_string(msg.type)))

    def _process_response(self, msg):
        """Handles a reply to our outstanding request (mirrors
        ovsdb_cs_process_response)."""
        ok = msg.type == ovs.jsonrpc.Message.T_REPLY
        if not ok and self.state not in (
                self.S_SERVER_SCHEMA_REQUESTED,
                self.S_SERVER_MONITOR_REQUESTED,
                self.S_DATA_MONITOR_COND_REQUESTED,
                self.S_DATA_MONITOR_COND_SINCE_REQUESTED):
            vlog.info("%s: received unexpected %s response in %s state"
                      % (self.session_name(),
                         ovs.jsonrpc.Message.type_to_string(msg.type),
                         self._STATE_NAMES.get(self.state, self.state)))
            self.force_reconnect()
            return

        if self.state == self.S_SERVER_SCHEMA_REQUESTED:
            if ok:
                try:
                    self.server.schema = ovs.db.schema.DbSchema.from_json(
                        msg.result)
                except error.Error as e:
                    vlog.err("%s: error parsing server schema: %s"
                             % (self.session_name(), e))
                    self.force_reconnect()
                    return
                self._send_monitor_request(self.server,
                                           self.server.max_version)
                self.state = self.S_SERVER_MONITOR_REQUESTED
            else:
                self._fallback_to_data_monitor()
        elif self.state == self.S_SERVER_MONITOR_REQUESTED:
            if ok:
                self.server.monitor_version = self.server.max_version
                self._db_parse_monitor_reply(self.server, msg.result,
                                             self.server.monitor_version)
                if self.check_server_db() and self.db_change_aware:
                    self._send_db_change_aware()
            else:
                self._fallback_to_data_monitor()
        elif self.state == self.S_DATA_MONITOR_COND_SINCE_REQUESTED:
            if not ok:
                # "monitor_cond_since" not supported.  Try "monitor_cond".
                self._send_monitor_request(self.data, 2)
                self.state = self.S_DATA_MONITOR_COND_REQUESTED
            else:
                self.data.monitor_version = 3
                self.state = self.S_MONITORING
                self._db_parse_monitor_reply(self.data, msg.result, 3)
        elif self.state == self.S_DATA_MONITOR_COND_REQUESTED:
            if not ok:
                # "monitor_cond" not supported.  Try "monitor".
                self._send_monitor_request(self.data, 1)
                self.state = self.S_DATA_MONITOR_REQUESTED
            else:
                self.data.monitor_version = 2
                self.state = self.S_MONITORING
                self._db_parse_monitor_reply(self.data, msg.result, 2)
        elif self.state == self.S_DATA_MONITOR_REQUESTED:
            self.data.monitor_version = 1
            self.state = self.S_MONITORING
            self._db_parse_monitor_reply(self.data, msg.result, 1)
        elif self.state == self.S_MONITORING:
            # We don't normally have a request outstanding in this state.  If
            # we do, it's a "monitor_cond_change", which means the conditional
            # monitor clauses were updated.  Mark the last requested conditions
            # as acked and if further condition changes were pending, send them
            # now.
            self._db_ack_condition(self.data)
            self.send_cond_change()
            self.data.cond_seqno += 1
        else:
            vlog.dbg("%s: received reply in unexpected state %s"
                     % (self.session_name(),
                        self._STATE_NAMES.get(self.state, self.state)))

    def _fallback_to_data_monitor(self):
        """Called when the _Server schema/monitor negotiation fails.

        The C code falls back to fetching the data database's schema directly
        (the S_DATA_SCHEMA_REQUESTED state).  Python does not replicate that
        state; instead it proceeds straight to a data monitor request, letting
        the monitor_cond_since -> monitor_cond -> monitor downgrade chain sort
        out what the server actually supports.  A clustered client cannot make
        clustering decisions without the _Server data, so it reconnects."""
        if self.cluster_id:
            self.force_reconnect()
            return
        self._send_monitor_request(self.data, self.data.max_version)
        self.state = self.S_DATA_MONITOR_COND_SINCE_REQUESTED

    def send_request(self, request):
        self._request_id = request.id
        if self.session.is_connected():
            return self.session.send(request)

    # Monitor / schema requests (parameterized by database).

    def _send_schema_request(self, db):
        self.send_request(ovs.jsonrpc.Message.create_request(
            "get_schema", [db.db_name]))

    def _send_monitor_request(self, db, version):
        monitor_requests = db.ops(db.schema)

        # Resync table conditions to avoid missing updates due to conditions
        # that were in flight or changed locally while the connection was
        # down.  This must happen after composing the monitor requests, since
        # composing may update the conditions to match the server's schema
        # (see compose_monitor_requests in ovs.db.idl).
        self._db_sync_condition(db)

        if version > 1:
            for name, mrs in monitor_requests.items():
                table = db.tables.get(name)
                if table is None:
                    continue
                acked = table.condition_state.acked
                if not ConditionState.is_true(acked) and mrs:
                    mrs[0]["where"] = acked

        method = {1: "monitor", 2: "monitor_cond",
                  3: "monitor_cond_since"}[version]
        params = [db.db_name, str(db.monitor_id), monitor_requests]
        if version == 3:
            params.append(str(db.last_id))
        self.send_request(ovs.jsonrpc.Message.create_request(method, params))

    def _send_db_change_aware(self):
        msg = ovs.jsonrpc.Message.create_request("set_db_change_aware", [True])
        self._db_change_aware_request_id = msg.id
        self.session.send(msg)

    def _db_add_event(self, db, event):
        db.events.append(event)

    def _db_add_update(self, db, table_updates, version, clear, monitor_reply):
        self._db_add_event(db, UpdateEvent(clear, monitor_reply, table_updates,
                                           _UPDATE_VERSION[version],
                                           db.last_id))

    def _db_parse_monitor_reply(self, db, result, version):
        if version == 3:
            try:
                found = result[0]
                db.last_id = result[1]
                table_updates = result[2]
            except (IndexError, TypeError):
                vlog.warn("%s: bad monitor_cond_since reply format"
                          % self.session_name())
                return
            clear = not found
        else:
            clear = True
            table_updates = result
        self._db_add_update(db, table_updates, version, clear, True)

    def _db_parse_update_rpc(self, db, msg):
        if msg.type != ovs.jsonrpc.Message.T_NOTIFY:
            return False

        version = {OVSDB_UPDATE: 1, OVSDB_UPDATE2: 2, OVSDB_UPDATE3: 3}.get(
            msg.method, 0)
        if not version:
            return False

        n = 3 if version == 3 else 2
        if not isinstance(msg.params, (list, tuple)) or len(msg.params) != n:
            vlog.warn("%s: %s must be an array with %d elements"
                      % (self.session_name(), msg.method, n))
            return False

        if msg.params[0] != str(db.monitor_id):
            return False

        if version == 3:
            db.last_id = msg.params[1]
        table_updates = msg.params[2 if version == 3 else 1]
        self._db_add_update(db, table_updates, version, False, False)
        return True

    def _handle_monitor_canceled(self, db, msg):
        if (msg.type != ovs.jsonrpc.Message.T_NOTIFY
                or msg.method != "monitor_canceled"
                or not isinstance(msg.params, (list, tuple))
                or len(msg.params) != 1
                or msg.params[0] != str(db.monitor_id)):
            return False

        db.monitor_version = 0

        # Cancel the other monitor and restart the FSM from the top.
        other_db = self.server if db is self.data else self.data
        if other_db.monitor_version:
            request = ovs.jsonrpc.Message.create_request(
                "monitor_cancel", [str(other_db.monitor_id)])
            self._monitor_cancel_request_id = request.id
            self.session.send(request)
            other_db.monitor_version = 0
        self.restart_fsm()
        return True

    def _is_stale_server_monitor(self, msg):
        """Returns True if 'msg' is monitor traffic (an update or a
        monitor_canceled notification) for a server monitor we have already
        canceled, i.e. its tail still in flight.  Stale data-monitor traffic
        is already consumed by _db_parse_update_rpc()/_handle_monitor_canceled
        because those match on monitor_id regardless of monitor_version; the
        server monitor is gated on monitor_version in the dispatcher (mirroring
        the C code), so its tail needs to be recognized here."""
        return (not self.server.monitor_version
                and msg.type == ovs.jsonrpc.Message.T_NOTIFY
                and msg.method in ("update", "update2", "update3",
                                   "monitor_canceled")
                and isinstance(msg.params, (list, tuple))
                and len(msg.params) >= 1
                and msg.params[0] == str(self.server.monitor_id))

    # Conditions.

    def _db_ack_condition(self, db):
        """Mark all requested table conditions as acked."""
        for table in db.tables.values():
            table.condition_state.ack()

    def _db_sync_condition(self, db):
        """Synchronize condition state when the FSM is restarted.

        See ovs.db.idl for the detailed rationale."""
        for table in db.tables.values():
            if table.condition_state.requested is not None:
                # There was an in-flight condition change - reset.
                db.last_id = str(uuid.UUID(int=0))
                break

        if db.last_id == str(uuid.UUID(int=0)):
            # No 'last_id' - use the latest conditions for the monitor request.
            for table in db.tables.values():
                table.condition_state.request()
                table.condition_state.ack()
            # Nothing to send after the initial monitor request.
            db.cond_changed = False
        else:
            # No in-flight changes and a non-zero 'last_id'.  Send acknowledged
            # first, then follow up with the new, if any.
            for table in db.tables.values():
                if table.condition_state.new is not None:
                    db.cond_changed = True
                    break

    def _db_compose_cond_change(self, db):
        if not db.cond_changed:
            return None

        change_requests = {}
        for name, table in db.tables.items():
            # Always use the most recent conditions set by the IDL client when
            # requesting monitor_cond_change
            if table.condition_state.new is not None:
                change_requests[name] = [{"where": table.condition_state.new}]
                table.condition_state.request()

        if not change_requests:
            return None

        db.cond_changed = False
        old_uuid = str(db.monitor_id)
        db.monitor_id = uuid.uuid1()
        params = [old_uuid, str(db.monitor_id), change_requests]
        return ovs.jsonrpc.Message.create_request("monitor_cond_change",
                                                  params)

    def send_cond_change(self):
        # When '_request_id' is not None, there is an outstanding conditional
        # monitoring update request that we have not heard from the server yet.
        # Don't generate another request in this case.
        if (not self.session.is_connected()
                or self.data.monitor_version == 1
                or self._request_id is not None):
            return

        msg = self._db_compose_cond_change(self.data)
        if msg:
            self.send_request(msg)

    def set_condition(self, table_name, cond):
        """Sets the condition for 'table_name' to 'cond'.  Returns the
        condition sequence number at which the change will have taken
        effect."""
        table = self.data.tables.get(table_name)
        if table is None:
            raise error.Error('Unknown table "%s"' % table_name)

        if cond == []:
            cond = [False]

        # Compare the new condition to the last known condition
        if table.condition_state.latest != cond:
            table.condition_state.init(cond)
            self.data.cond_changed = True

        # New condition will be sent out after all already requested ones
        # are acked.
        if table.condition_state.new:
            any_reqs = any(t.condition_state.requested is not None
                           for t in self.data.tables.values())
            return self.data.cond_seqno + int(any_reqs) + 1

        # Already requested conditions should be up to date at
        # self.data.cond_seqno + 1 while acked conditions are already up to
        # date
        requested = table.condition_state.requested is not None
        return self.data.cond_seqno + int(requested)

    def get_condition_seqno(self):
        return self.data.cond_seqno

    # Database change awareness.

    def set_db_change_aware(self, db_change_aware):
        """By default, or if 'db_change_aware' is True, the CS layer sends a
        'set_db_change_aware' request to the server after receiving the _Server
        data (when the server supports it), which is useful for clients that
        intend to keep long connections to the server.  Otherwise, it will not
        send the request, which is more reasonable for short-lived connections
        to avoid unnecessary processing at the server side and possible error
        handling due to connections being closed by the clients before the
        responses are sent by the server."""
        self.db_change_aware = db_change_aware

    # Locking.

    def set_lock(self, lock_name):
        """If 'lock_name' is not None, configures the CS layer to obtain the
        named lock; if None, drops the locking requirement and releases the
        lock."""
        assert not self._txns

        if (self.data.lock_name
                and (not lock_name or lock_name != self.data.lock_name)):
            # Release previous lock.
            self._send_unlock_request()
            self.data.lock_name = None
            self.data.is_lock_contended = False

        if lock_name and not self.data.lock_name:
            # Acquire new lock.
            self.data.lock_name = lock_name
            self._send_lock_request()

    def get_lock(self):
        return self.data.lock_name

    def has_lock(self):
        return self.data.has_lock

    def is_lock_contended(self):
        return self.data.is_lock_contended

    def _db_update_has_lock(self, db, new_has_lock):
        if new_has_lock and not db.has_lock:
            self._db_add_event(db, LockedEvent())
            db.is_lock_contended = False
        db.has_lock = new_has_lock

    def _db_process_lock_replies(self, db, msg):
        if (msg.type == ovs.jsonrpc.Message.T_REPLY
                and db.lock_request_id is not None
                and db.lock_request_id == msg.id):
            # Reply to our "lock" request.
            self._db_parse_lock_reply(db, msg.result)
            return True

        if msg.type == ovs.jsonrpc.Message.T_NOTIFY:
            if msg.method == "locked":
                # We got our lock.
                return self._db_parse_lock_notify(db, msg.params, True)
            elif msg.method == "stolen":
                # Someone else stole our lock.
                return self._db_parse_lock_notify(db, msg.params, False)

        return False

    def _compose_lock_request(self, method):
        self._db_update_has_lock(self.data, False)
        self.data.lock_request_id = None
        if self.session.is_connected():
            msg = ovs.jsonrpc.Message.create_request(
                method, [self.data.lock_name])
            self.session.send(msg)
            return msg.id
        return None

    def _send_lock_request(self):
        self.data.lock_request_id = self._compose_lock_request("lock")

    def _send_unlock_request(self):
        self._compose_lock_request("unlock")

    def _db_parse_lock_reply(self, db, result):
        db.lock_request_id = None
        got_lock = isinstance(result, dict) and result.get("locked") is True
        self._db_update_has_lock(db, got_lock)
        if not got_lock:
            db.is_lock_contended = True

    def _db_parse_lock_notify(self, db, params, new_has_lock):
        if (db.lock_name is not None
                and isinstance(params, (list, tuple))
                and params
                and params[0] == db.lock_name):
            self._db_update_has_lock(db, new_has_lock)
            if not new_has_lock:
                db.is_lock_contended = True
            return True
        return False

    # Transactions.

    def may_send_transaction(self):
        """Returns True if a transaction can be sent now.  There is no point in
        composing and sending a transaction if this returns False."""
        return (self.session is not None
                and self.state == self.S_MONITORING
                and (not self.data.lock_name or self.data.has_lock))

    def send(self, request):
        """Sends a request over the session and records it as an outstanding
        transaction so its reply is reported through a TxnReplyEvent.  Returns
        the session send() result (0 on success)."""
        error_code = self.session.send(request)
        if not error_code:
            self._txns.add(request.id)
        return error_code

    def forget_transaction(self, request_id):
        """Makes the CS layer drop its record of transaction 'request_id'."""
        self._txns.discard(request_id)

    def _db_txn_process_reply(self, msg):
        if msg.id in self._txns:
            self._txns.discard(msg.id)
            self._db_add_event(self.data, TxnReplyEvent(msg))
            return True
        return False

    # The _Server database.
    #
    # We replicate the Database table in the _Server database because this is
    # the only way to find out properties we need to know for clustering, such
    # as whether a database is clustered at all and whether this server is the
    # leader.  This is a small self-contained replica -- it does not use the
    # typed Row machinery of the IDL proper.

    def _compose_server_monitor_requests(self, schema):
        """The '_Server' database's ops.compose_monitor_requests() (mirrors
        ovsdb_cs_compose_server_monitor_request).  'schema' is the parsed
        _Server DbSchema; requests all columns of the 'Database' table."""
        table = schema.tables.get(self._server_db_table) if schema else None
        self._server_columns = table.columns if table else {}
        columns = list(self._server_columns.keys())
        return {self._server_db_table: [{"columns": columns}]}

    def _process_server_event(self, event):
        if event.clear:
            self._server_rows = {}
        self._parse_server_update(event.table_updates, event.version)

    def _parse_server_update(self, table_updates, version):
        # The _Server replica flows through the same parse_db_update() as the
        # data replica (mirroring the C code, where both databases share
        # ovsdb_cs_parse_db_update()).  Malformed input is logged and ignored
        # rather than allowed to escape, since the server replica is advisory.
        try:
            db_update = parse_db_update(table_updates, version)
        except error.Error as e:
            vlog.warn("error parsing _Server update: %s" % e)
            return

        for ru in db_update.get(self._server_db_table, []):
            if ru.type == ROW_UPDATE_DELETE:
                self._server_rows.pop(ru.uuid, None)
            elif ru.type == ROW_UPDATE_INSERT:
                self._server_rows[ru.uuid] = self._new_server_row(ru.columns)
            elif ru.type == ROW_UPDATE_XOR:
                row = self._server_rows.get(ru.uuid)
                if row is not None:
                    self._apply_server_diff(row, ru.columns)
            elif ru.type == ROW_UPDATE_UPDATE:
                # Version 1 "modify": 'columns' is a partial <row> of just the
                # changed columns.  The _Server monitor always negotiates
                # version 2, so this is not reached in practice; merge the
                # changed columns for correctness should that ever change.
                row = self._server_rows.get(ru.uuid)
                if row is not None:
                    self._merge_server_row(row, ru.columns)

    def _new_server_row(self, row_json):
        row = {}
        for name, column in self._server_columns.items():
            value = row_json.get(name)
            if value is None and column.type.n_min != 0 \
                    and not column.type.is_map():
                # A required scalar column is absent from the update.  Supply
                # the type's JSON default so it parses into a proper datum;
                # data.Datum.default() makes a scalar datum whose as_scalar()
                # does not round-trip, which would misread e.g. a boolean.
                value = self._column_default_json(column)
            if value is not None:
                try:
                    row[name] = data.Datum.from_json(column.type, value)
                    continue
                except error.Error:
                    pass
            row[name] = data.Datum.default(column.type)
        return row

    @staticmethod
    def _column_default_json(column):
        if column.type.key.type == ovs.db.types.UuidType:
            return ovs.ovsuuid.to_json(column.type.key.type.default)
        else:
            return column.type.key.type.default

    def _apply_server_diff(self, row, row_diff):
        for name, diff_json in row_diff.items():
            column = self._server_columns.get(name)
            if not column:
                continue
            try:
                diff = data.Datum.from_json(column.type, diff_json)
            except error.Error:
                continue
            row[name] = row[name].diff(diff)

    def _merge_server_row(self, row, row_json):
        # Overwrites just the columns present in a version 1 "modify" <row>,
        # leaving the rest of 'row' intact (see _parse_server_update).
        for name, value in row_json.items():
            column = self._server_columns.get(name)
            if not column:
                continue
            try:
                row[name] = data.Datum.from_json(column.type, value)
            except error.Error:
                continue

    @staticmethod
    def _server_value(row, name):
        datum = row.get(name)
        if datum is None:
            return None
        return datum.to_python(lambda atom, base: atom)

    def check_server_db(self):
        """Drains and evaluates the _Server replica, kicking off the data
        monitor when appropriate.  Forces a reconnect and returns False if the
        server is not usable (mirrors ovsdb_cs_check_server_db)."""
        ok = self._check_server_db()
        if not ok:
            self.force_reconnect()
        return ok

    def _check_server_db(self):
        """Returns True if this is a valid server database, False otherwise."""
        for event in self.server.events:
            self._process_server_event(event)
        self.server.events = []

        session_name = self.session_name()

        if not self._server_columns:
            vlog.info("%s: server does not have %s table in its %s database"
                      % (session_name, self._server_db_table,
                         self.server.db_name))
            return False

        database = None
        for row in self._server_rows.values():
            if self.cluster_id:
                cid = self._server_value(row, "cid") or []
                if self.cluster_id in map(lambda x: str(x)[:4], cid):
                    database = row
                    break
            elif self._server_value(row, "name") == self.data.db_name:
                database = row
                break

        if not database:
            vlog.info("%s: server does not have %s database"
                      % (session_name, self.data.db_name))
            return False

        model = self._server_value(database, "model")
        schema = self._server_value(database, "schema")
        connected = self._server_value(database, "connected")
        leader = self._server_value(database, "leader")
        index = self._server_value(database, "index")

        if model == CLUSTERED:
            if not schema:
                vlog.info('%s: clustered database server has not yet joined '
                          'cluster; trying another server' % session_name)
                return False
            if not connected:
                vlog.info('%s: clustered database server is disconnected '
                          'from cluster; trying another server' % session_name)
                return False
            if self.leader_only and not leader:
                vlog.info('%s: clustered database server is not cluster '
                          'leader; trying another server' % session_name)
                return False
            if index:
                if index[0] < self._min_index:
                    vlog.warn('%s: clustered database server has stale data; '
                              'trying another server' % session_name)
                    return False
                self._min_index = index[0]
        elif model == RELAY:
            if not schema:
                vlog.info('%s: relay database server has not yet connected '
                          'to the relay source; trying another server'
                          % session_name)
                return False
            if not connected:
                vlog.info('%s: relay database server is disconnected '
                          'from the relay source; trying another server'
                          % session_name)
                return False
            if self.leader_only:
                vlog.info('%s: relay database server cannot be a leader; '
                          'trying another server' % session_name)
                return False

        if self.state == self.S_SERVER_MONITOR_REQUESTED:
            # Kick off the data monitor now that the server db is up to date.
            self._send_monitor_request(self.data, self.data.max_version)
            self.state = self.S_DATA_MONITOR_COND_SINCE_REQUESTED

        return True
