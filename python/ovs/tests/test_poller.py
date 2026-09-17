import select

from unittest import mock

import ovs.poller

# select.poll is a builtin function, not a type, so capture the type of the
# object it returns in order to be able to assert on it.
POLL_TYPE = type(select.poll())


def test_poller_uses_poll_by_default():
    """Poller must use poll(2) when select.select is the real select(2).

    select(2) raises ValueError for a file descriptor numbered FD_SETSIZE
    (1024) or higher, poll(2) has no such limit.
    """
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=False), \
            mock.patch.object(ovs.poller, 'gevent_monkey', None):
        assert isinstance(ovs.poller.Poller().poll, POLL_TYPE)


def test_poller_uses_select_under_eventlet():
    """Poller must keep emulating poll with select.select under eventlet.

    The green select has no FD_SETSIZE limit either and, unlike the real
    poll(2), it yields to the hub instead of blocking the interpreter.
    """
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=True):
        assert isinstance(ovs.poller.Poller().poll, ovs.poller._SelectSelect)


def test_poller_uses_select_under_gevent():
    """Same as under eventlet, for a gevent patched select.select."""
    gevent_monkey = mock.Mock()
    gevent_monkey.is_object_patched.return_value = True
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=False), \
            mock.patch.object(ovs.poller, 'gevent_monkey', gevent_monkey):
        assert isinstance(ovs.poller.Poller().poll, ovs.poller._SelectSelect)
    gevent_monkey.is_object_patched.assert_called_once_with('select',
                                                            'select')
