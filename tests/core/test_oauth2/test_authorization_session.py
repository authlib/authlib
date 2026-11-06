import types

import pytest

from authlib.oauth2 import AuthorizationSession

KEY = "authlib_request_times"


class RecordingSession(dict):
    """A framework session that records its writes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.writes = 0

    def __setitem__(self, key, value):
        self.writes += 1
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self.writes += 1
        super().__delitem__(key)


@pytest.fixture(autouse=True)
def now(monkeypatch):
    monkeypatch.setattr("time.time", lambda: 1000.5)
    return 1000


def create_session(times=None):
    """Return an authorization session on a framework session with the given
    start times."""
    store = RecordingSession({KEY: times} if times is not None else {})
    return AuthorizationSession("user", store)


def create_request(key):
    """Return an authorization request with the given key."""
    return types.SimpleNamespace(authorization_key=key)


def test_get_user():
    """The user is the one given to the constructor."""
    assert create_session().get_user() == "user"


def test_request_time_is_kept(now):
    """The first call stores the current time, in whole seconds. The next
    calls return it without writing the session."""
    session = create_session()
    assert session.get_request_time(create_request("a")) == now
    assert session.session[KEY] == {"a": now}
    assert session.session.writes == 1

    assert session.get_request_time(create_request("a")) == now
    assert session.session.writes == 1


def test_old_request_times_are_removed(now):
    """The start times older than request_time_lifetime are removed, also
    the one of the current request."""
    session = create_session({"old": now - 601, "recent": now - 600})
    session.get_request_time(create_request("new"))
    assert session.session[KEY] == {"recent": now - 600, "new": now}

    session = create_session({"old": now - 601})
    assert session.get_request_time(create_request("old")) == now


def test_max_request_times(now):
    """At most max_request_times start times are kept. The oldest are
    removed first, but the time of the current request is kept."""
    times = {f"k{index}": now - 50 + index * 10 for index in range(5)}
    session = create_session(dict(times))
    session.get_request_time(create_request("new"))
    assert set(session.session[KEY]) == {"k1", "k2", "k3", "k4", "new"}

    session = create_session(dict(times))
    assert session.get_request_time(create_request("k0")) == now - 50
    assert set(session.session[KEY]) == {"k0", "k1", "k2", "k3", "k4"}


@pytest.mark.parametrize("max_request_times", [0, 1])
def test_only_current_request(now, max_request_times):
    """With max_request_times at 1 or less, only the current request is
    kept."""
    session = create_session({"a": now})
    session.max_request_times = max_request_times
    session.get_request_time(create_request("b"))
    assert session.session[KEY] == {"b": now}


def test_unknown_request():
    """Without an authorization key, there is no start time."""
    session = create_session()
    assert session.get_request_time(create_request(None)) is None
    assert KEY not in session.session


def test_end_request(now):
    """end_request removes the start time of the request, and the session key
    when it is empty."""
    session = create_session({"a": now, "b": now})
    session.end_request(create_request("a"))
    assert session.session[KEY] == {"b": now}

    session.end_request(create_request("b"))
    assert KEY not in session.session


@pytest.mark.parametrize("key", ["unknown", None])
def test_end_unknown_request(now, key):
    """end_request does not write the session for an unknown request."""
    session = create_session({"a": now})
    session.end_request(create_request(key))
    assert session.session[KEY] == {"a": now}
    assert session.session.writes == 0
