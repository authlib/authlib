import pytest

from authlib.integrations.fastapi_oauth2.signals import client_authenticated
from authlib.integrations.fastapi_oauth2.signals import token_authenticated
from authlib.integrations.fastapi_oauth2.signals import token_revoked


@pytest.mark.parametrize(
    "signal",
    [
        client_authenticated,
        token_revoked,
        token_authenticated,
    ],
)
def test_signal_can_receive_events(signal):
    calls = []

    def receiver(sender, **kwargs):
        calls.append((sender, kwargs))

    signal.connect(receiver, weak=False)

    try:
        sender = object()
        signal.send(sender, user_id=123)

        assert len(calls) == 1
        assert calls[0][0] is sender
        assert calls[0][1] == {"user_id": 123}
    finally:
        signal.disconnect(receiver)


def test_signals_are_independent():
    calls = []

    def receiver(sender, **kwargs):
        calls.append(sender)

    client_authenticated.connect(receiver, weak=False)

    try:
        sender = object()

        token_authenticated.send(sender)

        assert calls == []
    finally:
        client_authenticated.disconnect(receiver)


def test_all_signals_are_distinct():
    signals = [
        client_authenticated,
        token_revoked,
        token_authenticated,
    ]

    assert len(set(signals)) == 3


def test_signal_without_receivers_does_not_raise():
    sender = object()

    assert client_authenticated.send(sender) == []
    assert token_revoked.send(sender) == []
    assert token_authenticated.send(sender) == []
