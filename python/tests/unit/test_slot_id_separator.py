import pytest
from unittest.mock import MagicMock

from aun_core.config import normalize_slot_id, slot_isolation_key
from aun_core.client import AUNClient
from aun_core.errors import ValidationError


# --- slot_isolation_key ---

def test_space_separator():
    assert slot_isolation_key("evolclaw cli") == "evolclaw"

def test_slash_separator():
    assert slot_isolation_key("evolclaw/cli") == "evolclaw"

def test_colon_separator():
    assert slot_isolation_key("evolclaw:daemon") == "evolclaw"

def test_no_separator():
    assert slot_isolation_key("simple") == "simple"

def test_multiple_separators_takes_first():
    assert slot_isolation_key("a/b/c") == "a"

def test_separator_in_middle():
    assert slot_isolation_key("a b") == "a"


# --- normalize_slot_id ---

def test_allows_space():
    assert normalize_slot_id("evolclaw cli") == "evolclaw cli"

def test_allows_slash():
    assert normalize_slot_id("evolclaw/cli") == "evolclaw/cli"

def test_allows_colon():
    assert normalize_slot_id("evolclaw:daemon") == "evolclaw:daemon"

def test_rejects_leading_slash():
    with pytest.raises(ValueError):
        normalize_slot_id("/invalid")

def test_rejects_leading_colon():
    with pytest.raises(ValueError):
        normalize_slot_id(":invalid")

def test_empty_falls_back_to_default():
    assert normalize_slot_id(None) == "default"
    assert normalize_slot_id("") == "default"


# --- _message_targets_current_instance ---

def _make_client(slot_id: str) -> AUNClient:
    client = object.__new__(AUNClient)
    client._slot_id = slot_id
    client._device_id = "test-device"
    return client

def test_same_prefix_different_suffix_receives():
    client = _make_client("evolclaw cli")
    assert client._message_targets_current_instance({"slot_id": "evolclaw daemon"}) is True

def test_different_prefix_does_not_receive():
    client = _make_client("evolclaw cli")
    assert client._message_targets_current_instance({"slot_id": "other daemon"}) is False

def test_no_slot_id_field_receives():
    client = _make_client("evolclaw cli")
    assert client._message_targets_current_instance({"content": "hello"}) is True


# --- _inject_message_cursor_context ---

@pytest.mark.parametrize("slot_id", ["evolclaw cli", "evolclaw/cli", "evolclaw:cli"])
def test_message_cursor_context_accepts_slot_separators(slot_id):
    client = _make_client(slot_id)
    params = {"after_seq": 0, "limit": 10}

    client._inject_message_cursor_context("message.pull", params)

    assert params["device_id"] == "test-device"
    assert params["slot_id"] == slot_id


def test_message_cursor_context_matches_slot_isolation_key():
    client = _make_client("evolclaw cli")
    params = {"seq": 1, "slot_id": "evolclaw daemon"}

    client._inject_message_cursor_context("message.ack", params)

    assert params["device_id"] == "test-device"
    assert params["slot_id"] == "evolclaw cli"


def test_message_cursor_context_rejects_different_slot_isolation_key():
    client = _make_client("evolclaw cli")
    with pytest.raises(ValidationError, match="slot_id must match"):
        client._inject_message_cursor_context("message.pull", {
            "after_seq": 0,
            "slot_id": "other daemon",
        })
