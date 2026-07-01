import pytest

from aun_core.errors import ValidationError
from aun_core.group_id import (
    build_discovery_host,
    convert_to_group_aid,
    normalize_group_aid,
    normalize_group_id,
    split_group_id,
)
from aun_core.validators import validate_group_aid_format


def test_convert_to_group_aid_accepts_all_compatible_forms():
    assert convert_to_group_aid("room-123.agentid.pub") == "room-123.agentid.pub"
    assert convert_to_group_aid("group.agentid.pub/room-123") == "room-123.agentid.pub"
    assert convert_to_group_aid("room-123@agentid.pub") == "room-123.agentid.pub"
    assert convert_to_group_aid("g-abc123", local_issuer="agentid.pub") == "g-abc123.agentid.pub"
    assert convert_to_group_aid("group.pub/room-123@agentid") == "room-123.agentid.pub"


def test_normalize_legacy_group_id_names_return_group_aid():
    assert normalize_group_aid("group.agentid.pub/room-123") == "room-123.agentid.pub"
    assert normalize_group_id("group.agentid.pub/room-123") == "room-123.agentid.pub"


def test_split_group_id_and_discovery_host_do_not_rsplit_issuer():
    assert split_group_id("room-123.agentid.pub") == ("room-123", "agentid.pub")
    assert split_group_id("group.agentid.pub/room-123") == ("room-123", "agentid.pub")
    assert build_discovery_host("room-123.agentid.pub") == "agentid.pub"


def test_convert_to_group_aid_empty_and_slashes_do_not_create_default_group():
    assert convert_to_group_aid("") == ""
    assert convert_to_group_aid("   ") == ""
    assert convert_to_group_aid("///") == ""


@pytest.mark.parametrize(
    "raw",
    [
        "group.agentid.pub//room-123",
        "room#123.agentid.pub",
        f"{'a' * 65}.agentid.pub",
    ],
)
def test_validate_group_aid_rejects_malformed_or_too_long_input(raw):
    with pytest.raises(ValidationError):
        validate_group_aid_format(raw)
