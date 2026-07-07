import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core.aid import AID
from aun_core.facades import GroupFacade
from aun_core.group_index import GROUP_INDEX_SCHEMA, build_signed_group_index, parse_group_index, verify_group_index


def _aid(name: str = "owner.example.test") -> AID:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    return AID._create(
        aid=name,
        aun_path="",
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        cert_obj=cert,
        private_key_obj=key,
        cert_valid=True,
        private_key_valid=True,
        private_key_pem=private_pem,
    )


def _index(aid: AID, etag_seed: str):
    return build_signed_group_index(
        group_aid="g-team.example.test",
        entries=[{"key": "rules.content", "source": "db", "etag": f'"sha256:{etag_seed}"', "last_modified": 1}],
        signer=aid,
        last_modified=1,
    )


def _index_with_entries(aid: AID, entries):
    return build_signed_group_index(
        group_aid="g-team.example.test",
        entries=entries,
        signer=aid,
        last_modified=1,
    )


def _tamper_index(index):
    lines = index["body"].splitlines()
    entry = parse_group_index(index["body"])["entries"][0]
    entry["etag"] = '"sha256:tampered"'
    lines[1] = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {**index, "body": "\n".join(lines) + "\n"}


class FakeClient:
    def __init__(self, aid: AID, get_results, *, fail_first_set=False):
        self.current_aid = aid
        self.get_results = list(get_results)
        self.fail_first_set = fail_first_set
        self.calls = []
        self.remote_meta = {}
        self.local_etag = ""
        self.stale = False
        self.fresh_marks = []
        self.remote_settings = {}
        self.cached_settings = {}
        self.cached_entry_etags = {}
        self.cached_group_etag = ""
        self.cache_calls = []

    async def call(self, method, params):
        self.calls.append((method, params))
        if method == "group.get_settings":
            keys = list(params.get("keys") or [])
            if keys == ["group.index"]:
                value = self.get_results.pop(0) if self.get_results else None
                settings = [{"key": "group.index", "value": value}] if value else []
            else:
                settings = [
                    {"key": key, "value": self.remote_settings[key]}
                    for key in keys
                    if key in self.remote_settings
                ]
            return {"group_id": params["group_id"], "group_aid": "g-team.example.test", "settings": settings}
        if method == "group.set_settings":
            if self.fail_first_set:
                self.fail_first_set = False
                raise ValueError("group.index etag conflict")
            return {"group_id": params["group_id"], "updated_keys": list(params["settings"].keys())}
        raise AssertionError(method)

    def is_group_index_stale(self, group_aid):
        return self.stale

    def get_group_index_remote_meta(self, group_aid):
        return self.remote_meta

    def get_group_index_local_etag(self, group_aid):
        return self.local_etag

    def mark_group_index_fresh(self, group_aid, *, etag):
        self.fresh_marks.append((group_aid, etag))
        self.stale = False
        self.local_etag = etag

    def get_group_index_cached_settings(self, group_aid, keys):
        if not all(key in self.cached_settings for key in keys):
            return None
        return {key: self.cached_settings[key] for key in keys}

    def get_group_index_cached_settings_by_entries(self, group_aid, keys, entries):
        cached = {}
        missing = []
        entry_etags = {str(item.get("key")): str(item.get("etag") or "") for item in entries}
        for key in keys:
            if key in self.cached_settings and self.cached_entry_etags.get(key) == entry_etags.get(key):
                cached[key] = self.cached_settings[key]
            else:
                missing.append(key)
        return cached, missing

    def cache_group_index_settings(self, group_aid, settings, *, entries=None, etag="", group_index=None):
        self.cache_calls.append(group_aid)
        self.cached_settings.update(settings)
        if entries is not None:
            for item in entries:
                key = str(item.get("key") or "")
                if key:
                    self.cached_entry_etags[key] = str(item.get("etag") or "")
        if etag:
            self.cached_group_etag = etag


def test_group_facade_does_not_expose_set_settings_with_index_alias():
    assert not hasattr(GroupFacade(FakeClient(_aid(), [])), "set_settings_with_index")


@pytest.mark.asyncio
async def test_update_group_index_sends_expected_index_etag_and_signed_index():
    owner = _aid()
    old_index = _index(owner, "old")
    client = FakeClient(owner, [old_index])
    facade = GroupFacade(client)

    result = await facade.update_group_index(group_id="g-team.example.test", settings={"rules.content": "新群规"}, last_modified=2000)

    assert result["updated_keys"] == ["rules.content", "group.index"]
    set_call = [item for item in client.calls if item[0] == "group.set_settings"][0][1]
    assert set_call["expected_index_etag"] == parse_group_index(old_index["body"])["meta"]["etag"]
    assert set_call["settings"]["rules.content"] == "新群规"
    assert verify_group_index(set_call["settings"]["group.index"]["body"], owner).data["valid"] is True


@pytest.mark.asyncio
async def test_check_group_index_reports_observed_remote_meta_without_rpc():
    owner = _aid()
    client = FakeClient(owner, [])
    client.stale = True
    client.local_etag = '"sha256:local"'
    client.remote_meta = {"etag": '"sha256:remote"', "last_modified": 1234, "schema": GROUP_INDEX_SCHEMA}
    facade = GroupFacade(client)

    result = await facade.check_group_index(group_aid="g-team.example.test")

    assert result == {
        "group_aid": "g-team.example.test",
        "local_found": True,
        "remote_found": True,
        "local_etag": '"sha256:local"',
        "remote_etag": '"sha256:remote"',
        "in_sync": False,
        "needs_update": True,
        "last_modified": 1234,
        "status": 200,
        "cached": True,
    }
    assert client.calls == []


@pytest.mark.asyncio
async def test_get_group_index_fetches_remote_index_and_marks_fresh():
    owner = _aid()
    remote_index = _index(owner, "remote")
    client = FakeClient(owner, [remote_index])
    client.stale = True
    client.remote_settings = {"rules.content": "远端群规"}
    facade = GroupFacade(client)

    result = await facade.get_group_index(group_id="g-team.example.test")

    parsed = parse_group_index(remote_index["body"])
    assert result["group_id"] == "g-team.example.test"
    assert result["group_aid"] == "g-team.example.test"
    assert result["group_index"] == remote_index
    assert result["meta"] == parsed["meta"]
    assert result["entries"] == parsed["entries"]
    assert client.fresh_marks == [("g-team.example.test", parsed["meta"]["etag"])]
    assert client.cached_settings["rules.content"] == "远端群规"
    assert client.calls == [
        ("group.get_settings", {"group_id": "g-team.example.test", "keys": ["group.index"]}),
        ("group.get_settings", {"group_id": "g-team.example.test", "keys": ["rules.content"]}),
    ]


@pytest.mark.asyncio
async def test_get_group_index_rejects_tampered_remote_index_before_cache_update():
    owner = _aid()
    remote_index = _tamper_index(_index(owner, "remote"))
    client = FakeClient(owner, [remote_index])
    client.remote_settings = {"rules.content": "不应读取"}
    facade = GroupFacade(client)

    with pytest.raises(ValueError, match="group.index"):
        await facade.get_group_index(group_id="g-team.example.test")

    assert client.fresh_marks == []
    assert client.cached_settings == {}
    assert client.calls == [
        ("group.get_settings", {"group_id": "g-team.example.test", "keys": ["group.index"]}),
    ]


@pytest.mark.asyncio
async def test_get_rules_returns_cached_rules_even_when_group_index_is_stale():
    owner = _aid()
    client = FakeClient(owner, [])
    client.stale = True
    client.cached_settings = {
        "rules.content": "缓存群规",
        "rules.attachments": [{"uri": "groupfs://rules.pdf"}],
    }
    facade = GroupFacade(client)

    result = await facade.get_rules(group_id="g-team.example.test")

    assert result == {
        "group_id": "g-team.example.test",
        "rules": {
            "group_id": "g-team.example.test",
            "content": "缓存群规",
            "attachments": [{"uri": "groupfs://rules.pdf"}],
            "updated_by": "",
            "updated_at": 0,
        },
    }
    assert client.calls == []


@pytest.mark.asyncio
async def test_get_rules_fetches_settings_only_when_local_cache_is_missing():
    owner = _aid()
    client = FakeClient(owner, [])
    client.stale = True
    client.remote_settings = {
        "rules.content": "远端群规",
        "rules.attachments": [{"uri": "groupfs://rules.pdf"}],
    }
    facade = GroupFacade(client)

    result = await facade.get_rules(group_id="g-team.example.test")

    assert result["rules"]["content"] == "远端群规"
    assert result["rules"]["attachments"] == [{"uri": "groupfs://rules.pdf"}]
    assert client.calls == [
        ("group.get_settings", {"group_id": "g-team.example.test", "keys": ["rules.content", "rules.attachments"]}),
    ]
    assert client.fresh_marks == []
    assert client.cached_settings["rules.content"] == "远端群规"


@pytest.mark.asyncio
async def test_get_rules_caches_settings_under_canonical_and_requested_group_ids():
    owner = _aid()
    client = FakeClient(owner, [])
    client.remote_settings = {
        "rules.content": "远端群规",
        "rules.attachments": [],
    }
    facade = GroupFacade(client)

    await facade.get_rules(group_id="legacy.remote.example")

    assert client.cache_calls == ["g-team.example.test", "legacy.remote.example"]


@pytest.mark.asyncio
async def test_update_rules_refreshes_indexed_settings_cache_after_push():
    owner = _aid()
    old_index = _index(owner, "old")
    client = FakeClient(owner, [old_index])
    facade = GroupFacade(client)

    await facade.update_rules(group_id="g-team.example.test", content="新群规", last_modified=2000)

    assert client.cached_settings["rules.content"] == "新群规"
    assert client.cached_group_etag


@pytest.mark.asyncio
async def test_update_group_index_pulls_merges_and_pushes_with_cas():
    owner = _aid()
    old_index = _index(owner, "old")
    client = FakeClient(owner, [old_index])
    facade = GroupFacade(client)

    result = await facade.update_group_index(group_id="g-team.example.test", settings={"rules.content": "新群规"}, last_modified=2000)

    assert result["updated_keys"] == ["rules.content", "group.index"]
    set_call = [item for item in client.calls if item[0] == "group.set_settings"][0][1]
    assert set_call["expected_index_etag"] == parse_group_index(old_index["body"])["meta"]["etag"]
    assert set_call["settings"]["rules.content"] == "新群规"
    assert verify_group_index(set_call["settings"]["group.index"]["body"], owner).data["valid"] is True


@pytest.mark.asyncio
async def test_update_group_index_marks_pushed_index_fresh():
    owner = _aid()
    old_index = _index(owner, "old")
    client = FakeClient(owner, [old_index])
    client.stale = True
    facade = GroupFacade(client)

    await facade.update_group_index(group_id="g-team.example.test", settings={"rules.content": "新群规"}, last_modified=2000)

    set_call = [item[1] for item in client.calls if item[0] == "group.set_settings"][0]
    pushed_etag = parse_group_index(set_call["settings"]["group.index"]["body"])["meta"]["etag"]
    assert client.fresh_marks == [("g-team.example.test", pushed_etag)]
    assert client.stale is False


@pytest.mark.asyncio
async def test_update_group_index_reloads_index_and_retries_once_on_cas_conflict():
    owner = _aid()
    old_index = _index(owner, "old")
    newer_index = _index(owner, "newer")
    client = FakeClient(owner, [old_index, newer_index], fail_first_set=True)
    facade = GroupFacade(client)

    await facade.update_group_index(group_id="g-team.example.test", settings={"rules.content": "我的版本"}, last_modified=2000)

    set_calls = [item[1] for item in client.calls if item[0] == "group.set_settings"]
    assert len(set_calls) == 2
    assert set_calls[0]["expected_index_etag"] == parse_group_index(old_index["body"])["meta"]["etag"]
    assert set_calls[1]["expected_index_etag"] == parse_group_index(newer_index["body"])["meta"]["etag"]
    assert set_calls[1]["settings"]["rules.content"] == "我的版本"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "params", "expected_key"),
    [
        ("update_rules", {"content": "新群规"}, "rules.content"),
        ("update_announcement", {"content": "新公告"}, "announcement.content"),
        ("update_join_requirements", {"mode": "approval"}, "join.mode"),
    ],
)
async def test_indexed_settings_helpers_write_signed_group_index(method_name, params, expected_key):
    owner = _aid()
    old_index = _index(owner, "old")
    client = FakeClient(owner, [old_index])
    facade = GroupFacade(client)

    await getattr(facade, method_name)(group_id="g-team.example.test", last_modified=2000, **params)

    methods = [method for method, _params in client.calls]
    assert methods == ["group.get_settings", "group.set_settings"]
    set_call = client.calls[1][1]
    assert expected_key in set_call["settings"]
    assert "group.index" in set_call["settings"]
    assert set_call["expected_index_etag"] == parse_group_index(old_index["body"])["meta"]["etag"]
