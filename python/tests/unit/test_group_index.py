import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from aun_core.aid import AID
from aun_core.group_index import (
    GroupIndexMetaCache,
    build_signed_group_index,
    compute_group_index_body_hash,
    group_index_signing_payload,
    parse_group_index,
    prepare_group_settings_with_index,
    verify_group_index,
)
from aun_core.v2.crypto.canonical import canonical_json


def _aid(name: str = "owner.example.test") -> AID:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    return AID._create(
        aid=name,
        aun_path="",
        cert_pem=cert_pem,
        cert_obj=cert,
        private_key_obj=key,
        cert_valid=True,
        private_key_valid=True,
        private_key_pem=private_pem,
    )


def test_group_index_body_hash_is_stable_for_dict_order():
    entries_a = [
        {"key": "rules.content", "source": "db", "etag": '"sha256:a"', "last_modified": 2},
        {"last_modified": 1, "etag": '"sha256:b"', "source": "db", "key": "announcement.content"},
    ]
    entries_b = [
        {"source": "db", "key": "announcement.content", "etag": '"sha256:b"', "last_modified": 1},
        {"last_modified": 2, "key": "rules.content", "source": "db", "etag": '"sha256:a"'},
    ]

    assert compute_group_index_body_hash(entries_a) == compute_group_index_body_hash(entries_b)


def test_group_index_body_hash_uses_v2_canonical_json_for_numbers():
    entries = [
        {
            "key": "numeric.content",
            "source": "db",
            "etag": '"sha256:numeric"',
            "last_modified": 1.0,
            "meta": {"ratio": 1e-7, "count": 1.0},
        },
    ]
    expected_body = canonical_json(entries[0]) + b"\n"
    expected_hash = "sha256:" + hashlib.sha256(expected_body).hexdigest()

    assert b"1e-" not in expected_body
    assert b"1.0" not in expected_body
    assert compute_group_index_body_hash(entries) == expected_hash


def test_signed_group_index_roundtrip_and_tamper_detection():
    owner = _aid()
    signed = build_signed_group_index(
        group_aid="g-team.example.test",
        entries=[
            {"key": "rules.content", "source": "db", "etag": '"sha256:a"', "last_modified": 2},
            {"key": "announcement.content", "source": "db", "etag": '"sha256:b"', "last_modified": 1},
        ],
        signer=owner,
        last_modified=1234,
    )

    parsed = parse_group_index(signed["body"])
    assert parsed["meta"]["group_aid"] == "g-team.example.test"
    assert parsed["meta"]["signed_by"] == owner.aid
    assert parsed["meta"]["sig_alg"] == "ECDSA-P256-SHA256"
    assert parsed["meta"]["signature"]
    assert verify_group_index(signed["body"], owner).data["valid"] is True

    tampered_lines = signed["body"].splitlines()
    tampered_entry = json.loads(tampered_lines[1])
    tampered_entry["etag"] = '"sha256:evil"'
    tampered_lines[1] = json.dumps(tampered_entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert verify_group_index("\n".join(tampered_lines) + "\n", owner).data["valid"] is False


def test_group_index_signing_payload_excludes_signature_field():
    owner = _aid()
    signed = build_signed_group_index(
        group_aid="g-team.example.test",
        entries=[{"key": "rules.content", "source": "db", "etag": '"sha256:a"', "last_modified": 2}],
        signer=owner,
        last_modified=1234,
    )
    parsed = parse_group_index(signed["body"])
    payload = group_index_signing_payload(parsed["meta"], parsed["entries"])

    assert b"signature" not in payload
    assert b"rules.content" in payload


def test_prepare_group_settings_with_index_preserves_settings_and_adds_signed_index():
    owner = _aid()
    settings = prepare_group_settings_with_index(
        group_aid="g-team.example.test",
        settings={"rules.content": "群规", "announcement.content": "公告"},
        signer=owner,
        last_modified=1234,
    )

    assert settings["rules.content"] == "群规"
    assert settings["announcement.content"] == "公告"
    assert "group.index" in settings
    assert verify_group_index(settings["group.index"]["body"], owner).data["valid"] is True


def test_group_index_meta_cache_tracks_stale_by_local_aid_and_group_aid():
    cache = GroupIndexMetaCache()

    cache.observe_rpc_meta(
        {"group_indexes": {"g-team.example.test": {"etag": '"v1"', "last_modified": 1, "schema": "aun.group.index.v1"}}},
        local_aid="alice.example.test",
    )
    assert cache.is_stale("alice.example.test", "g-team.example.test") is True


def test_group_index_meta_cache_persists_index_jsonl_and_cache_envelope(tmp_path):
    cache = GroupIndexMetaCache(tmp_path)
    entries = [{"key": "rules.content", "etag": '"entry-v1"'}]
    owner = _aid()
    signed = build_signed_group_index(
        group_aid="g-team.example.test",
        entries=[{"key": "rules.content", "source": "db", "etag": '"entry-v1"', "last_modified": 1}],
        signer=owner,
        last_modified=1,
    )

    cache.observe_rpc_meta(
        {"group_indexes": {"g-team.example.test": {"etag": '"v1"', "last_modified": 1, "schema": "aun.group.index.v1"}}},
        local_aid="alice.example.test",
    )
    cache.mark_fresh("alice.example.test", "g-team.example.test", etag='"v1"')
    cache.cache_settings(
        "alice.example.test",
        "g-team.example.test",
        {"rules.content": "缓存群规"},
        entries=entries,
        etag='"v1"',
        group_index=signed,
    )

    cache_dir = tmp_path / "AIDs" / "alice.example.test" / "groups" / "g-team.example.test"
    assert (cache_dir / "index.jsonl").read_text(encoding="utf-8") == signed["body"]
    assert (cache_dir / "group-index-cache.json").is_file()

    restored = GroupIndexMetaCache(tmp_path)
    assert restored.local_etag("alice.example.test", "g-team.example.test") == '"v1"'
    assert restored.remote_meta("alice.example.test", "g-team.example.test") == {
        "etag": '"v1"',
        "last_modified": 1,
        "schema": "aun.group.index.v1",
    }
    assert restored.cached_settings("alice.example.test", "g-team.example.test", ["rules.content"]) == {
        "rules.content": "缓存群规",
    }
    assert restored.cached_settings_by_entries(
        "alice.example.test",
        "g-team.example.test",
        ["rules.content"],
        entries,
    ) == ({"rules.content": "缓存群规"}, [])

    cache.mark_fresh("alice.example.test", "g-team.example.test", etag='"v1"')
    cache.observe_rpc_meta(
        {"group_indexes": {"g-team.example.test": {"etag": '"v1"', "last_modified": 1, "schema": "aun.group.index.v1"}}},
        local_aid="alice.example.test",
    )
    assert cache.is_stale("alice.example.test", "g-team.example.test") is False

    cache.observe_rpc_meta(
        {"group_indexes": {"g-team.example.test": {"etag": '"v2"', "last_modified": 2, "schema": "aun.group.index.v1"}}},
        local_aid="alice.example.test",
    )
    assert cache.is_stale("alice.example.test", "g-team.example.test") is True
