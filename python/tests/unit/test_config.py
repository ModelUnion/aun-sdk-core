from pathlib import Path

from aun_core.config import AUNConfig, get_device_id


def test_from_dict_defaults(monkeypatch):
    monkeypatch.delenv("AUN_ENV", raising=False)
    monkeypatch.delenv("KITE_ENV", raising=False)
    cfg = AUNConfig.from_dict(None)
    assert isinstance(cfg.aun_path, Path)
    assert cfg.root_ca_path is None
    assert cfg.seed_password is None
    assert cfg.require_forward_secrecy is True  # 默认强制前向保密
    assert cfg.group_e2ee is True
    assert cfg.verify_ssl is True


def test_from_dict_custom(tmp_path):
    raw = {
        "aun_path": str(tmp_path / "my-aun"),
        "root_ca_path": "/ca/root.pem",
        "encryption_seed": "s3cret",
        "discovery_port": 20001,
        "group_e2ee": False,
        "epoch_auto_rotate_interval": 3600,
        "old_epoch_retention_seconds": 86400,
        "verify_ssl": False,
        "require_forward_secrecy": False,
        "replay_window_seconds": 600,
    }
    cfg = AUNConfig.from_dict(raw)
    assert cfg.aun_path == (tmp_path / "my-aun")
    assert cfg.root_ca_path == "/ca/root.pem"
    assert cfg.seed_password == "s3cret"
    assert cfg.discovery_port == 20001
    assert cfg.group_e2ee is True  # 必备能力，不可关闭
    assert cfg.epoch_auto_rotate_interval == 3600
    assert cfg.old_epoch_retention_seconds == 86400
    assert cfg.verify_ssl is False
    assert cfg.require_forward_secrecy is False
    assert cfg.replay_window_seconds == 600


def test_from_dict_supports_camel_case_aliases(tmp_path):
    cfg = AUNConfig.from_dict({
        "aunPath": str(tmp_path / "camel-aun"),
        "rootCaPath": "/ca/camel.pem",
        "encryptionSeed": "camel-seed",
        "discoveryPort": 21001,
        "groupE2EE": False,
        "epochAutoRotateInterval": 120,
        "oldEpochRetentionSeconds": 30,
        "verifySSL": False,
        "requireForwardSecrecy": False,
        "replayWindowSeconds": 42,
    })

    assert cfg.aun_path == (tmp_path / "camel-aun")
    assert cfg.root_ca_path == "/ca/camel.pem"
    assert cfg.seed_password == "camel-seed"
    assert cfg.discovery_port == 21001
    assert cfg.group_e2ee is True  # 必备能力，不可关闭
    assert cfg.epoch_auto_rotate_interval == 120
    assert cfg.old_epoch_retention_seconds == 30
    assert cfg.verify_ssl is False
    assert cfg.require_forward_secrecy is False
    assert cfg.replay_window_seconds == 42


def test_from_dict_ignores_unknown_keys():
    raw = {
        "aun_path": "/tmp/test",
        "gateway": "ws://localhost:20001/aun",
        "auto_reconnect": True,
    }
    cfg = AUNConfig.from_dict(raw)
    assert cfg.aun_path == Path("/tmp/test")
    # gateway 和 auto_reconnect 不在 config 中，应被忽略
    assert not hasattr(cfg, "gateway")
    assert not hasattr(cfg, "auto_reconnect")


def test_from_dict_ignores_delivery_mode_constructor_fields(tmp_path):
    cfg = AUNConfig.from_dict({
        "aun_path": str(tmp_path / "aun"),
        "slot_id": "slot-a",
        "delivery_mode": "queue",
        "queue_routing": "sender_affinity",
        "affinity_ttl_ms": 1200,
    })

    assert not hasattr(cfg, "slot_id")
    assert not hasattr(cfg, "delivery_mode")
    assert not hasattr(cfg, "queue_routing")
    assert not hasattr(cfg, "affinity_ttl_ms")


def test_from_dict_verify_ssl_follows_development_env(monkeypatch):
    monkeypatch.setenv("AUN_ENV", "development")
    monkeypatch.delenv("KITE_ENV", raising=False)

    cfg = AUNConfig.from_dict(None)

    assert cfg.verify_ssl is False


def test_from_dict_verify_ssl_follows_production_env(monkeypatch):
    monkeypatch.setenv("AUN_ENV", "production")
    monkeypatch.delenv("KITE_ENV", raising=False)

    cfg = AUNConfig.from_dict(None)

    assert cfg.verify_ssl is True


def test_get_device_id_loaded_from_dot_device_id(tmp_path):
    root = tmp_path / "aun"
    root.mkdir(parents=True)
    (root / ".device_id").write_text("device-001", encoding="utf-8")

    assert get_device_id(root) == "device-001"
