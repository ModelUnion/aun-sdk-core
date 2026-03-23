from pathlib import Path

from aun_core.config import AUNConfig


def test_from_dict_defaults():
    cfg = AUNConfig.from_dict(None)
    assert isinstance(cfg.aun_path, Path)
    assert cfg.root_ca_path is None
    assert cfg.encryption_seed is None


def test_from_dict_custom(tmp_path):
    raw = {
        "aun_path": str(tmp_path / "my-aun"),
        "root_ca_path": "/ca/root.pem",
        "encryption_seed": "s3cret",
    }
    cfg = AUNConfig.from_dict(raw)
    assert cfg.aun_path == (tmp_path / "my-aun")
    assert cfg.root_ca_path == "/ca/root.pem"
    assert cfg.encryption_seed == "s3cret"


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
