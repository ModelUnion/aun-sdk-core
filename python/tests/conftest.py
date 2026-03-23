import pytest


@pytest.fixture
def tmp_aun_path(tmp_path):
    """提供临时 aun_path 目录。"""
    return tmp_path / "aun-test"
