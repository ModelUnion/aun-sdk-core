import json

import pytest

from aun_core import GroupFacade


GROUP_FS_POSIX_METHODS = {
    "ls",
    "find",
    "stat",
    "lstat",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "df",
    "mount",
    "umount",
}

GROUP_FS_FORBIDDEN_METHODS = {
    "read",
    "write",
    "put",
    "get",
}


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        return {"method": method, "params": params or {}}


def test_group_facade_exposes_posix_group_fs_namespace():
    group = GroupFacade(_FakeClient())

    fs = group.fs

    for method in GROUP_FS_POSIX_METHODS:
        assert hasattr(fs, method)
    for method in GROUP_FS_FORBIDDEN_METHODS:
        assert not hasattr(fs, method)


@pytest.mark.asyncio
async def test_group_fs_posix_methods_call_group_fs_rpc():
    client = _FakeClient()
    fs = GroupFacade(client).fs

    await fs.ls("g-team.agentid.pub:/docs", page=1, size=20)
    await fs.find("g-team.agentid.pub:/docs", pattern="*.md")
    await fs.stat("g-team.agentid.pub:/docs/a.md")
    await fs.lstat("g-team.agentid.pub:/docs/link")
    await fs.mkdir("g-team.agentid.pub:/docs/new", parents=True)
    await fs.rm("g-team.agentid.pub:/docs/old.md", recursive=False, force=True)
    await fs.cp("g-team.agentid.pub:/docs/a.md", "g-team.agentid.pub:/docs/b.md", force=True)
    await fs.mv("g-team.agentid.pub:/docs/b.md", "g-team.agentid.pub:/docs/c.md")
    await fs.df("g-team.agentid.pub:/")
    await fs.mount("g-team.agentid.pub:/memberdata/alice.agentid.pub")
    await fs.umount("g-team.agentid.pub:/memberdata/alice.agentid.pub")

    assert [method for method, _params in client.calls] == [
        "group.fs.ls",
        "group.fs.find",
        "group.fs.stat",
        "group.fs.lstat",
        "group.fs.mkdir",
        "group.fs.rm",
        "group.fs.cp",
        "group.fs.mv",
        "group.fs.df",
        "group.fs.mount",
        "group.fs.umount",
    ]
    assert client.calls[0][1] == {"path": "g-team.agentid.pub:/docs", "page": 1, "size": 20}
    assert client.calls[4][1] == {"path": "g-team.agentid.pub:/docs/new", "parents": True}
    assert client.calls[6][1] == {
        "src": "g-team.agentid.pub:/docs/a.md",
        "dst": "g-team.agentid.pub:/docs/b.md",
        "force": True,
    }


@pytest.mark.asyncio
async def test_group_fs_does_not_map_memberdata_to_groupdata_in_sdk():
    client = _FakeClient()
    fs = GroupFacade(client).fs

    await fs.stat("g-team.agentid.pub:/memberdata/me/logs/a.md")

    assert client.calls == [
        ("group.fs.stat", {"path": "g-team.agentid.pub:/memberdata/me/logs/a.md"})
    ]
    assert "groupdata" not in json.dumps(client.calls, ensure_ascii=False)
