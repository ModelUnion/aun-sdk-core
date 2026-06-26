import hashlib
import json

import pytest

from aun_core.facades import GroupFacade
from aun_core.group_fs import GroupFSVFS, is_group_remote_path
from aun_core.storage.errors import ExistsError, StorageError


class _FakeLowLevel:
    def __init__(self, download_data: bytes = b"") -> None:
        self.puts = []
        self.gets = []
        self.download_data = download_data

    async def http_put(self, upload_url, data, headers=None, on_progress=None):
        payload = data.read() if hasattr(data, "read") else data
        self.puts.append((upload_url, bytes(payload), dict(headers or {})))
        if on_progress:
            on_progress(len(payload), len(payload))

    async def http_get(self, download_url, headers=None, on_progress=None):
        self.gets.append((download_url, dict(headers or {})))
        if on_progress:
            on_progress(len(self.download_data), len(self.download_data))
        return self.download_data


class _FakeClient:
    def __init__(self) -> None:
        self.calls = []
        self.responses = {}
        self.access_token = None
        self._identity = {}
        self._session_params = {}

    async def call(self, method, params=None):
        merged = params or {}
        self.calls.append((method, merged))
        response = self.responses.get(method)
        if callable(response):
            return response(merged)
        if response is not None:
            return response
        return {"method": method, "params": merged}


def test_group_remote_path_detection_keeps_windows_paths_local():
    assert is_group_remote_path("g-team.agentid.pub:/docs/a.md")
    assert is_group_remote_path("https://g-team.agentid.pub/docs/a.md")
    assert is_group_remote_path("http://g-team.agentid.pub/docs/a.md")

    assert not is_group_remote_path("D:/tmp/a.md")
    assert not is_group_remote_path("D:\\tmp\\a.md")
    assert not is_group_remote_path("local:/tmp/a.md")
    assert not is_group_remote_path("relative/a.md")
    assert not is_group_remote_path("/tmp/a.md")


@pytest.mark.asyncio
async def test_group_fs_role_acl_facade_maps_to_control_rpcs():
    client = _FakeClient()
    fs = GroupFSVFS(client)

    await fs.set_acl("g-team.agentid.pub:/archive", grantee_aid="role:admin", perms="rwx")
    await fs.remove_acl("g-team.agentid.pub:/archive", grantee_aid="role:admin")
    await fs.get_acl("g-team.agentid.pub:/archive")
    await fs.list_acl("g-team.agentid.pub:/archive", include_inherited=True)

    assert client.calls == [
        (
            "group.fs.set_acl",
            {
                "path": "g-team.agentid.pub:/archive",
                "grantee_aid": "role:admin",
                "perms": "rwx",
            },
        ),
        (
            "group.fs.remove_acl",
            {
                "path": "g-team.agentid.pub:/archive",
                "grantee_aid": "role:admin",
            },
        ),
        (
            "group.fs.get_acl",
            {
                "path": "g-team.agentid.pub:/archive",
            },
        ),
        (
            "group.fs.list_acl",
            {
                "path": "g-team.agentid.pub:/archive",
                "include_inherited": True,
            },
        ),
    ]


@pytest.mark.asyncio
async def test_cp_local_to_group_uses_upload_control_plane(tmp_path):
    local = tmp_path / "a.md"
    local.write_bytes(b"hello group")
    digest = hashlib.sha256(b"hello group").hexdigest()
    client = _FakeClient()
    client.responses = {
        "group.fs.check_upload": {"target_exists": False},
        "group.fs.create_upload_session": {
            "upload_url": "https://upload.example.test/session-1",
            "session_id": "s1",
            "headers": {"Content-Type": "text/markdown"},
        },
        "group.fs.complete_upload": {
            "type": "file",
            "path": "g-team.agentid.pub:/docs/a.md",
            "name": "a.md",
            "size": len(b"hello group"),
            "sha256": digest,
        },
    }
    lowlevel = _FakeLowLevel()
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    result = await fs.cp(str(local), "g-team.agentid.pub:/docs/a.md", force=True, parents=True)

    assert result["path"] == "g-team.agentid.pub:/docs/a.md"
    assert [method for method, _params in client.calls] == [
        "group.fs.check_upload",
        "group.fs.create_upload_session",
        "group.fs.complete_upload",
    ]
    assert client.calls[0][1] == {
        "path": "g-team.agentid.pub:/docs/a.md",
        "size_bytes": len(b"hello group"),
        "sha256": digest,
        "content_type": "text/markdown",
        "force": True,
        "parents": True,
    }
    assert client.calls[2][1]["session_id"] == "s1"
    assert client.calls[2][1]["sha256"] == digest
    assert lowlevel.puts == [
        ("https://upload.example.test/session-1", b"hello group", {"Content-Type": "text/markdown"})
    ]
    assert "group_data" not in json.dumps(client.calls, ensure_ascii=False)


@pytest.mark.asyncio
async def test_cp_local_prefix_is_stripped_for_upload_and_download(tmp_path):
    local = tmp_path / "prefixed.md"
    local.write_bytes(b"hello local prefix")
    digest = hashlib.sha256(b"hello local prefix").hexdigest()
    target_dir = tmp_path / "download"
    target_dir.mkdir()
    client = _FakeClient()
    client.responses = {
        "group.fs.check_upload": {"target_exists": False},
        "group.fs.create_upload_session": {
            "upload_url": "https://upload.example.test/local-prefix",
            "session_id": "s-local",
        },
        "group.fs.complete_upload": {"type": "file", "path": "g-team.agentid.pub:/docs/prefixed.md"},
        "group.fs.create_download_ticket": {
            "download_url": "https://download.example.test/local-prefix",
            "sha256": digest,
            "file_name": "prefixed.md",
        },
    }
    lowlevel = _FakeLowLevel(download_data=b"hello local prefix")
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp(f"local:{local}", "g-team.agentid.pub:/docs/prefixed.md")
    result = await fs.cp("g-team.agentid.pub:/docs/prefixed.md", f"local:{target_dir}")

    assert lowlevel.puts[0][1] == b"hello local prefix"
    assert (target_dir / "prefixed.md").read_bytes() == b"hello local prefix"
    assert result.local_path == str(target_dir / "prefixed.md")
    assert [method for method, _params in client.calls] == [
        "group.fs.check_upload",
        "group.fs.create_upload_session",
        "group.fs.complete_upload",
        "group.fs.create_download_ticket",
    ]


@pytest.mark.asyncio
async def test_cp_explicit_local_prefix_wins_over_shared_group_id(tmp_path):
    local = tmp_path / "active.md"
    local.write_bytes(b"active local prefix")
    digest = hashlib.sha256(b"active local prefix").hexdigest()
    target = tmp_path / "out.md"
    client = _FakeClient()
    client.responses = {
        "group.fs.check_upload": {"target_exists": False},
        "group.fs.create_upload_session": {
            "upload_url": "https://upload.example.test/active-prefix",
            "session_id": "s-active",
        },
        "group.fs.complete_upload": {"type": "file", "path": "/docs/active.md"},
        "group.fs.create_download_ticket": {
            "download_url": "https://download.example.test/active-prefix",
            "sha256": digest,
            "file_name": "active.md",
        },
    }
    lowlevel = _FakeLowLevel(download_data=b"active local prefix")
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp(f"local:{local}", "/docs/active.md", group_id="group.example.test/team")
    result = await fs.cp("/docs/active.md", f"local:{target}", group_id="group.example.test/team")

    assert lowlevel.puts[0][1] == b"active local prefix"
    assert target.read_bytes() == b"active local prefix"
    assert result.local_path == str(target)
    assert [method for method, _params in client.calls] == [
        "group.fs.check_upload",
        "group.fs.create_upload_session",
        "group.fs.complete_upload",
        "group.fs.create_download_ticket",
    ]
    assert client.calls[0][1]["group_id"] == "group.example.test/team"
    assert client.calls[3][1]["group_id"] == "group.example.test/team"


@pytest.mark.asyncio
async def test_cp_local_to_group_skips_http_put_on_instant_upload(tmp_path):
    local = tmp_path / "same.bin"
    local.write_bytes(b"same")
    digest = hashlib.sha256(b"same").hexdigest()
    client = _FakeClient()
    client.responses = {
        "group.fs.check_upload": {"instant": True, "session_id": "instant-1"},
        "group.fs.complete_upload": {"type": "file", "path": "g-team.agentid.pub:/same.bin"},
    }
    lowlevel = _FakeLowLevel()
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp(str(local), "g-team.agentid.pub:/same.bin")

    assert [method for method, _params in client.calls] == [
        "group.fs.check_upload",
        "group.fs.complete_upload",
    ]
    assert client.calls[1][1]["sha256"] == digest
    assert client.calls[1][1]["skip_blob"] is True
    assert lowlevel.puts == []


@pytest.mark.asyncio
async def test_cp_group_to_local_downloads_ticket_and_writes_file(tmp_path):
    data = b"downloaded"
    digest = hashlib.sha256(data).hexdigest()
    target = tmp_path / "out" / "a.md"
    client = _FakeClient()
    client.responses = {
        "group.fs.create_download_ticket": {
            "download_url": "https://download.example.test/ticket-1",
            "sha256": digest,
            "file_name": "a.md",
        }
    }
    lowlevel = _FakeLowLevel(download_data=data)
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    result = await fs.cp("g-team.agentid.pub:/docs/a.md", str(target))

    assert target.read_bytes() == data
    assert result.local_path == str(target)
    assert result.verified is True
    assert client.calls == [
        ("group.fs.create_download_ticket", {"path": "g-team.agentid.pub:/docs/a.md"})
    ]
    assert lowlevel.gets == [("https://download.example.test/ticket-1", {})]


@pytest.mark.asyncio
async def test_cp_group_to_local_sends_bearer_for_scoped_download_ticket(tmp_path):
    data = b"scoped download"
    target = tmp_path / "out.md"
    client = _FakeClient()
    client.access_token = "access-token-1"
    client.responses = {
        "group.fs.create_download_ticket": {
            "download_url": "https://storage.example.test/g-team/docs/a.md?t=share",
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_name": "a.md",
        }
    }
    lowlevel = _FakeLowLevel(download_data=data)
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp("g-team.agentid.pub:/docs/a.md", str(target))

    assert lowlevel.gets == [
        (
            "https://storage.example.test/g-team/docs/a.md?t=share",
            {"Authorization": "Bearer access-token-1"},
        )
    ]


@pytest.mark.asyncio
async def test_cp_memberdata_shared_file_sends_bearer(tmp_path):
    data = b"shared by another member"
    target = tmp_path / "shared.txt"
    client = _FakeClient()
    client.access_token = "viewer-access-token"
    client.responses = {
        "group.fs.create_download_ticket": {
            "download_url": "https://storage.example.test/member-source/group_data/g-team/shared.txt?t=share",
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_name": "shared.txt",
        }
    }
    lowlevel = _FakeLowLevel(download_data=data)
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp("g-team.agentid.pub:/memberdata/alice.agentid.pub/shared.txt", str(target))

    assert client.calls == [
        (
            "group.fs.create_download_ticket",
            {"path": "g-team.agentid.pub:/memberdata/alice.agentid.pub/shared.txt"},
        )
    ]
    assert lowlevel.gets == [
        (
            "https://storage.example.test/member-source/group_data/g-team/shared.txt?t=share",
            {"Authorization": "Bearer viewer-access-token"},
        )
    ]


@pytest.mark.asyncio
async def test_cp_group_to_local_uses_identity_access_token_fallback(tmp_path):
    data = b"identity token"
    target = tmp_path / "out.md"
    client = _FakeClient()
    client._identity = {"access_token": "identity-token-1"}
    client.responses = {
        "group.fs.create_download_ticket": {
            "download_url": "https://download.example.test/identity-token",
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_name": "a.md",
        }
    }
    lowlevel = _FakeLowLevel(download_data=data)
    fs = GroupFSVFS(client, lowlevel=lowlevel)

    await fs.cp("g-team.agentid.pub:/docs/a.md", str(target))

    assert lowlevel.gets == [
        (
            "https://download.example.test/identity-token",
            {"Authorization": "Bearer identity-token-1"},
        )
    ]


@pytest.mark.asyncio
async def test_cp_group_to_local_rejects_existing_target_without_force(tmp_path):
    target = tmp_path / "a.md"
    target.write_text("exists", encoding="utf-8")
    client = _FakeClient()
    fs = GroupFSVFS(client, lowlevel=_FakeLowLevel(download_data=b"new"))

    with pytest.raises(ExistsError) as excinfo:
        await fs.cp("g-team.agentid.pub:/docs/a.md", str(target))

    assert excinfo.value.code == "EEXIST"
    assert client.calls == []
    assert target.read_text(encoding="utf-8") == "exists"


@pytest.mark.asyncio
async def test_cp_group_to_local_detects_sha256_mismatch(tmp_path):
    target = tmp_path / "a.md"
    client = _FakeClient()
    client.responses = {
        "group.fs.create_download_ticket": {
            "download_url": "https://download.example.test/ticket-1",
            "sha256": "0" * 64,
        }
    }
    fs = GroupFSVFS(client, lowlevel=_FakeLowLevel(download_data=b"bad"))

    with pytest.raises(StorageError) as excinfo:
        await fs.cp("g-team.agentid.pub:/docs/a.md", str(target))

    assert excinfo.value.code == "ECONFLICT"
    assert not target.exists()


@pytest.mark.asyncio
async def test_cp_group_to_group_uses_single_rpc():
    client = _FakeClient()
    fs = GroupFSVFS(client)

    await fs.cp("g-team.agentid.pub:/a.md", "g-team.agentid.pub:/b.md", force=True, recursive=True)

    assert client.calls == [
        (
            "group.fs.cp",
            {
                "src": "g-team.agentid.pub:/a.md",
                "dst": "g-team.agentid.pub:/b.md",
                "force": True,
                "recursive": True,
            },
        )
    ]


@pytest.mark.asyncio
async def test_cp_local_to_local_is_rejected(tmp_path):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("x", encoding="utf-8")
    fs = GroupFSVFS(_FakeClient())

    with pytest.raises(StorageError) as excinfo:
        await fs.cp(str(src), str(dst))

    assert excinfo.value.code == "EINVAL"
