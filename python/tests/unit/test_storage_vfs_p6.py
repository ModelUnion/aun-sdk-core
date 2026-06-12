import pytest

from aun_core.storage import StorageLowLevel, StorageVFS


class _FakeClient:
    def __init__(self, responses):
        self.aid = "alice.agentid.pub"
        self.calls = []
        self._responses = responses

    async def call(self, method, params=None):
        params = params or {}
        self.calls.append((method, params))
        response = self._responses.get(method)
        if isinstance(response, BaseException):
            raise response
        if callable(response):
            return response(params)
        return response if response is not None else {}


@pytest.mark.asyncio
async def test_lowlevel_fs_mount_unmount_rpc_contracts():
    client = _FakeClient({
        "storage.fs.mount": {
            "type": "mount",
            "path": "memberdata/alice",
            "name": "alice",
            "owner_aid": "g-team.agentid.pub",
            "mount_source": "alice.agentid.pub:/group-data/g",
            "status": "pending",
        },
        "storage.fs.approve": {"approved": True, "type": "mount", "path": "memberdata/alice", "status": "active"},
        "storage.fs.reject": {"rejected": True, "type": "mount", "path": "memberdata/alice", "status": "rejected"},
        "storage.fs.unmount": {"unmounted": True},
    })
    lowlevel = StorageLowLevel(client)

    mounted = await lowlevel.fs_mount(
        owner="g-team.agentid.pub",
        bucket="default",
        mount_path="memberdata/alice",
        source_aid="alice.agentid.pub",
        source_path="group-data/g",
        readonly=False,
        expires_at=123456,
        require_approval=True,
    )
    approved = await lowlevel.fs_approve(owner="g-team.agentid.pub", bucket="default", mount_path="memberdata/alice")
    rejected = await lowlevel.fs_reject(owner="g-team.agentid.pub", bucket="default", mount_path="memberdata/alice")
    unmounted = await lowlevel.fs_unmount(owner="g-team.agentid.pub", bucket="default", mount_path="memberdata/alice")

    assert mounted["type"] == "mount"
    assert approved["approved"] is True
    assert rejected["rejected"] is True
    assert unmounted["unmounted"] is True
    assert client.calls == [
        (
            "storage.fs.mount",
            {
                "mount_path": "memberdata/alice",
                "source_aid": "alice.agentid.pub",
                "source_path": "group-data/g",
                "readonly": False,
                "expires_at": 123456,
                "require_approval": True,
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.approve",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.reject",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.unmount",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_lowlevel_share_meta_append_and_children_rpc_contracts():
    client = _FakeClient({
        "storage.create_share_link": {"share_id": "shr_1"},
        "storage.list_share_links": {"links": [{"share_id": "shr_1"}]},
        "storage.revoke_share_link": {"revoked": True},
        "storage.get_by_share": {"object_key": "docs/a.txt"},
        "storage.set_object_meta": {"object_key": "docs/a.txt", "metadata": {"k": "v"}},
        "storage.append_object": {"object_key": "docs/a.txt", "size_bytes": 5},
        "storage.list_children": {"items": [{"type": "file", "path": "docs/a.txt"}]},
    })
    lowlevel = StorageLowLevel(client)

    await lowlevel.create_share_link(
        owner="alice.agentid.pub",
        bucket="default",
        object_key="docs/a.txt",
        allowed_aids=["bob.agentid.pub"],
        expire_in_seconds=60,
        max_uses=2,
    )
    await lowlevel.list_share_links(owner="alice.agentid.pub", bucket="default", object_key="docs/a.txt")
    await lowlevel.revoke_share_link(share_id="shr_1")
    await lowlevel.get_by_share(share_id="shr_1")
    await lowlevel.set_object_meta(
        owner="alice.agentid.pub",
        bucket="default",
        object_key="docs/a.txt",
        metadata={"k": "v"},
        content_type="text/plain",
        merge=False,
        expected_version=3,
    )
    await lowlevel.append_object(
        owner="alice.agentid.pub",
        bucket="default",
        object_key="docs/a.txt",
        content=b"tail",
        content_type="text/plain",
        metadata={"append": True},
        expected_version=4,
        is_public=True,
    )
    await lowlevel.list_children(
        owner="alice.agentid.pub",
        bucket="default",
        path="docs",
        node_type="object",
        page=2,
        size=10,
        order_by="updated_at",
        order="desc",
        include_metadata=False,
        include_urls=False,
    )

    assert client.calls == [
        (
            "storage.create_share_link",
            {
                "object_key": "docs/a.txt",
                "allowed_aids": ["bob.agentid.pub"],
                "expire_in_seconds": 60,
                "max_uses": 2,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.list_share_links",
            {
                "object_key": "docs/a.txt",
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        ("storage.revoke_share_link", {"share_id": "shr_1"}),
        ("storage.get_by_share", {"share_id": "shr_1"}),
        (
            "storage.set_object_meta",
            {
                "object_key": "docs/a.txt",
                "metadata": {"k": "v"},
                "content_type": "text/plain",
                "merge": False,
                "expected_version": 3,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.append_object",
            {
                "object_key": "docs/a.txt",
                "content": "dGFpbA==",
                "content_type": "text/plain",
                "metadata": {"append": True},
                "expected_version": 4,
                "is_private": False,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.list_children",
            {
                "path": "docs",
                "type": "object",
                "page": 2,
                "size": 10,
                "order_by": "updated_at",
                "order": "desc",
                "include_metadata": False,
                "include_urls": False,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_vfs_mount_volume_uses_volume_id_branch():
    client = _FakeClient({
        "storage.fs.mount": {
            "type": "mount",
            "path": "mnt/vol-1",
            "name": "vol-1",
            "owner_aid": "alice.agentid.pub",
            "mount_source": "volume:vol-1",
        },
    })
    vfs = StorageVFS(client)

    node = await vfs.mount_volume("vol-1", "/mnt/vol-1", owner="alice.agentid.pub", readonly=True)

    assert node.type == "mount"
    assert client.calls == [
        (
            "storage.fs.mount",
            {
                "mount_path": "mnt/vol-1",
                "readonly": True,
                "require_approval": False,
                "volume_id": "vol-1",
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        )
    ]


@pytest.mark.asyncio
async def test_lowlevel_volume_lifecycle_and_membership_invalidation_rpc_contracts():
    client = _FakeClient({
        "storage.volume.create": {"volume_id": "vol-1", "status": "active"},
        "storage.volume.renew": {"volume_id": "vol-1", "expires_at": 999},
        "storage.volume.expire_due": {"expired": 1, "mounts_unavailable": 1},
        "storage.fs.invalidate_membership": {"invalidated": 1},
    })
    lowlevel = StorageLowLevel(client)

    created = await lowlevel.volume_create(
        owner="alice.agentid.pub",
        bucket="default",
        volume_id="vol-1",
        size_bytes=4096,
        mount_point="volumes/vol-1",
        expires_at=123,
    )
    renewed = await lowlevel.volume_renew(
        owner="alice.agentid.pub",
        volume_id="vol-1",
        expires_at=999,
    )
    expired = await lowlevel.volume_expire_due(owner="alice.agentid.pub", now=1000)
    invalidated = await lowlevel.fs_invalidate_membership(
        group_id="g-team.agentid.pub",
        group_owner_aid="owner.agentid.pub",
        member_aid="alice.agentid.pub",
        reason="left",
    )

    assert created["volume_id"] == "vol-1"
    assert renewed["expires_at"] == 999
    assert expired["expired"] == 1
    assert invalidated["invalidated"] == 1
    assert client.calls == [
        (
            "storage.volume.create",
            {
                "volume_id": "vol-1",
                "size_bytes": 4096,
                "mount_point": "volumes/vol-1",
                "expires_at": 123,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.volume.renew",
            {
                "volume_id": "vol-1",
                "expires_at": 999,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.volume.expire_due",
            {
                "now": 1000,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.invalidate_membership",
            {
                "group_id": "g-team.agentid.pub",
                "group_owner_aid": "owner.agentid.pub",
                "member_aid": "alice.agentid.pub",
                "reason": "left",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_vfs_mount_parses_remote_source_and_unmount_returns_remove_result():
    client = _FakeClient({
        "storage.fs.mount": {
            "mount": {
                "type": "mount",
                "path": "memberdata/alice",
                "name": "alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
                "mount_source": "alice.agentid.pub:/group-data/g",
            }
        },
        "storage.fs.approve": {"approved": True, "type": "mount", "path": "memberdata/alice", "status": "active"},
        "storage.fs.reject": {"rejected": True, "type": "mount", "path": "memberdata/alice", "status": "rejected"},
        "storage.fs.unmount": {"unmounted": True},
    })
    vfs = StorageVFS(client)

    node = await vfs.mount(
        "alice.agentid.pub:/group-data/g",
        "/memberdata/alice",
        owner="g-team.agentid.pub",
        readonly=True,
        require_approval=True,
    )
    approved = await vfs.approve_mount("/memberdata/alice", owner="g-team.agentid.pub")
    rejected = await vfs.reject_mount("/memberdata/alice", owner="g-team.agentid.pub")
    removed = await vfs.unmount("/memberdata/alice", owner="g-team.agentid.pub")

    assert node.type == "mount"
    assert node.path == "/memberdata/alice"
    assert node.mount_source == "alice.agentid.pub:/group-data/g"
    assert approved["approved"] is True
    assert rejected["rejected"] is True
    assert removed.path == "/memberdata/alice"
    assert removed.removed_count == 1
    assert client.calls == [
        (
            "storage.fs.mount",
            {
                "mount_path": "memberdata/alice",
                "source_aid": "alice.agentid.pub",
                "source_path": "group-data/g",
                "readonly": True,
                "require_approval": True,
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.approve",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.reject",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
        (
            "storage.fs.unmount",
            {
                "mount_path": "memberdata/alice",
                "owner_aid": "g-team.agentid.pub",
                "bucket": "default",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_vfs_mount_requires_remote_source_with_aid():
    client = _FakeClient({})
    vfs = StorageVFS(client)

    with pytest.raises(ValueError, match="source"):
        await vfs.mount("/group-data/g", "/memberdata/alice", owner="g-team.agentid.pub")

    assert client.calls == []
