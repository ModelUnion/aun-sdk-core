import pytest
from types import SimpleNamespace

from aun_core import GroupPendingOpsPartialFailure, GroupResourcesFacade


class _FakeClient:
    def __init__(self):
        self.calls = []
        self.results = []

    async def call(self, method, params=None):
        payload = params or {}
        self.calls.append((method, payload))
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return {"method": method, "params": payload}


@pytest.mark.asyncio
async def test_group_resources_low_level_group_storage_methods_map_to_rpc():
    client = _FakeClient()
    resources = GroupResourcesFacade(client)

    await resources.namespace_ready(group_id="g1", folder_ids={"announce": "f1"})
    await resources.confirm(group_id="g1", op_id="op1", confirm_key="upload")
    await resources.confirm_mount(group_id="g1", mount_id="m1")
    await resources.get_df(group_id="g1")

    assert [method for method, _params in client.calls] == [
        "group.resources.namespace_ready",
        "group.resources.confirm",
        "group.resources.confirm_mount",
        "group.resources.get_df",
    ]
    assert client.calls[0][1] == {"group_id": "g1", "folder_ids": {"announce": "f1"}}


@pytest.mark.asyncio
async def test_initialize_namespace_creates_baseline_dirs_and_confirms_ready():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"node_id": "fld-announce"},
        {"node_id": "fld-public"},
        {"node_id": "fld-archive"},
        {"node_id": "fld-memberdata"},
        {"type": "dir", "path": "public", "visibility": "public"},
        {"namespace_ready": True},
    ]
    resources = GroupResourcesFacade(client)

    result = await resources.initialize_namespace(group_id="g1", group_aid="g.example.test")

    assert result == {"namespace_ready": True}
    assert client.calls[:4] == [
        (
            "storage.fs.mkdir",
            {
                "owner_aid": "g.example.test",
                "bucket": "default",
                "path": "announce",
                "parents": True,
            },
        ),
        (
            "storage.fs.mkdir",
            {
                "owner_aid": "g.example.test",
                "bucket": "default",
                "path": "public",
                "parents": True,
            },
        ),
        (
            "storage.fs.mkdir",
            {
                "owner_aid": "g.example.test",
                "bucket": "default",
                "path": "archive",
                "parents": True,
            },
        ),
        (
            "storage.fs.mkdir",
            {
                "owner_aid": "g.example.test",
                "bucket": "default",
                "path": "memberdata",
                "parents": True,
            },
        ),
    ]
    assert client.calls[4] == (
        "storage.set_visibility",
        {
            "owner_aid": "g.example.test",
            "bucket": "default",
            "path": "public",
            "visibility": "public",
        },
    )
    assert client.calls[5] == (
        "group.resources.namespace_ready",
        {
            "group_id": "g1",
            "group_aid": "g.example.test",
            "folder_ids": {
                "announce": "fld-announce",
                "public": "fld-public",
                "archive": "fld-archive",
                "memberdata": "fld-memberdata",
            },
        },
    )


@pytest.mark.asyncio
async def test_initialize_namespace_reads_nested_node_folder_id_and_honors_empty_paths():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"node": {"folder_id": "fld-docs"}},
        {"namespace_ready": True},
        {"node_id": "fld-announce"},
        {"node_id": "fld-public"},
        {"node_id": "fld-archive"},
        {"node_id": "fld-memberdata"},
        {"type": "dir", "path": "public", "visibility": "public"},
        {"namespace_ready": True},
    ]
    resources = GroupResourcesFacade(client)

    nested = await resources.initialize_namespace(
        {"group_id": "g1", "group_aid": "g.example.test", "paths": ["docs"]}
    )
    empty = await resources.initialize_namespace(
        {"group_id": "g1", "group_aid": "g.example.test", "paths": ["", " / "]}
    )

    assert nested == {"namespace_ready": True}
    assert empty == {"namespace_ready": True}
    assert client.calls == [
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "docs", "parents": True},
        ),
        (
            "group.resources.namespace_ready",
            {"group_id": "g1", "group_aid": "g.example.test", "folder_ids": {"docs": "fld-docs"}},
        ),
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "announce", "parents": True},
        ),
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "public", "parents": True},
        ),
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "archive", "parents": True},
        ),
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "memberdata", "parents": True},
        ),
        (
            "storage.set_visibility",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "public", "visibility": "public"},
        ),
        (
            "group.resources.namespace_ready",
            {
                "group_id": "g1",
                "group_aid": "g.example.test",
                "folder_ids": {
                    "announce": "fld-announce",
                    "public": "fld-public",
                    "archive": "fld-archive",
                    "memberdata": "fld-memberdata",
                },
            },
        ),
    ]


@pytest.mark.asyncio
async def test_initialize_namespace_requires_aid_store_when_signer_differs():
    client = _FakeClient()
    client.aid = "owner.example.test"
    resources = GroupResourcesFacade(client)

    with pytest.raises(ValueError, match="requires aid_store"):
        await resources.initialize_namespace(group_id="g1", group_aid="g.example.test")

    assert client.calls == []


@pytest.mark.asyncio
async def test_initialize_namespace_with_aid_store_uses_signer_client(monkeypatch):
    from aun_core import client as client_module

    signer_instances = []

    class _SignerClient:
        def __init__(self, aid):
            self.aid = aid
            self.calls = []
            self.connected = False
            self.closed = False
            signer_instances.append(self)

        async def connect(self, opts=None):
            self.connected = True
            self.connect_opts = opts

        async def call(self, method, params=None):
            payload = dict(params or {})
            self.calls.append((method, payload))
            return {"node_id": f"fld-{payload['path']}"}

        async def close(self):
            self.closed = True

    class _Store:
        def __init__(self):
            self.loads = []

        def load(self, aid):
            self.loads.append(aid)
            return SimpleNamespace(ok=True, data={"aid": object()})

    monkeypatch.setattr(client_module, "AUNClient", _SignerClient)
    client = _FakeClient()
    client.results = [{"namespace_ready": True}]
    resources = GroupResourcesFacade(client)

    result = await resources.initialize_namespace(
        group_id="g1",
        group_aid="g.example.test",
        paths=["announce", "public"],
        aid_store=_Store(),
    )

    assert result == {"namespace_ready": True}
    assert len(signer_instances) == 1
    signer = signer_instances[0]
    assert signer.connected is True
    assert signer.closed is True
    assert signer.calls == [
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "announce", "parents": True},
        ),
        (
            "storage.fs.mkdir",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "public", "parents": True},
        ),
        (
            "storage.set_visibility",
            {"owner_aid": "g.example.test", "bucket": "default", "path": "public", "visibility": "public"},
        ),
    ]
    assert client.calls == [
        (
            "group.resources.namespace_ready",
            {
                "group_id": "g1",
                "group_aid": "g.example.test",
                "folder_ids": {"announce": "fld-announce", "public": "fld-public"},
            },
        )
    ]


@pytest.mark.asyncio
async def test_execute_pending_ops_runs_in_order_and_calls_confirm_rpc():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"session_id": "s1"},
        {"object_id": "o1", "status": "active"},
        {"confirmed": True},
    ]
    resources = GroupResourcesFacade(client)

    result = await resources.execute_pending_ops({
        "mode": "pending_ops",
        "group_id": "g1",
        "group_aid": "g.example.test",
        "op_id": "op1",
        "confirm_rpc": "group.resources.confirm",
        "confirm_params": {
            "group_id": "g1",
            "path": "announce/a.txt",
            "resource_type": "file",
        },
        "pending_ops": [
            {
                "rpc": "storage.create_upload_session",
                "params": {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
                "sign_as": "g.example.test",
                "confirm_key": "upload_session",
            },
            {
                "rpc": "storage.complete_upload",
                "params": {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
                "sign_as": "g.example.test",
                "confirm_key": "upload",
            },
        ],
    })

    assert result["confirmed"] == {"confirmed": True}
    assert result["storage_results"] == {
        "upload_session": {"session_id": "s1"},
        "upload": {"object_id": "o1", "status": "active"},
    }
    assert client.calls == [
        (
            "storage.create_upload_session",
            {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
        ),
        (
            "storage.complete_upload",
            {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
        ),
        (
            "group.resources.confirm",
            {
                "group_id": "g1",
                "path": "announce/a.txt",
                "resource_type": "file",
                "op_id": "op1",
                "storage_results": {
                    "upload_session": {"session_id": "s1"},
                    "upload": {"object_id": "o1", "status": "active"},
                },
                "op_results": [
                    {"session_id": "s1"},
                    {"object_id": "o1", "status": "active"},
                ],
                "storage_result": {"object_id": "o1", "status": "active"},
                "confirm_key": "upload",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_execute_pending_ops_rejects_unsupported_rpc_fields():
    client = _FakeClient()
    client.aid = "g.example.test"
    resources = GroupResourcesFacade(client)

    with pytest.raises(ValueError, match="unsupported pending rpc"):
        await resources.execute_pending_ops({
            "group_id": "g1",
            "group_aid": "g.example.test",
            "pending_ops": [{"rpc": "group.dissolve", "params": {}, "confirm_key": "bad"}],
        })

    with pytest.raises(ValueError, match="unsupported confirm rpc"):
        await resources.execute_pending_ops({
            "group_id": "g1",
            "group_aid": "g.example.test",
            "confirm_rpc": "group.dissolve",
            "pending_ops": [],
        })

    with pytest.raises(ValueError, match="unsupported compensation rpc"):
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "failure_policy": "compensate_successful_ops_before_confirm",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "pending_ops": [
                {
                    "rpc": "storage.fs.mkdir",
                    "params": {"owner_aid": "g.example.test", "path": "announce"},
                    "confirm_key": "mkdir",
                    "compensation": {"rpc": "group.dissolve", "params": {}, "confirm_key": "bad"},
                },
                {"rpc": "storage.set_acl", "params": {"owner_aid": "g.example.test", "path": "public"}, "confirm_key": "acl"},
            ],
        })

    with pytest.raises(ValueError, match="pending op missing rpc"):
        await resources.execute_pending_ops({
            "group_id": "g1",
            "group_aid": "g.example.test",
            "pending_ops": [{"params": {"owner_aid": "g.example.test"}, "confirm_key": "missing"}],
        })

    assert client.calls == []


@pytest.mark.asyncio
async def test_execute_pending_ops_index0_failure_rethrows_original_error_without_partial_wrapper():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [RuntimeError("first op failed")]
    resources = GroupResourcesFacade(client)

    with pytest.raises(RuntimeError, match="first op failed") as caught:
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "confirm_rpc": "group.resources.confirm",
            "pending_ops": [
                {
                    "rpc": "storage.fs.mkdir",
                    "params": {"owner_aid": "g.example.test", "path": "announce"},
                    "sign_as": "g.example.test",
                    "confirm_key": "mkdir",
                    "compensation": {
                        "rpc": "storage.fs.remove",
                        "params": {"owner_aid": "g.example.test", "path": "announce", "recursive": True},
                        "sign_as": "g.example.test",
                        "confirm_key": "remove:announce",
                    },
                },
            ],
        })

    assert not isinstance(caught.value, GroupPendingOpsPartialFailure)
    assert [method for method, _params in client.calls] == ["storage.fs.mkdir"]


@pytest.mark.asyncio
async def test_execute_pending_ops_does_not_confirm_after_partial_storage_failure():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"acl_id": "acl-announce"},
        RuntimeError("storage failed"),
    ]
    resources = GroupResourcesFacade(client)

    with pytest.raises(RuntimeError, match="storage failed"):
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "op_id": "acl-op1",
            "confirm_rpc": "group.resources.confirm",
            "confirm_params": {
                "group_id": "g1",
                "operation": "acl",
                "path": "announce",
                "acl_paths": ["announce", "public"],
            },
            "pending_ops": [
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "announce"},
                    "sign_as": "g.example.test",
                    "confirm_key": "acl:announce",
                },
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "public"},
                    "sign_as": "g.example.test",
                    "confirm_key": "acl:public",
                },
            ],
        })

    assert [method for method, _params in client.calls] == [
        "storage.set_acl",
        "storage.set_acl",
    ]


@pytest.mark.asyncio
async def test_execute_pending_ops_compensates_successful_ops_after_partial_failure():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"acl_id": "acl-announce"},
        RuntimeError("storage failed"),
        {"removed": True},
    ]
    resources = GroupResourcesFacade(client)

    with pytest.raises(GroupPendingOpsPartialFailure, match="storage failed") as caught:
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "failure_policy": "compensate_successful_ops_before_confirm",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "op_id": "acl-op1",
            "confirm_rpc": "group.resources.confirm",
            "pending_ops": [
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "announce", "grantee_aid": "admin.example.test", "perms": "rwx"},
                    "sign_as": "g.example.test",
                    "confirm_key": "acl:announce",
                    "compensation": {
                        "rpc": "storage.remove_acl",
                        "params": {"owner_aid": "g.example.test", "path": "announce", "grantee_aid": "admin.example.test"},
                        "sign_as": "g.example.test",
                        "confirm_key": "compensate_acl:announce",
                        "depends_on": "acl:announce",
                    },
                },
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "public", "grantee_aid": "admin.example.test", "perms": "rwx"},
                    "sign_as": "g.example.test",
                    "confirm_key": "acl:public",
                },
            ],
        })

    assert [method for method, _params in client.calls] == [
        "storage.set_acl",
        "storage.set_acl",
        "storage.remove_acl",
    ]
    assert caught.value.storage_results == {"acl:announce": {"acl_id": "acl-announce"}}
    assert caught.value.compensation_results["compensate_acl:announce"] == {"removed": True}
    assert caught.value.to_dict()["compensation_errors"] == []


@pytest.mark.asyncio
async def test_execute_pending_ops_records_compensation_errors_without_confirming():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"acl_id": "acl-announce"},
        RuntimeError("storage failed"),
        RuntimeError("compensation failed"),
    ]
    resources = GroupResourcesFacade(client)

    with pytest.raises(GroupPendingOpsPartialFailure, match="storage failed") as caught:
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "failure_policy": "compensate_successful_ops_before_confirm",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "op_id": "acl-op1",
            "confirm_rpc": "group.resources.confirm",
            "pending_ops": [
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "announce"},
                    "confirm_key": "acl:announce",
                    "compensation": {
                        "rpc": "storage.remove_acl",
                        "params": {"owner_aid": "g.example.test", "path": "announce"},
                        "confirm_key": "compensate_acl:announce",
                    },
                },
                {
                    "rpc": "storage.set_acl",
                    "params": {"owner_aid": "g.example.test", "path": "public"},
                    "confirm_key": "acl:public",
                },
            ],
        })

    assert [method for method, _params in client.calls] == [
        "storage.set_acl",
        "storage.set_acl",
        "storage.remove_acl",
    ]
    assert "group.resources.confirm" not in [method for method, _params in client.calls]
    assert caught.value.compensation_results == {}
    assert caught.value.compensation_errors == [{
        "confirm_key": "compensate_acl:announce",
        "rpc": "storage.remove_acl",
        "error": "compensation failed",
    }]
    assert caught.value.to_dict()["failed_index"] == 1


@pytest.mark.asyncio
async def test_execute_pending_ops_compensation_params_from_storage_results_prefix():
    client = _FakeClient()
    client.aid = "alice.example.test"
    client.results = [
        {"token": "source-token"},
        RuntimeError("mount failed"),
        {"revoked": True},
    ]
    resources = GroupResourcesFacade(client)

    with pytest.raises(GroupPendingOpsPartialFailure) as caught:
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "failure_policy": "compensate_successful_ops_before_confirm",
            "group_id": "g1",
            "group_aid": "team.example.test",
            "sign_as": "alice.example.test",
            "confirm_rpc": "group.resources.confirm_mount",
            "pending_ops": [
                {
                    "rpc": "storage.issue_token",
                    "params": {"owner_aid": "alice.example.test", "path": "team-data"},
                    "sign_as": "alice.example.test",
                    "confirm_key": "source_token",
                    "compensation": {
                        "rpc": "storage.revoke_token",
                        "params": {"owner_aid": "alice.example.test", "path": "team-data"},
                        "params_from_results": {"token": "storage_results.source_token.token"},
                        "confirm_key": "revoke_source_token",
                        "depends_on": "source_token",
                    },
                },
                {
                    "rpc": "storage.fs.mount",
                    "params": {
                        "owner_aid": "team.example.test",
                        "mount_path": "memberdata/alice.example.test",
                        "source_aid": "alice.example.test",
                        "source_path": "team-data",
                    },
                    "sign_as": "alice.example.test",
                    "confirm_key": "mount",
                },
            ],
        })

    assert client.calls[2] == (
        "storage.revoke_token",
        {"owner_aid": "alice.example.test", "path": "team-data", "token": "source-token"},
    )
    assert caught.value.compensation_results == {"revoke_source_token": {"revoked": True}}


@pytest.mark.asyncio
async def test_execute_pending_ops_requires_aid_store_when_signer_differs():
    client = _FakeClient()
    client.aid = "owner.example.test"
    resources = GroupResourcesFacade(client)

    with pytest.raises(ValueError, match="requires aid_store"):
        await resources.execute_pending_ops({
            "group_id": "g1",
            "group_aid": "g.example.test",
            "pending_ops": [
                {
                    "rpc": "storage.put_object",
                    "params": {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
                    "sign_as": "g.example.test",
                },
            ],
        })

    assert client.calls == []


@pytest.mark.asyncio
async def test_execute_pending_ops_with_aid_store_uses_signer_client(monkeypatch):
    from aun_core import client as client_module

    signer_instances = []

    class _SignerClient:
        def __init__(self, aid):
            self.aid = aid
            self.calls = []
            self.connected = False
            self.closed = False
            signer_instances.append(self)

        async def connect(self, opts=None):
            self.connected = True
            self.connect_opts = opts

        async def call(self, method, params=None):
            payload = dict(params or {})
            self.calls.append((method, payload))
            if method == "group.resources.confirm":
                return {"confirmed": True}
            return {"object_id": "o1", "status": "active"}

        async def close(self):
            self.closed = True

    class _Store:
        def __init__(self):
            self.loads = []

        def load(self, aid):
            self.loads.append(aid)
            return SimpleNamespace(ok=True, data={"aid": object()})

    monkeypatch.setattr(client_module, "AUNClient", _SignerClient)
    client = _FakeClient()
    client.results = [{"confirmed": True}]
    resources = GroupResourcesFacade(client)
    store = _Store()

    result = await resources.execute_pending_ops(
        {
            "mode": "pending_ops",
            "group_id": "g1",
            "group_aid": "g.example.test",
            "op_id": "op1",
            "confirm_params": {"group_id": "g1", "path": "announce/a.txt"},
            "pending_ops": [
                {
                    "rpc": "storage.put_object",
                    "params": {"owner_aid": "g.example.test", "object_key": "announce/a.txt"},
                    "sign_as": "g.example.test",
                    "confirm_key": "put",
                },
            ],
        },
        aid_store=store,
    )

    assert result["confirmed"] == {"confirmed": True}
    assert store.loads == ["g.example.test"]
    assert len(signer_instances) == 1
    signer = signer_instances[0]
    assert signer.connected is True
    assert signer.closed is True
    assert signer.calls == [
        ("storage.put_object", {"owner_aid": "g.example.test", "object_key": "announce/a.txt"}),
        (
            "group.resources.confirm",
            {
                "group_id": "g1",
                "path": "announce/a.txt",
                    "op_id": "op1",
                    "storage_results": {"put": {"object_id": "o1", "status": "active"}},
                    "op_results": [{"object_id": "o1", "status": "active"}],
                    "storage_result": {"object_id": "o1", "status": "active"},
                    "confirm_key": "put",
                },
        ),
    ]
    assert client.calls == []


@pytest.mark.asyncio
async def test_execute_pending_ops_preserves_acl_confirm_params():
    client = _FakeClient()
    client.aid = "g.example.test"
    client.results = [
        {"acl_id": "acl-announce"},
        {"acl_id": "acl-public"},
        {"confirmed": True},
    ]
    resources = GroupResourcesFacade(client)

    result = await resources.execute_pending_ops({
        "mode": "pending_ops",
        "group_id": "g1",
        "group_aid": "g.example.test",
        "op_id": "acl-op1",
        "confirm_rpc": "group.resources.confirm",
        "confirm_params": {
            "group_id": "g1",
            "operation": "acl",
            "path": "announce",
            "member_aid": "admin.example.test",
            "acl_action": "set_acl",
            "acl_paths": ["announce", "public"],
        },
        "pending_ops": [
            {
                "rpc": "storage.set_acl",
                "params": {"owner_aid": "g.example.test", "path": "announce", "grantee_aid": "admin.example.test", "perms": "rwx"},
                "sign_as": "g.example.test",
                "confirm_key": "acl:announce",
            },
            {
                "rpc": "storage.set_acl",
                "params": {"owner_aid": "g.example.test", "path": "public", "grantee_aid": "admin.example.test", "perms": "rwx"},
                "sign_as": "g.example.test",
                "confirm_key": "acl:public",
            },
        ],
    })

    assert result["confirmed"] == {"confirmed": True}
    assert client.calls[2] == (
        "group.resources.confirm",
        {
            "group_id": "g1",
            "operation": "acl",
            "path": "announce",
            "member_aid": "admin.example.test",
            "acl_action": "set_acl",
            "acl_paths": ["announce", "public"],
            "op_id": "acl-op1",
                "storage_results": {
                    "acl:announce": {"acl_id": "acl-announce"},
                    "acl:public": {"acl_id": "acl-public"},
                },
                "op_results": [
                    {"acl_id": "acl-announce"},
                    {"acl_id": "acl-public"},
                ],
                "storage_result": {"acl_id": "acl-public"},
                "confirm_key": "acl:public",
            },
    )


@pytest.mark.asyncio
async def test_execute_pending_ops_runs_member_mount_and_confirms_mount():
    client = _FakeClient()
    client.aid = "alice.example.test"
    client.results = [
        {"mount_id": "mnt-1", "status": "active"},
        {"confirmed": True},
    ]
    resources = GroupResourcesFacade(client)

    result = await resources.execute_pending_ops({
        "mode": "pending_ops",
        "group_id": "g1",
        "group_aid": "team.example.test",
        "sign_as": "alice.example.test",
        "confirm_rpc": "group.resources.confirm_mount",
        "confirm_params": {
            "group_id": "g1",
            "group_aid": "team.example.test",
            "mount_path": "memberdata/alice.example.test",
            "source_aid": "alice.example.test",
            "source_path": "team-data",
        },
        "pending_ops": [
            {
                "rpc": "storage.fs.mount",
                "params": {
                    "owner_aid": "team.example.test",
                    "mount_path": "memberdata/alice.example.test",
                    "source_aid": "alice.example.test",
                    "source_path": "team-data",
                },
                "sign_as": "alice.example.test",
                "confirm_key": "mount",
            },
        ],
    })

    assert result["confirmed"] == {"confirmed": True}
    assert client.calls == [
        (
            "storage.fs.mount",
            {
                "owner_aid": "team.example.test",
                "mount_path": "memberdata/alice.example.test",
                "source_aid": "alice.example.test",
                "source_path": "team-data",
            },
        ),
        (
            "group.resources.confirm_mount",
            {
                "group_id": "g1",
                "group_aid": "team.example.test",
                "mount_path": "memberdata/alice.example.test",
                "source_aid": "alice.example.test",
                "source_path": "team-data",
                "storage_results": {"mount": {"mount_id": "mnt-1", "status": "active"}},
                "op_results": [{"mount_id": "mnt-1", "status": "active"}],
                "storage_result": {"mount_id": "mnt-1", "status": "active"},
                "confirm_key": "mount",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_execute_pending_ops_does_not_confirm_mount_after_partial_failure():
    client = _FakeClient()
    client.aid = "alice.example.test"
    client.results = [
        {"token": "source-token"},
        RuntimeError("mount failed"),
    ]
    resources = GroupResourcesFacade(client)

    with pytest.raises(RuntimeError, match="mount failed"):
        await resources.execute_pending_ops({
            "mode": "pending_ops",
            "group_id": "g1",
            "group_aid": "team.example.test",
            "sign_as": "alice.example.test",
            "confirm_rpc": "group.resources.confirm_mount",
            "confirm_params": {
                "group_id": "g1",
                "group_aid": "team.example.test",
                "mount_path": "memberdata/alice.example.test",
                "source_aid": "alice.example.test",
                "source_path": "team-data",
            },
            "pending_ops": [
                {
                    "rpc": "storage.issue_token",
                    "params": {"owner_aid": "alice.example.test", "path": "team-data"},
                    "sign_as": "alice.example.test",
                    "confirm_key": "source_token",
                },
                {
                    "rpc": "storage.fs.mount",
                    "params": {
                        "owner_aid": "team.example.test",
                        "mount_path": "memberdata/alice.example.test",
                        "source_aid": "alice.example.test",
                        "source_path": "team-data",
                    },
                    "sign_as": "alice.example.test",
                    "confirm_key": "mount",
                },
            ],
        })

    assert [method for method, _params in client.calls] == [
        "storage.issue_token",
        "storage.fs.mount",
    ]
