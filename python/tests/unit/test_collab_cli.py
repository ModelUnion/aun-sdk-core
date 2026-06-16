import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aun_core.errors import NotFoundError as AUNNotFoundError, PermissionError as AUNPermissionError, ValidationError


class _FakeCollab:
    def __init__(self):
        self.calls = []
        self.snapshot = _FakeSnapshot(self)

    async def create(self, collab_root, doc, source):
        self.calls.append(("create", collab_root, doc, source))
        return {"version": 1, "current_target": f"{collab_root}/target"}

    async def submit(self, collab_root, doc, source, base_version, *, message=""):
        self.calls.append(("submit", collab_root, doc, source, base_version, message))
        return {"ok": True, "version": 2}

    async def read(self, collab_root, doc):
        self.calls.append(("read", collab_root, doc))
        return {"content": base64.b64encode(b"remote text").decode(), "version": 1}

    async def merge(self, collab_root, doc, source, base_version):
        self.calls.append(("merge", collab_root, doc, source, base_version))
        return {"content": base64.b64encode(b"merged").decode(), "conflicts": False}

    async def ls(self, collab_root):
        self.calls.append(("ls", collab_root))
        return [{"doc": "a.md", "version": 1, "author": "alice"}]

    async def history(self, collab_root, doc):
        self.calls.append(("history", collab_root, doc))
        return [{"version": 1, "author": "alice", "target": "t", "time": 1}]

    async def get(self, collab_root, doc, version):
        self.calls.append(("get", collab_root, doc, version))
        return {"content": base64.b64encode(b"v1").decode(), "version": version}

    async def diff(self, collab_root, doc, v_from, v_to):
        self.calls.append(("diff", collab_root, doc, v_from, v_to))
        return {"diff": "--- v1\n+++ v2\n"}

    async def export(self, collab_root, dest):
        self.calls.append(("export", collab_root, dest))
        return {"ok": True, "dest": dest}

    async def adopt(self, src, new_root):
        self.calls.append(("adopt", src, new_root))
        return {"ok": True, "new_root": new_root}

    async def prune(self, collab_root, doc):
        self.calls.append(("prune", collab_root, doc))
        return {"pruned": 1}

    async def reset(self, collab_root, doc, version, *, message=""):
        self.calls.append(("reset", collab_root, doc, version, message))
        return {"ok": True, "version": version + 1}

    async def gc(self, collab_root, *, dry_run=True):
        self.calls.append(("gc", collab_root, dry_run))
        return {"scanned": 3, "garbage": 1, "deleted": 0 if dry_run else 1}

    async def reflog(self, collab_root, doc=None, *, limit=100):
        self.calls.append(("reflog", collab_root, doc, limit))
        return [{"version": 2, "action": "submit"}]

    async def discover(self, group_aid):
        self.calls.append(("discover", group_aid))
        return [{"collab_root": f"{group_aid}:/proj", "authority_aid": group_aid}]

    async def unregister(self, group_aid, collab_root):
        self.calls.append(("unregister", group_aid, collab_root))
        return {"removed": 1}


class _FakeSnapshot:
    def __init__(self, parent):
        self._parent = parent

    async def create(self, collab_root, *, message="", major=False):
        self._parent.calls.append(("snapshot.create", collab_root, message, major))
        return {"version": "1.0.0", "message": message}

    async def list(self, collab_root):
        self._parent.calls.append(("snapshot.list", collab_root))
        return [{"version": "1.0.0", "created_at": 1, "message": "m"}]

    async def prune(self, collab_root, *, before=None, keep_last=None):
        self._parent.calls.append(("snapshot.prune", collab_root, before, keep_last))
        return {"pruned": 1}


class _FakeClient:
    def __init__(self):
        self.collab = _FakeCollab()


def _install_fake_session(monkeypatch, collab_commands, client):
    class _FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return client

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(collab_commands, "CLISession", _FakeSession)


def _invoke(args):
    from aun_cli.main import app

    return CliRunner().invoke(app, args)


def test_collab_create_converts_local_file_to_base64(monkeypatch, tmp_path):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)
    source = tmp_path / "draft.md"
    source.write_text("hello", encoding="utf-8")

    result = _invoke(["--json", "collab", "create", "alice.aid.com:/proj", "draft.md", str(source)])

    assert result.exit_code == 0, result.output
    call = client.collab.calls[0]
    assert call[:3] == ("create", "alice.aid.com:/proj", "draft.md")
    assert base64.b64decode(call[3]).decode() == "hello"


def test_collab_submit_keeps_aid_path_source(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    result = _invoke([
        "--json",
        "collab",
        "submit",
        "alice.aid.com:/proj",
        "draft.md",
        "alice.aid.com:/tmp/draft.md",
        "--base-version",
        "2",
    ])

    assert result.exit_code == 0, result.output
    assert client.collab.calls == [
        ("submit", "alice.aid.com:/proj", "draft.md", "alice.aid.com:/tmp/draft.md", 2, "")
    ]


def test_collab_read_and_merge_output_files(monkeypatch, tmp_path):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)
    read_out = tmp_path / "read.md"
    merge_out = tmp_path / "merge.md"

    read = _invoke(["collab", "read", "alice.aid.com:/proj", "draft.md", "-o", str(read_out)])
    merge = _invoke([
        "collab",
        "merge",
        "alice.aid.com:/proj",
        "draft.md",
        "INLINE",
        "--base-version",
        "1",
        "-o",
        str(merge_out),
    ])

    assert read.exit_code == 0, read.output
    assert merge.exit_code == 0, merge.output
    assert read_out.read_text(encoding="utf-8") == "remote text"
    assert merge_out.read_text(encoding="utf-8") == "merged"


def test_collab_submit_conflict_exit_code_and_hint(monkeypatch):
    from aun_cli.commands import collab as collab_commands
    from aun_core.collab import CollabConflictError

    class ConflictCollab(_FakeCollab):
        async def submit(self, collab_root, doc, source, base_version, *, message=""):
            raise CollabConflictError(
                "conflict",
                current_version=3,
                current_target="alice.aid.com:/proj/current",
                hint="run merge",
            )

    client = _FakeClient()
    client.collab = ConflictCollab()
    _install_fake_session(monkeypatch, collab_commands, client)

    result = _invoke([
        "collab",
        "submit",
        "alice.aid.com:/proj",
        "draft.md",
        "INLINE",
        "--base-version",
        "1",
    ])

    assert result.exit_code == 2
    assert "run merge" in result.stderr


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(AUNPermissionError("forbidden", code=-32004), id="permission"),
        pytest.param(AUNNotFoundError("missing", code=-32008), id="not_found"),
        pytest.param(ValidationError("bad args", code=-32602), id="validation"),
    ],
)
def test_collab_user_errors_exit_code_3(monkeypatch, exc):
    from aun_cli.commands import collab as collab_commands

    class FailingCollab(_FakeCollab):
        async def ls(self, collab_root):
            raise exc

    client = _FakeClient()
    client.collab = FailingCollab()
    _install_fake_session(monkeypatch, collab_commands, client)

    result = _invoke(["collab", "ls", "alice.aid.com:/proj"])

    assert result.exit_code == 3


def test_collab_snapshot_and_discover_commands(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    snap = _invoke(["--json", "collab", "snapshot", "create", "alice.aid.com:/proj", "--message", "m"])
    discover = _invoke(["--json", "collab", "discover", "g-team.aid.com"])

    assert snap.exit_code == 0, snap.output
    assert discover.exit_code == 0, discover.output
    assert client.collab.calls == [
        ("snapshot.create", "alice.aid.com:/proj", "m", False),
        ("discover", "g-team.aid.com"),
    ]
    assert json.loads(discover.output)[0]["collab_root"] == "g-team.aid.com:/proj"


def test_collab_submit_message_and_maintenance_commands(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    submit = _invoke([
        "--json", "collab", "submit",
        "alice.aid.com:/proj", "draft.md", "INLINE",
        "--base-version", "2", "--message", "edit",
    ])
    reset = _invoke([
        "--json", "collab", "reset",
        "alice.aid.com:/proj", "draft.md",
        "--version", "1", "--message", "rollback",
    ])
    gc = _invoke(["--json", "collab", "gc", "alice.aid.com:/proj", "--apply"])
    reflog = _invoke(["--json", "collab", "reflog", "alice.aid.com:/proj", "draft.md", "--limit", "5"])

    for result in [submit, reset, gc, reflog]:
        assert result.exit_code == 0, result.output

    submit_source = client.collab.calls[0][3]
    assert base64.b64decode(submit_source).decode() == "INLINE"
    assert client.collab.calls == [
        ("submit", "alice.aid.com:/proj", "draft.md", submit_source, 2, "edit"),
        ("reset", "alice.aid.com:/proj", "draft.md", 1, "rollback"),
        ("gc", "alice.aid.com:/proj", False),
        ("reflog", "alice.aid.com:/proj", "draft.md", 5),
    ]
