import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aun_core.errors import NotFoundError as AUNNotFoundError, PermissionError as AUNPermissionError, ValidationError


class _FakeCollab:
    def __init__(self):
        self.calls = []
        self.tag = _FakeTag(self)

    async def create(self, collab_root, doc, source):
        self.calls.append(("create", collab_root, doc, source))
        return {"version": 1, "current_target": f"{collab_root}/target"}

    async def commit(self, collab_root, doc, source, onto, *, message=""):
        self.calls.append(("commit", collab_root, doc, source, onto, message))
        return {"ok": True, "version": 2}

    async def show(self, collab_root, doc, rev=None):
        self.calls.append(("show", collab_root, doc, rev))
        return {"content": base64.b64encode(b"remote text").decode(), "version": rev or 1}

    async def merge(self, collab_root, doc, source, onto):
        self.calls.append(("merge", collab_root, doc, source, onto))
        return {"content": base64.b64encode(b"merged").decode(), "conflicts": False}

    async def ls_files(self, collab_root):
        self.calls.append(("ls_files", collab_root))
        return [{"doc": "a.md", "version": 1, "author": "alice"}]

    async def log(self, collab_root, doc):
        self.calls.append(("log", collab_root, doc))
        return [{"version": 1, "author": "alice", "target": "t", "time": 1}]

    async def diff(self, collab_root, doc, v_from, v_to):
        self.calls.append(("diff", collab_root, doc, v_from, v_to))
        return {"diff": "--- v1\n+++ v2\n"}

    async def clone(self, src, dest, *, reroot=False):
        self.calls.append(("clone", src, dest, reroot))
        return {"ok": True, "dest": dest, "new_root": dest}

    async def prune(self, collab_root, doc):
        self.calls.append(("prune", collab_root, doc))
        return {"pruned": 1}

    async def revert(self, collab_root, doc, rev, *, message=""):
        self.calls.append(("revert", collab_root, doc, rev, message))
        return {"ok": True, "version": rev + 1}

    async def gc(self, collab_root, *, dry_run=True):
        self.calls.append(("gc", collab_root, dry_run))
        return {"scanned": 3, "garbage": 1, "deleted": 0 if dry_run else 1}

    async def reflog(self, collab_root, doc=None, *, limit=100):
        self.calls.append(("reflog", collab_root, doc, limit))
        return [{"version": 2, "action": "commit"}]

    async def ls_remote(self, group_aid):
        self.calls.append(("ls_remote", group_aid))
        return [{"collab_root": f"{group_aid}:/proj", "authority_aid": group_aid}]

    async def unregister(self, group_aid, collab_root):
        self.calls.append(("unregister", group_aid, collab_root))
        return {"removed": 1}


class _FakeTag:
    def __init__(self, parent):
        self._parent = parent

    async def create(self, collab_root, *, message="", major=False):
        self._parent.calls.append(("tag.create", collab_root, message, major))
        return {"version": "1.0.0", "message": message}

    async def list(self, collab_root):
        self._parent.calls.append(("tag.list", collab_root))
        return [{"version": "1.0.0", "created_at": 1, "message": "m"}]

    async def prune(self, collab_root, *, before=None, keep_last=None):
        self._parent.calls.append(("tag.prune", collab_root, before, keep_last))
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


def test_collab_commit_keeps_aid_path_source(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    result = _invoke([
        "--json",
        "collab",
        "commit",
        "alice.aid.com:/proj",
        "draft.md",
        "alice.aid.com:/tmp/draft.md",
        "--onto",
        "2",
    ])

    assert result.exit_code == 0, result.output
    assert client.collab.calls == [
        ("commit", "alice.aid.com:/proj", "draft.md", "alice.aid.com:/tmp/draft.md", 2, "")
    ]


def test_collab_show_and_merge_output_files(monkeypatch, tmp_path):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)
    show_out = tmp_path / "show.md"
    merge_out = tmp_path / "merge.md"

    show = _invoke(["collab", "show", "alice.aid.com:/proj", "draft.md", "-o", str(show_out)])
    merge = _invoke([
        "collab",
        "merge",
        "alice.aid.com:/proj",
        "draft.md",
        "INLINE",
        "--onto",
        "1",
        "-o",
        str(merge_out),
    ])

    assert show.exit_code == 0, show.output
    assert merge.exit_code == 0, merge.output
    assert show_out.read_text(encoding="utf-8") == "remote text"
    assert merge_out.read_text(encoding="utf-8") == "merged"


def test_collab_commit_conflict_exit_code_and_hint(monkeypatch):
    from aun_cli.commands import collab as collab_commands
    from aun_core.collab import CollabConflictError

    class ConflictCollab(_FakeCollab):
        async def commit(self, collab_root, doc, source, onto, *, message=""):
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
        "commit",
        "alice.aid.com:/proj",
        "draft.md",
        "INLINE",
        "--onto",
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
        async def ls_files(self, collab_root):
            raise exc

    client = _FakeClient()
    client.collab = FailingCollab()
    _install_fake_session(monkeypatch, collab_commands, client)

    result = _invoke(["collab", "ls-files", "alice.aid.com:/proj"])

    assert result.exit_code == 3


def test_collab_tag_and_ls_remote_commands(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    snap = _invoke(["--json", "collab", "tag", "create", "alice.aid.com:/proj", "--message", "m"])
    ls_remote = _invoke(["--json", "collab", "ls-remote", "g-team.aid.com"])

    assert snap.exit_code == 0, snap.output
    assert ls_remote.exit_code == 0, ls_remote.output
    assert client.collab.calls == [
        ("tag.create", "alice.aid.com:/proj", "m", False),
        ("ls_remote", "g-team.aid.com"),
    ]
    assert json.loads(ls_remote.output)[0]["collab_root"] == "g-team.aid.com:/proj"


def test_collab_commit_message_and_maintenance_commands(monkeypatch):
    from aun_cli.commands import collab as collab_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, collab_commands, client)

    commit = _invoke([
        "--json", "collab", "commit",
        "alice.aid.com:/proj", "draft.md", "INLINE",
        "--onto", "2", "--message", "edit",
    ])
    revert = _invoke([
        "--json", "collab", "revert",
        "alice.aid.com:/proj", "draft.md",
        "--rev", "1", "--message", "rollback",
    ])
    gc = _invoke(["--json", "collab", "gc", "alice.aid.com:/proj", "--apply"])
    reflog = _invoke(["--json", "collab", "reflog", "alice.aid.com:/proj", "draft.md", "--limit", "5"])

    for result in [commit, revert, gc, reflog]:
        assert result.exit_code == 0, result.output

    commit_source = client.collab.calls[0][3]
    assert base64.b64decode(commit_source).decode() == "INLINE"
    assert client.collab.calls == [
        ("commit", "alice.aid.com:/proj", "draft.md", commit_source, 2, "edit"),
        ("revert", "alice.aid.com:/proj", "draft.md", 1, "rollback"),
        ("gc", "alice.aid.com:/proj", False),
        ("reflog", "alice.aid.com:/proj", "draft.md", 5),
    ]
