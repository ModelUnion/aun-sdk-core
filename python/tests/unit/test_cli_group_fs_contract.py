import re

import pytest
from typer.main import get_command
from typer.testing import CliRunner


GROUP_FS_COMMANDS = {
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

GROUP_FS_FORBIDDEN_COMMANDS = {
    "read",
    "write",
    "put",
    "get",
}


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def test_cli_group_fs_help_exposes_only_posix_commands():
    from aun_cli.main import app

    result = CliRunner().invoke(app, ["group", "fs", "--help"])

    assert result.exit_code == 0, result.output
    output = _strip_ansi(result.output).lower()
    for command in GROUP_FS_COMMANDS:
        assert command in output
    for command in GROUP_FS_FORBIDDEN_COMMANDS:
        assert f" {command} " not in output


def test_cli_group_help_recommends_fs_not_compat_resources():
    from aun_cli.main import app

    result = CliRunner().invoke(app, ["group", "--help"])

    assert result.exit_code == 0, result.output
    output = _strip_ansi(result.output).lower()
    assert " fs " in output
    assert "resources" not in output


def test_cli_group_fs_command_tree_contract():
    from aun_cli.main import app

    root = get_command(app)
    root_ctx = None
    group = root.get_command(root_ctx, "group")
    fs = group.get_command(root_ctx, "fs")

    assert fs is not None
    assert GROUP_FS_COMMANDS <= set(fs.commands)
    assert GROUP_FS_FORBIDDEN_COMMANDS.isdisjoint(set(fs.commands))
