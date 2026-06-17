from __future__ import annotations

from typing import Any

from .errors import map_collab_error


def _drop_none(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if value is not None}


class TagClient:
    def __init__(self, parent: "CollabClient") -> None:
        self._parent = parent

    async def create(self, collab_root: str, *, message: str = "", major: bool = False) -> dict[str, Any]:
        return await self._parent._call(
            "collab.tag.create",
            {"collab_root": collab_root, "message": message, "major": major},
        )

    async def list(self, collab_root: str) -> list[dict[str, Any]]:
        return await self._parent._call("collab.tag.list", {"collab_root": collab_root})

    async def show(self, collab_root: str, version: str) -> dict[str, Any]:
        return await self._parent._call("collab.tag.show", {"collab_root": collab_root, "version": version})

    async def diff(self, collab_root: str, version_a: str, version_b: str) -> dict[str, Any]:
        return await self._parent._call(
            "collab.tag.diff",
            {"collab_root": collab_root, "version_a": version_a, "version_b": version_b},
        )

    async def restore(self, collab_root: str, version: str, *, message: str = "") -> dict[str, Any]:
        return await self._parent._call(
            "collab.tag.restore",
            {"collab_root": collab_root, "version": version, "message": message},
        )

    async def rm(self, collab_root: str, version: str) -> dict[str, Any]:
        return await self._parent._call("collab.tag.rm", {"collab_root": collab_root, "version": version})

    async def prune(
        self,
        collab_root: str,
        *,
        before: int | str | None = None,
        keep_last: int | None = None,
    ) -> dict[str, Any]:
        return await self._parent._call(
            "collab.tag.prune",
            _drop_none({"collab_root": collab_root, "before": before, "keep_last": keep_last}),
        )

# APPEND_MARKER


class CollabClient:
    def __init__(self, client: Any) -> None:
        self._client = client
        self.tag = TagClient(self)

    async def _call(self, method: str, params: dict[str, Any] | None = None):
        try:
            return await self._client.call(method, params or {})
        except Exception as exc:
            mapped = map_collab_error(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    async def ls_files(self, collab_root: str) -> list[dict[str, Any]]:
        return await self._call("collab.ls-files", {"collab_root": collab_root})

    async def create(self, collab_root: str, doc: str, source: str) -> dict[str, Any]:
        return await self._call("collab.create", {"collab_root": collab_root, "doc": doc, "source": source})

    async def show(self, collab_root: str, doc: str, rev: int | None = None) -> dict[str, Any]:
        params = {"collab_root": collab_root, "doc": doc}
        if rev is not None:
            params["rev"] = rev
        return await self._call("collab.show", params)

    async def commit(self, collab_root: str, doc: str, source: str, onto: int, *, message: str = "") -> dict[str, Any]:
        return await self._call(
            "collab.commit",
            {"collab_root": collab_root, "doc": doc, "source": source, "onto": onto, "message": message},
        )

    async def merge(self, collab_root: str, doc: str, source: str, onto: int) -> dict[str, Any]:
        return await self._call(
            "collab.merge",
            {"collab_root": collab_root, "doc": doc, "source": source, "onto": onto},
        )

    async def log(self, collab_root: str, doc: str) -> list[dict[str, Any]]:
        return await self._call("collab.log", {"collab_root": collab_root, "doc": doc})

    async def diff(self, collab_root: str, doc: str, v_from: int, v_to: int) -> dict[str, Any]:
        return await self._call(
            "collab.diff",
            {"collab_root": collab_root, "doc": doc, "from": v_from, "to": v_to},
        )

    async def clone(self, src: str, dest: str, *, reroot: bool = False) -> dict[str, Any]:
        return await self._call("collab.clone", {"src": src, "dest": dest, "reroot": reroot})

    async def prune(self, collab_root: str, doc: str) -> dict[str, Any]:
        return await self._call("collab.prune", {"collab_root": collab_root, "doc": doc})

    async def gc(self, collab_root: str, *, dry_run: bool = True) -> dict[str, Any]:
        return await self._call("collab.gc", {"collab_root": collab_root, "dry_run": dry_run})

    async def reflog(self, collab_root: str, doc: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
        params = {"collab_root": collab_root, "limit": limit}
        if doc:
            params["doc"] = doc
        return await self._call("collab.reflog", params)

    async def revert(self, collab_root: str, doc: str, rev: int, *, message: str = "") -> dict[str, Any]:
        return await self._call("collab.revert", {"collab_root": collab_root, "doc": doc, "rev": rev, "message": message})

    async def ls_remote(self, group_aid: str) -> list[dict[str, Any]]:
        return await self._call("collab.ls-remote", {"group_aid": group_aid})

    async def unregister(self, group_aid: str, collab_root: str) -> dict[str, Any]:
        return await self._call("collab.unregister", {"group_aid": group_aid, "collab_root": collab_root})
