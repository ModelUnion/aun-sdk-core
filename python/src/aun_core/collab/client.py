from __future__ import annotations

from typing import Any

from .errors import map_collab_error


def _drop_none(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if value is not None}


class SnapshotClient:
    def __init__(self, parent: "CollabClient") -> None:
        self._parent = parent

    async def create(self, collab_root: str, *, message: str = "", major: bool = False) -> dict[str, Any]:
        return await self._parent._call(
            "collab.snapshot.create",
            {"collab_root": collab_root, "message": message, "major": major},
        )

    async def list(self, collab_root: str) -> list[dict[str, Any]]:
        return await self._parent._call("collab.snapshot.list", {"collab_root": collab_root})

    async def show(self, collab_root: str, version: str) -> dict[str, Any]:
        return await self._parent._call("collab.snapshot.show", {"collab_root": collab_root, "version": version})

    async def diff(self, collab_root: str, version_a: str, version_b: str) -> dict[str, Any]:
        return await self._parent._call(
            "collab.snapshot.diff",
            {"collab_root": collab_root, "version_a": version_a, "version_b": version_b},
        )

    async def restore(self, collab_root: str, version: str, *, message: str = "") -> dict[str, Any]:
        return await self._parent._call(
            "collab.snapshot.restore",
            {"collab_root": collab_root, "version": version, "message": message},
        )

    async def rm(self, collab_root: str, version: str) -> dict[str, Any]:
        return await self._parent._call("collab.snapshot.rm", {"collab_root": collab_root, "version": version})

    async def prune(
        self,
        collab_root: str,
        *,
        before: int | str | None = None,
        keep_last: int | None = None,
    ) -> dict[str, Any]:
        return await self._parent._call(
            "collab.snapshot.prune",
            _drop_none({"collab_root": collab_root, "before": before, "keep_last": keep_last}),
        )


class CollabClient:
    def __init__(self, client: Any) -> None:
        self._client = client
        self.snapshot = SnapshotClient(self)

    async def _call(self, method: str, params: dict[str, Any] | None = None):
        try:
            return await self._client.call(method, params or {})
        except Exception as exc:
            mapped = map_collab_error(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    async def ls(self, collab_root: str) -> list[dict[str, Any]]:
        return await self._call("collab.ls", {"collab_root": collab_root})

    async def create(self, collab_root: str, doc: str, source: str) -> dict[str, Any]:
        return await self._call("collab.create", {"collab_root": collab_root, "doc": doc, "source": source})

    async def read(self, collab_root: str, doc: str) -> dict[str, Any]:
        return await self._call("collab.read", {"collab_root": collab_root, "doc": doc})

    async def submit(self, collab_root: str, doc: str, source: str, base_version: int, *, message: str = "") -> dict[str, Any]:
        return await self._call(
            "collab.submit",
            {"collab_root": collab_root, "doc": doc, "source": source, "base_version": base_version, "message": message},
        )

    async def merge(self, collab_root: str, doc: str, source: str, base_version: int) -> dict[str, Any]:
        return await self._call(
            "collab.merge",
            {"collab_root": collab_root, "doc": doc, "source": source, "base_version": base_version},
        )

    async def history(self, collab_root: str, doc: str) -> list[dict[str, Any]]:
        return await self._call("collab.history", {"collab_root": collab_root, "doc": doc})

    async def get(self, collab_root: str, doc: str, version: int) -> dict[str, Any]:
        return await self._call("collab.get", {"collab_root": collab_root, "doc": doc, "version": version})

    async def diff(self, collab_root: str, doc: str, v_from: int, v_to: int) -> dict[str, Any]:
        return await self._call(
            "collab.diff",
            {"collab_root": collab_root, "doc": doc, "from": v_from, "to": v_to},
        )

    async def export(self, collab_root: str, dest: str) -> dict[str, Any]:
        return await self._call("collab.export", {"collab_root": collab_root, "dest": dest})

    async def adopt(self, src: str, new_root: str) -> dict[str, Any]:
        return await self._call("collab.adopt", {"src": src, "new_root": new_root})

    async def prune(self, collab_root: str, doc: str) -> dict[str, Any]:
        return await self._call("collab.prune", {"collab_root": collab_root, "doc": doc})

    async def gc(self, collab_root: str, *, dry_run: bool = True) -> dict[str, Any]:
        return await self._call("collab.gc", {"collab_root": collab_root, "dry_run": dry_run})

    async def reflog(self, collab_root: str, doc: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
        params = {"collab_root": collab_root, "limit": limit}
        if doc:
            params["doc"] = doc
        return await self._call("collab.reflog", params)

    async def reset(self, collab_root: str, doc: str, version: int, *, message: str = "") -> dict[str, Any]:
        return await self._call("collab.reset", {"collab_root": collab_root, "doc": doc, "version": version, "message": message})

    async def discover(self, group_aid: str) -> list[dict[str, Any]]:
        return await self._call("collab.discover", {"group_aid": group_aid})

    async def unregister(self, group_aid: str, collab_root: str) -> dict[str, Any]:
        return await self._call("collab.unregister", {"group_aid": group_aid, "collab_root": collab_root})
