from __future__ import annotations

import hashlib
import mimetypes
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

from .storage.errors import ExistsError, IsADirectoryError, StorageError, map_storage_error
from .storage.lowlevel import StorageLowLevel
from .storage.types import DownloadResult


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_GROUP_REF_RE = re.compile(r"^[^:/\\][^:]*:/")
_LOCAL_PREFIX = "local:"


def _is_explicit_local_path(value: str) -> bool:
    return str(value or "").strip().lower().startswith(_LOCAL_PREFIX)


def _strip_local_path_prefix(value: str) -> str:
    text = str(value or "").strip()
    return text[len(_LOCAL_PREFIX):] if _is_explicit_local_path(text) else text


def _is_group_remote_copy_path(value: str, *group_hints: Any) -> bool:
    if _is_explicit_local_path(value):
        return False
    return is_group_remote_path(value) or any(bool(hint) for hint in group_hints)


def is_group_remote_path(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if _is_explicit_local_path(text):
        return False
    if _WINDOWS_DRIVE_RE.match(text):
        return False
    if text.startswith(("http://", "https://")):
        return True
    return bool(_GROUP_REF_RE.match(text))


class GroupFSVFS:
    def __init__(self, client: Any, *, lowlevel: StorageLowLevel | None = None) -> None:
        self._client = client
        self.lowlevel = lowlevel or StorageLowLevel(client)

    def _params(self, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update(kwargs)
        self._apply_signing_identity(merged)
        return {key: value for key, value in merged.items() if value is not None}

    def _apply_signing_identity(self, params: dict[str, Any]) -> None:
        sign_as = str(params.pop("sign_as", None) or params.pop("signAs", None) or "").strip()
        aid_store = params.pop("aid_store", None) or params.pop("aidStore", None)
        if not sign_as:
            return
        current = getattr(self._client, "current_aid", None)
        current_aid = (
            getattr(current, "aid", None)
            or getattr(self._client, "aid", None)
            or getattr(self._client, "_aid", None)
        )
        if str(current_aid or "").strip().lower() == sign_as.lower():
            return
        store = aid_store or getattr(self._client, "_aid_store", None)
        if store is None:
            raise ValueError(f"group.fs operation requires aid_store to sign as {sign_as}")
        loaded = store.load(sign_as)
        if not getattr(loaded, "ok", False) or not getattr(loaded, "data", None):
            error = getattr(loaded, "error", None)
            message = getattr(error, "message", None) or f"signer identity not found: {sign_as}"
            raise ValueError(message)
        data = loaded.data
        aid_obj = data.get("aid") if isinstance(data, dict) else getattr(data, "aid", None)
        if aid_obj is None or not getattr(aid_obj, "private_key_pem", None):
            raise ValueError(f"signer identity missing private key: {sign_as}")
        params["_client_signature_identity"] = aid_obj

    async def _call(self, method: str, params: dict[str, Any] | None = None, *, path: str = "") -> Any:
        try:
            return await self._client.call(method, params or {})
        except Exception as exc:
            raise map_storage_error(exc, path=path) from exc

    def _bearer_headers(self) -> dict[str, str]:
        token = str(getattr(self._client, "access_token", "") or "").strip()
        if not token:
            identity = getattr(self._client, "_identity", None)
            if isinstance(identity, dict):
                token = str(identity.get("access_token") or "").strip()
        if not token:
            for attr in ("_session_params", "_sessionParams"):
                session_params = getattr(self._client, attr, None)
                if isinstance(session_params, dict):
                    token = str(session_params.get("access_token") or "").strip()
                    if token:
                        break
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def ls(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.ls", self._params(path=path, **options), path=path)

    async def find(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.find", self._params(path=path, **options), path=path)

    async def stat(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.stat", self._params(path=path, **options), path=path)

    async def lstat(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.lstat", self._params(path=path, **options), path=path)

    async def mkdir(self, path: str, *, parents: bool = False, **options: Any) -> Any:
        return await self._call("group.fs.mkdir", self._params(path=path, parents=parents, **options), path=path)

    async def set_acl(
        self,
        path: str,
        *,
        grantee_aid: str = "role:admin",
        perms: str = "rwx",
        **options: Any,
    ) -> Any:
        return await self._call(
            "group.fs.set_acl",
            self._params(path=path, grantee_aid=grantee_aid, perms=perms, **options),
            path=path,
        )

    async def remove_acl(
        self,
        path: str,
        *,
        grantee_aid: str = "role:admin",
        **options: Any,
    ) -> Any:
        return await self._call(
            "group.fs.remove_acl",
            self._params(path=path, grantee_aid=grantee_aid, **options),
            path=path,
        )

    async def get_acl(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.get_acl", self._params(path=path, **options), path=path)

    async def list_acl(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.list_acl", self._params(path=path, **options), path=path)

    async def rm(self, path: str, *, recursive: bool = False, force: bool = False, **options: Any) -> Any:
        return await self._call(
            "group.fs.rm",
            self._params(path=path, recursive=recursive, force=force, **options),
            path=path,
        )

    async def cp(
        self,
        src: str,
        dst: str,
        *,
        force: bool = False,
        recursive: bool = False,
        parents: bool = True,
        follow_symlinks: bool | None = None,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        expected_version: int | None = None,
        verify_hash: bool = True,
        progress: Callable[[int, int], None] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        **options: Any,
    ) -> Any:
        src_group_id = options.pop("src_group_id", None)
        dst_group_id = options.pop("dst_group_id", None)
        shared_group_id = options.pop("group_id", None)
        src_remote = _is_group_remote_copy_path(src, src_group_id, shared_group_id)
        dst_remote = _is_group_remote_copy_path(dst, dst_group_id, shared_group_id)
        callback = progress or on_progress

        if src_remote and dst_remote:
            params = self._params(src=src, dst=dst, **options)
            if shared_group_id is not None:
                params["group_id"] = shared_group_id
            if src_group_id is not None:
                params["src_group_id"] = src_group_id
            if dst_group_id is not None:
                params["dst_group_id"] = dst_group_id
            if force:
                params["force"] = True
            if recursive:
                params["recursive"] = True
            if follow_symlinks is not None:
                params["follow_symlinks"] = follow_symlinks
            return await self._call("group.fs.cp", params, path=src)
        if not src_remote and dst_remote:
            return await self._upload_local_file(
                src,
                dst,
                force=force,
                parents=parents,
                content_type=content_type,
                metadata=metadata,
                expected_version=expected_version,
                on_progress=callback,
                group_id=dst_group_id or shared_group_id,
                **options,
            )
        if src_remote and not dst_remote:
            return await self._download_remote_file(
                src,
                dst,
                force=force,
                verify_hash=verify_hash,
                on_progress=callback,
                group_id=src_group_id or shared_group_id,
                **options,
            )
        raise StorageError("local-to-local copy is not handled by group.fs", code="EINVAL", path=src)

    async def mv(self, src: str, dst: str, *, force: bool = False, **options: Any) -> Any:
        src_group_id = options.pop("src_group_id", None)
        dst_group_id = options.pop("dst_group_id", None)
        shared_group_id = options.pop("group_id", None)
        if not _is_group_remote_copy_path(src, src_group_id, shared_group_id) or not _is_group_remote_copy_path(
            dst,
            dst_group_id,
            shared_group_id,
        ):
            raise StorageError("group.fs.mv only supports group remote paths", code="EINVAL", path=src)
        params = self._params(src=src, dst=dst, **options)
        if shared_group_id is not None:
            params["group_id"] = shared_group_id
        if src_group_id is not None:
            params["src_group_id"] = src_group_id
        if dst_group_id is not None:
            params["dst_group_id"] = dst_group_id
        if force:
            params["force"] = True
        return await self._call("group.fs.mv", params, path=src)

    async def df(self, path_or_group: str | None = None, **options: Any) -> Any:
        params = self._params(**options)
        if path_or_group is not None:
            params["path"] = path_or_group
        return await self._call("group.fs.df", params, path=path_or_group or "")

    async def mount(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.mount", self._params(path=path, **options), path=path)

    async def umount(self, path: str, **options: Any) -> Any:
        return await self._call("group.fs.umount", self._params(path=path, **options), path=path)

    async def _upload_local_file(
        self,
        local_path: str,
        group_path: str,
        *,
        force: bool,
        parents: bool,
        content_type: str | None,
        metadata: dict[str, Any] | None,
        expected_version: int | None,
        on_progress: Callable[[int, int], None] | None,
        **options: Any,
    ) -> Any:
        source = Path(_strip_local_path_prefix(local_path))
        if source.is_dir():
            raise IsADirectoryError("directory upload is not supported by group.fs.cp yet", code="EISDIR", path=local_path)
        data = source.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        guessed_type = content_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        base_params = self._params(
            path=group_path,
            size_bytes=len(data),
            sha256=sha256,
            content_type=guessed_type,
            force=force,
            parents=parents,
            metadata=metadata,
            expected_version=expected_version,
            **options,
        )
        check = await self._call("group.fs.check_upload", dict(base_params), path=group_path)
        if isinstance(check, dict):
            if check.get("within_limit") is False:
                raise StorageError("file size exceeds group fs upload limit", code="E2BIG", path=group_path, data=check)
            if check.get("target_exists") and not force and expected_version is None:
                raise ExistsError("group fs target already exists", code="EEXIST", path=group_path, data=check.get("target"))

        if isinstance(check, dict) and any(bool(check.get(key)) for key in ("instant", "dedup_hit", "skip_upload")):
            complete_params = dict(base_params)
            complete_params["skip_blob"] = True
            if check.get("session_id") is not None:
                complete_params["session_id"] = check.get("session_id")
            return await self._call("group.fs.complete_upload", complete_params, path=group_path)

        session = await self._call("group.fs.create_upload_session", dict(base_params), path=group_path)
        if not isinstance(session, dict):
            raise StorageError(f"group.fs.create_upload_session returned invalid response: {session}", path=group_path)
        upload_url = str(session.get("upload_url") or session.get("url") or "").strip()
        if not upload_url:
            raise StorageError(f"group.fs.create_upload_session did not return upload_url: {session}", path=group_path)
        headers = dict(session.get("headers") or {})
        headers.setdefault("Content-Type", guessed_type)
        await self.lowlevel.http_put(upload_url, data, headers=headers, on_progress=on_progress)
        complete_params = dict(base_params)
        session_id = session.get("session_id") or session.get("id")
        if session_id is not None:
            complete_params["session_id"] = session_id
        return await self._call("group.fs.complete_upload", complete_params, path=group_path)

    async def _download_remote_file(
        self,
        group_path: str,
        local_path: str,
        *,
        force: bool,
        verify_hash: bool,
        on_progress: Callable[[int, int], None] | None,
        **options: Any,
    ) -> DownloadResult:
        target = Path(_strip_local_path_prefix(local_path))
        if target.exists() and not target.is_dir() and not force:
            raise ExistsError(f"local path already exists: {target}", code="EEXIST", path=str(target))
        ticket = await self._call(
            "group.fs.create_download_ticket",
            self._params(path=group_path, **options),
            path=group_path,
        )
        if not isinstance(ticket, dict):
            raise StorageError(f"group.fs.create_download_ticket returned invalid response: {ticket}", path=group_path)
        download_url = str(ticket.get("download_url") or ticket.get("url") or "").strip()
        if not download_url:
            raise StorageError(f"group.fs.create_download_ticket did not return download_url: {ticket}", path=group_path)
        if target.exists() and target.is_dir():
            file_name = str(ticket.get("file_name") or ticket.get("name") or Path(group_path).name or "download").strip()
            target = target / file_name
            if target.exists() and not force:
                raise ExistsError(f"local path already exists: {target}", code="EEXIST", path=str(target))

        data = await self.lowlevel.http_get(
            download_url,
            headers=self._bearer_headers(),
            on_progress=on_progress,
        )
        expected_sha = str(ticket.get("sha256") or "").strip()
        verified = not verify_hash or not expected_sha or hashlib.sha256(data).hexdigest() == expected_sha
        if verify_hash and not verified:
            raise StorageError("download hash verification failed", code="ECONFLICT", path=group_path, data=ticket)

        target.parent.mkdir(parents=True, exist_ok=True)
        if force:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile("wb", delete=False, dir=target.parent, prefix=f".{target.name}.", suffix=".tmp") as handle:
                    tmp_path = Path(handle.name)
                    handle.write(data)
                tmp_path.replace(target)
            finally:
                if tmp_path is not None and tmp_path.exists():
                    tmp_path.unlink()
        else:
            try:
                with target.open("xb") as handle:
                    handle.write(data)
            except FileExistsError as exc:
                raise ExistsError(f"local path already exists: {target}", code="EEXIST", path=str(target)) from exc
        return DownloadResult(path=group_path, local_path=str(target), size=len(data), sha256=expected_sha, verified=verified)


__all__ = ["GroupFSVFS", "is_group_remote_path"]
