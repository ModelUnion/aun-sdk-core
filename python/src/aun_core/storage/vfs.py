from __future__ import annotations

import base64
import hashlib
import mimetypes
import posixpath
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

from .errors import ConflictError, ExistsError, NotFoundError, StorageError, map_storage_error
from .lowlevel import StorageLowLevel
from .types import DownloadResult, NodeView, ObjectView, RemoveResult, UsageView, normalize_display_path


def normalize_path(path: str) -> str:
    raw = str(path or "/").replace("\\", "/").strip()
    if not raw.startswith("/"):
        raw = f"/{raw}"
    raw = re.sub(r"/+", "/", raw)
    normalized = posixpath.normpath(raw)
    return "/" if normalized == "." else normalized


def path_to_key(path: str) -> str:
    normalized = normalize_path(path)
    return "" if normalized == "/" else normalized.lstrip("/")


def key_to_path(key: str) -> str:
    return normalize_display_path(key)


def split_parent_name(path: str) -> tuple[str, str]:
    key = path_to_key(path)
    if not key:
        return "", ""
    if "/" not in key:
        return "", key
    parent, name = key.rsplit("/", 1)
    return parent, name


_REMOTE_REF_RE = re.compile(r"^[^:/\\][^:]*:")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _is_remote_ref(value: str) -> bool:
    text = str(value or "")
    if _WINDOWS_DRIVE_RE.match(text):
        return False
    if text.startswith(("http://", "https://")):
        return False
    return bool(_REMOTE_REF_RE.match(text))


def _split_remote_ref(value: str, *, field: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if not _is_remote_ref(text):
        raise ValueError(f"{field} must be remote AID:path")
    owner, path = text.split(":", 1)
    owner = owner.strip()
    if not owner:
        raise ValueError(f"{field} missing AID")
    return owner, normalize_path(path or "/")


class StorageVFS:
    def __init__(self, client: Any, *, lowlevel: StorageLowLevel | None = None, use_fs_rpc: bool = True) -> None:
        self._client = client
        self.lowlevel = lowlevel or StorageLowLevel(client)
        self.use_fs_rpc = use_fs_rpc
        self.pwd = "/"

    @property
    def default_owner(self) -> str | None:
        return getattr(self._client, "aid", None) or getattr(self._client, "_aid", None)

    def _owner(self, owner: str | None) -> str | None:
        return owner or self.default_owner

    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        content_type: str | None = None,
        overwrite: bool = False,
        expected_version: int | None = None,
        public: bool = False,
        metadata: dict[str, Any] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> ObjectView:
        file_path = Path(local_path)
        data = file_path.read_bytes()
        guessed_type = content_type or mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        return await self._upload_bytes(
            data,
            remote_path,
            owner=owner,
            bucket=bucket,
            content_type=guessed_type,
            overwrite=overwrite,
            expected_version=expected_version,
            public=public,
            metadata=metadata,
            on_progress=on_progress,
        )

    async def write_bytes(
        self,
        remote_path: str,
        data: bytes,
        *,
        owner: str | None = None,
        bucket: str = "default",
        content_type: str | None = None,
        overwrite: bool = False,
        expected_version: int | None = None,
        public: bool = False,
        metadata: dict[str, Any] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> ObjectView:
        return await self._upload_bytes(
            data,
            remote_path,
            owner=owner,
            bucket=bucket,
            content_type=content_type or "application/octet-stream",
            overwrite=overwrite,
            expected_version=expected_version,
            public=public,
            metadata=metadata,
            on_progress=on_progress,
        )

    async def _upload_bytes(
        self,
        data: bytes,
        remote_path: str,
        *,
        owner: str | None,
        bucket: str,
        content_type: str,
        overwrite: bool,
        expected_version: int | None,
        public: bool,
        metadata: dict[str, Any] | None,
        on_progress: Callable[[int, int], None] | None,
    ) -> ObjectView:
        owner = self._owner(owner)
        object_key = path_to_key(remote_path)
        sha256 = hashlib.sha256(data).hexdigest()
        try:
            check = await self.lowlevel.check_upload(
                owner=owner,
                bucket=bucket,
                object_key=object_key,
                size=len(data),
                sha256=sha256,
            )
            if check.get("within_limit") is False:
                max_file = int(check.get("max_file_size_bytes") or 0)
                suffix = f" > {max_file}" if max_file else ""
                raise StorageError(f"file size exceeds max_file_size_bytes: {len(data)}{suffix}", code="E2BIG", path=remote_path)
            if check.get("target_exists") and not overwrite and expected_version is None:
                raise ExistsError(f"remote path already exists: {remote_path}", code="EEXIST", path=remote_path, data=check.get("target"))
            if check.get("dedup_hit") or check.get("skip_upload"):
                completed = await self.lowlevel.complete_upload(
                    owner=owner,
                    bucket=bucket,
                    object_key=object_key,
                    size=len(data),
                    sha256=sha256,
                    content_type=content_type,
                    metadata=metadata,
                    is_public=public,
                    expected_version=expected_version,
                    skip_blob=True,
                    overwrite=overwrite,
                )
                return ObjectView.from_dict(completed)

            if check.get("inline") is True:
                result = await self.lowlevel.put_object(
                    owner=owner,
                    bucket=bucket,
                    object_key=object_key,
                    content=data,
                    content_type=content_type,
                    metadata=metadata,
                    is_public=public,
                    expected_version=expected_version,
                    overwrite=overwrite,
                )
                return ObjectView.from_dict(result)

            session = await self.lowlevel.create_upload_session(
                owner=owner,
                bucket=bucket,
                object_key=object_key,
                size=len(data),
                content_type=content_type,
                expected_version=expected_version,
                overwrite=overwrite,
            )
            upload_url = str(session.get("upload_url") or "")
            if not upload_url:
                raise StorageError(f"create_upload_session did not return upload_url: {session}", path=remote_path)
            await self.lowlevel.http_put(
                upload_url,
                data,
                headers=session.get("headers") or {"Content-Type": content_type},
                on_progress=on_progress,
            )
            completed = await self.lowlevel.complete_upload(
                owner=owner,
                bucket=bucket,
                object_key=object_key,
                session_id=session.get("session_id"),
                size=len(data),
                sha256=sha256,
                content_type=content_type,
                metadata=metadata,
                is_public=public,
                expected_version=expected_version,
                overwrite=overwrite,
            )
            return ObjectView.from_dict(completed)
        except Exception as exc:
            raise map_storage_error(exc, path=remote_path) from exc

    async def download_file(
        self,
        remote_path: str,
        local_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        verify_hash: bool = True,
        token: str | None = None,
        overwrite: bool = False,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> DownloadResult:
        owner = self._owner(owner)
        object_key = path_to_key(remote_path)
        ticket = await self.lowlevel.create_download_ticket(owner=owner, bucket=bucket, object_key=object_key, token=token)
        download_url = str(ticket.get("download_url") or "")
        if not download_url:
            raise StorageError(f"create_download_ticket did not return download_url: {ticket}", path=remote_path)
        target = Path(local_path)
        if target.exists() and target.is_dir():
            target = target / (str(ticket.get("file_name") or Path(object_key).name))
        if target.exists():
            if target.is_dir():
                raise StorageError(f"local path is a directory: {target}", code="EISDIR", path=str(target))
            if not overwrite:
                raise ExistsError(f"local path already exists: {target}", code="EEXIST", path=str(target))
        data = await self.lowlevel.http_get(download_url, on_progress=on_progress)
        expected_sha = str(ticket.get("sha256") or "")
        verified = not verify_hash or not expected_sha or hashlib.sha256(data).hexdigest() == expected_sha
        if verify_hash and not verified:
            raise StorageError("download hash verification failed", code="ECONFLICT", path=remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not overwrite:
            try:
                with target.open("xb") as handle:
                    handle.write(data)
            except FileExistsError as exc:
                raise ExistsError(f"local path already exists: {target}", code="EEXIST", path=str(target)) from exc
        else:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile("wb", delete=False, dir=target.parent, prefix=f".{target.name}.", suffix=".tmp") as handle:
                    tmp_path = Path(handle.name)
                    handle.write(data)
                tmp_path.replace(target)
            finally:
                if tmp_path is not None and tmp_path.exists():
                    tmp_path.unlink()
        return DownloadResult(path=normalize_path(remote_path), local_path=str(target), size=len(data), sha256=expected_sha, verified=verified)

    async def read_bytes(
        self,
        remote_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        token: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> bytes:
        owner = self._owner(owner)
        object_key = path_to_key(remote_path)
        try:
            result = await self.lowlevel.get_object(
                owner=owner,
                bucket=bucket,
                object_key=object_key,
                token=token,
                offset=offset,
                limit=limit,
            )
            return base64.b64decode(str(result.get("content") or ""), validate=True)
        except StorageError as exc:
            if offset is not None or limit is not None:
                raise
            text = str(exc)
            if "create_download_ticket" not in text and "inline" not in text.lower() and "超过" not in text:
                raise
        ticket = await self.lowlevel.create_download_ticket(owner=owner, bucket=bucket, object_key=object_key, token=token)
        download_url = str(ticket.get("download_url") or "")
        if not download_url:
            raise StorageError(f"create_download_ticket did not return download_url: {ticket}", path=remote_path)
        return await self.lowlevel.http_get(download_url)

    async def list(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        page: int = 1,
        size: int = 100,
        marker: str | None = None,
        long: bool = False,
        recursive: bool = False,
        token: str | None = None,
    ) -> list[NodeView]:
        if recursive:
            return await self._list_recursive(path, owner=owner, bucket=bucket, size=size, long=long, token=token)
        owner = self._owner(owner)
        if self.use_fs_rpc:
            key = path_to_key(path)
            try:
                result = await self.lowlevel.fs_list(owner=owner, bucket=bucket, path=key, page=page, size=size, marker=marker, token=token)
                return [NodeView.from_any(item) for item in (result.get("nodes") or result.get("items") or [])]
            except Exception as exc:
                raise map_storage_error(exc, path=path) from exc
        prefix = path_to_key(path)
        if prefix:
            prefix = f"{prefix.rstrip('/')}/"
        prefixes = await self.lowlevel.list_prefixes(owner=owner, bucket=bucket, prefix=prefix, size=size)
        objects = await self.lowlevel.list_objects(owner=owner, bucket=bucket, prefix=prefix, page=page, size=size, marker=marker)
        nodes: list[NodeView] = []
        seen: set[str] = set()
        for item in prefixes.get("prefixes", []):
            key = str(item)
            if prefix and key and not key.startswith(prefix):
                key = f"{prefix}{key.lstrip('/')}"
            name = key.rstrip("/").rsplit("/", 1)[-1]
            if not name:
                continue
            path_value = key_to_path(key.rstrip("/"))
            seen.add(path_value)
            nodes.append(NodeView(type="dir", path=path_value, name=name, owner=owner or "", bucket=bucket))
        for item in objects.get("items", []):
            key = str(item.get("object_key") or item.get("path") or "")
            if prefix and not key.startswith(prefix):
                continue
            remainder = key[len(prefix):] if prefix else key
            if "/" in remainder.strip("/"):
                continue
            node = NodeView.from_any(item)
            if not node.owner and owner:
                node.owner = owner
            if node.path in seen:
                continue
            nodes.append(node)
        return sorted(nodes, key=lambda n: (0 if n.type == "dir" else 1, n.name))

    async def _list_recursive(
        self,
        path: str,
        *,
        owner: str | None,
        bucket: str,
        size: int,
        long: bool,
        token: str | None = None,
    ) -> list[NodeView]:
        result: list[NodeView] = []
        pending = [normalize_path(path)]
        while pending:
            current = pending.pop(0)
            children = await self.list(current, owner=owner, bucket=bucket, size=size, long=long, token=token)
            result.extend(children)
            pending.extend(item.path for item in children if item.type == "dir")
        return result

    async def stat(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        token: str | None = None,
    ) -> NodeView:
        if self.use_fs_rpc:
            owner = self._owner(owner)
            key = path_to_key(path)
            try:
                return NodeView.from_any(await self.lowlevel.fs_stat(owner=owner, bucket=bucket, path=key, token=token))
            except Exception as exc:
                raise map_storage_error(exc, path=path) from exc
        return await self._stat(path, owner=owner, bucket=bucket, follow_symlinks=True)

    async def lstat(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        token: str | None = None,
    ) -> NodeView:
        owner = self._owner(owner)
        if self.use_fs_rpc:
            key = path_to_key(path)
            try:
                return NodeView.from_any(await self.lowlevel.fs_lstat(owner=owner, bucket=bucket, path=key, token=token))
            except Exception as exc:
                raise map_storage_error(exc, path=path) from exc
        key = path_to_key(path)
        try:
            return await self.readlink(path, owner=owner, bucket=bucket)
        except NotFoundError:
            return await self._stat(path, owner=owner, bucket=bucket, follow_symlinks=False)

    async def _stat(self, path: str, *, owner: str | None, bucket: str, follow_symlinks: bool) -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(path)
        try:
            resolved = await self.lowlevel.resolve_path(owner=owner, bucket=bucket, path=key, follow_symlinks=follow_symlinks)
            node_type = str(resolved.get("type") or "").lower()
            resolved_key = str(resolved.get("path") or key)
            if node_type in {"symlink", "link"}:
                return NodeView.from_any(resolved)
            if node_type in {"folder", "dir"}:
                folder = await self.lowlevel.get_folder(owner=owner, bucket=bucket, path=resolved_key)
                return NodeView.from_folder(folder.get("folder") or folder)
            if node_type in {"object", "file"}:
                return NodeView.from_object(await self.lowlevel.head_object(owner=owner, bucket=bucket, object_key=resolved_key))
        except Exception as exc:
            raise map_storage_error(exc, path=path) from exc
        raise NotFoundError(f"path not found: {path}", code="ENOENT", path=path)

    async def symlink(
        self,
        target: str,
        link_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        overwrite: bool = False,
    ) -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(link_path)
        result = await self.lowlevel.create_symlink(owner=owner, bucket=bucket, path=key, target=target, overwrite=overwrite)
        return NodeView.from_any(result.get("symlink") or result)

    async def readlink(self, path: str, *, owner: str | None = None, bucket: str = "default") -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(path)
        result = await self.lowlevel.readlink(owner=owner, bucket=bucket, path=key)
        raw = result.get("symlink") or result
        node_type = str(raw.get("type") or raw.get("node_type") or "").lower()
        if node_type not in {"symlink", "link"} and not raw.get("symlink_id") and not raw.get("target"):
            raise NotFoundError(f"symlink not found: {path}", code="ENOENT", path=path)
        return NodeView.from_any(raw)

    async def repoint(
        self,
        path: str,
        new_target: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        expected_version: int | None = None,
    ) -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(path)
        result = await self.lowlevel.atomic_repoint(
            owner=owner,
            bucket=bucket,
            path=key,
            new_target=new_target,
            expected_version=expected_version,
        )
        if result.get("ok") is False:
            raise ConflictError(
                "symlink version conflict",
                code="ECONFLICT",
                path=path,
                data=result,
            )
        return NodeView.from_any(result.get("symlink") or result)

    async def rename_symlink(
        self,
        src: str,
        dst: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        overwrite: bool = False,
        expected_version: int | None = None,
    ) -> NodeView:
        owner = self._owner(owner)
        result = await self.lowlevel.rename_symlink(
            owner=owner,
            bucket=bucket,
            path=path_to_key(src),
            new_path=path_to_key(dst),
            overwrite=overwrite,
            expected_version=expected_version,
        )
        if result.get("ok") is False:
            raise ConflictError(
                "symlink version conflict",
                code="ECONFLICT",
                path=src,
                data=result,
            )
        return NodeView.from_any(result.get("symlink") or result)

    async def mkdir(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        parents: bool = False,
    ) -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(path)
        if self.use_fs_rpc:
            result = await self.lowlevel.fs_mkdir(owner=owner, bucket=bucket, path=key, parents=parents)
            return NodeView.from_any(result.get("node") or result)
        result = await self.lowlevel.create_folder(owner=owner, bucket=bucket, path=key, parents=parents)
        return NodeView.from_folder(result.get("folder") or result)

    async def remove(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        recursive: bool = False,
    ) -> RemoveResult:
        owner = self._owner(owner)
        key = path_to_key(path)
        if self.use_fs_rpc:
            result = await self.lowlevel.fs_remove(owner=owner, bucket=bucket, path=key, recursive=recursive)
            removed = int(result.get("removed_count") or result.get("deleted_count") or 0)
            return RemoveResult(path=normalize_path(path), removed_count=removed)
        resolved = await self.lowlevel.resolve_path(owner=owner, bucket=bucket, path=key, follow_symlinks=False)
        node_type = str(resolved.get("type") or "").lower()
        if node_type in {"symlink", "link"}:
            result = await self.lowlevel.delete_symlink(owner=owner, bucket=bucket, path=key)
            return RemoveResult(path=normalize_path(path), removed_count=1 if result.get("deleted", True) else 0)
        if recursive:
            kind = "folder" if node_type in {"folder", "dir"} else "object"
            result = await self.lowlevel.batch_delete(
                owner=owner,
                bucket=bucket,
                items=[{"type": kind, "path": key}],
                recursive=True,
            )
            summary = result.get("summary") or {}
            removed = int(summary.get("deleted") or result.get("deleted_count") or len(result.get("deleted") or []))
            return RemoveResult(path=normalize_path(path), removed_count=removed)
        if node_type in {"folder", "dir"}:
            result = await self.lowlevel.delete_folder(owner=owner, bucket=bucket, path=key, recursive=False)
            removed = int(result.get("deleted_folders") or 1)
            return RemoveResult(path=normalize_path(path), removed_count=removed)
        result = await self.lowlevel.delete_object(owner=owner, bucket=bucket, object_key=key)
        return RemoveResult(path=normalize_path(path), removed_count=1 if result.get("deleted", True) else 0)

    async def rename(
        self,
        src: str,
        dst: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        overwrite: bool = False,
        expected_version: int | None = None,
    ) -> NodeView:
        owner = self._owner(owner)
        src_key = path_to_key(src)
        dst_key = path_to_key(dst)
        if self.use_fs_rpc:
            result = await self.lowlevel.fs_rename(
                owner=owner,
                bucket=bucket,
                src=src_key,
                dst=dst_key,
                overwrite=overwrite,
                expected_version=expected_version,
            )
            return NodeView.from_any(result.get("node") or result)
        dst_parent, dst_name = split_parent_name(dst)
        resolved = await self.lowlevel.resolve_path(owner=owner, bucket=bucket, path=src_key)
        node_type = str(resolved.get("type") or "").lower()
        if node_type in {"folder", "dir"}:
            result = await self.lowlevel.move_folder(
                owner=owner,
                bucket=bucket,
                path=src_key,
                dst_parent_path=dst_parent,
                new_name=dst_name,
                expected_version=expected_version,
            )
            return NodeView.from_folder(result.get("folder") or result)
        result = await self.lowlevel.move_object(
            owner=owner,
            bucket=bucket,
            path=src_key,
            dst_parent_path=dst_parent,
            new_name=dst_name,
            overwrite=overwrite,
            expected_version=expected_version,
        )
        return NodeView.from_object(result.get("object") or result)

    async def copy(
        self,
        src: str,
        dst: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        dst_owner: str | None = None,
        dst_bucket: str | None = None,
        overwrite: bool = False,
        follow_symlinks: bool = False,
        recursive: bool = False,
    ) -> NodeView:
        owner = self._owner(owner)
        dst_owner = self._owner(dst_owner) if dst_owner else None
        src_key = path_to_key(src)
        dst_key = path_to_key(dst)
        if self.use_fs_rpc:
            result = await self.lowlevel.fs_copy(
                owner=owner,
                bucket=bucket,
                src=src_key,
                dst=dst_key,
                overwrite=overwrite,
                follow_symlinks=follow_symlinks,
                recursive=recursive,
                dst_owner=dst_owner,
                dst_bucket=dst_bucket,
            )
            return NodeView.from_any(result.get("node") or result)
        resolved = await self.lowlevel.resolve_path(owner=owner, bucket=bucket, path=src_key)
        if str(resolved.get("type") or "").lower() in {"folder", "dir"}:
            if not recursive:
                raise StorageError("directory copy requires recursive traversal", code="EISDIR", path=src)
            result = await self.lowlevel.fs_copy(
                owner=owner,
                bucket=bucket,
                src=src_key,
                dst=dst_key,
                overwrite=overwrite,
                follow_symlinks=follow_symlinks,
                recursive=True,
                dst_owner=dst_owner,
                dst_bucket=dst_bucket,
            )
            return NodeView.from_any(result.get("node") or result)
        result = await self.lowlevel.copy_object(
            owner=owner,
            bucket=bucket,
            src_path=src_key,
            dst_path=dst_key,
            overwrite=overwrite,
        )
        return NodeView.from_object(result.get("object") or result)

    async def find(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        name: str | None = None,
        node_type: str | None = None,
        size: str | None = None,
        mtime: str | None = None,
        page: int = 1,
        page_size: int = 1000,
        token: str | None = None,
    ) -> list[NodeView]:
        owner = self._owner(owner)
        result = await self.lowlevel.fs_find(
            owner=owner,
            bucket=bucket,
            path=path_to_key(path),
            name=name,
            node_type=node_type,
            size=size,
            mtime=mtime,
            page=page,
            page_size=page_size,
            token=token,
        )
        items = result.get("nodes") or result.get("items") or []
        return [NodeView.from_any(item) for item in items]

    async def df(self, *, owner: str | None = None, bucket: str = "default") -> UsageView:
        owner = self._owner(owner)
        result = await self.lowlevel.fs_df(owner=owner, bucket=bucket)
        if owner and "owner_aid" not in result:
            result["owner_aid"] = owner
        return UsageView.from_dict(result)

    async def mount(
        self,
        source: str,
        mount_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        readonly: bool = True,
        expires_at: int | None = None,
        source_bucket: str | None = None,
        require_approval: bool = False,
    ) -> NodeView:
        source_aid, source_remote_path = _split_remote_ref(source, field="source")
        mount_owner = owner
        mount_remote_path = mount_path
        if _is_remote_ref(mount_path):
            parsed_owner, parsed_path = _split_remote_ref(mount_path, field="mount_path")
            if owner and owner != parsed_owner:
                raise ValueError("mount_path owner conflicts with owner")
            mount_owner = parsed_owner
            mount_remote_path = parsed_path
        mount_owner = self._owner(mount_owner)
        result = await self.lowlevel.fs_mount(
            owner=mount_owner,
            bucket=bucket,
            mount_path=path_to_key(mount_remote_path),
            source_aid=source_aid,
            source_path=path_to_key(source_remote_path),
            readonly=readonly,
            expires_at=expires_at,
            source_bucket=source_bucket,
            require_approval=require_approval,
        )
        return NodeView.from_any(result.get("mount") or result)

    async def mount_volume(
        self,
        volume_id: str,
        mount_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        readonly: bool = True,
        expires_at: int | None = None,
        require_approval: bool = False,
    ) -> NodeView:
        mount_owner = owner
        mount_remote_path = mount_path
        if _is_remote_ref(mount_path):
            parsed_owner, parsed_path = _split_remote_ref(mount_path, field="mount_path")
            if owner and owner != parsed_owner:
                raise ValueError("mount_path owner conflicts with owner")
            mount_owner = parsed_owner
            mount_remote_path = parsed_path
        mount_owner = self._owner(mount_owner)
        result = await self.lowlevel.fs_mount(
            owner=mount_owner,
            bucket=bucket,
            mount_path=path_to_key(mount_remote_path),
            readonly=readonly,
            expires_at=expires_at,
            require_approval=require_approval,
            volume_id=volume_id,
        )
        return NodeView.from_any(result.get("mount") or result)

    async def approve_mount(
        self,
        mount_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        mount_owner = owner
        mount_remote_path = mount_path
        if _is_remote_ref(mount_path):
            parsed_owner, parsed_path = _split_remote_ref(mount_path, field="mount_path")
            if owner and owner != parsed_owner:
                raise ValueError("mount_path owner conflicts with owner")
            mount_owner = parsed_owner
            mount_remote_path = parsed_path
        mount_owner = self._owner(mount_owner)
        return await self.lowlevel.fs_approve(
            owner=mount_owner,
            bucket=bucket,
            mount_path=path_to_key(mount_remote_path),
            mount_id=mount_id,
            request_id=request_id,
        )

    async def reject_mount(
        self,
        mount_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        mount_owner = owner
        mount_remote_path = mount_path
        if _is_remote_ref(mount_path):
            parsed_owner, parsed_path = _split_remote_ref(mount_path, field="mount_path")
            if owner and owner != parsed_owner:
                raise ValueError("mount_path owner conflicts with owner")
            mount_owner = parsed_owner
            mount_remote_path = parsed_path
        mount_owner = self._owner(mount_owner)
        return await self.lowlevel.fs_reject(
            owner=mount_owner,
            bucket=bucket,
            mount_path=path_to_key(mount_remote_path),
            mount_id=mount_id,
            request_id=request_id,
        )

    async def unmount(
        self,
        mount_path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
    ) -> RemoveResult:
        mount_owner = owner
        mount_remote_path = mount_path
        if _is_remote_ref(mount_path):
            parsed_owner, parsed_path = _split_remote_ref(mount_path, field="mount_path")
            if owner and owner != parsed_owner:
                raise ValueError("mount_path owner conflicts with owner")
            mount_owner = parsed_owner
            mount_remote_path = parsed_path
        mount_owner = self._owner(mount_owner)
        result = await self.lowlevel.fs_unmount(
            owner=mount_owner,
            bucket=bucket,
            mount_path=path_to_key(mount_remote_path),
        )
        return RemoveResult(path=normalize_path(mount_remote_path), removed_count=1 if result.get("unmounted") else 0)

    async def set_acl(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        grantee_aid: str,
        perms: str,
        expires_at: int | None = None,
        max_uses: int | None = None,
    ) -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.set_acl(
            owner=owner,
            bucket=bucket,
            path=key,
            grantee_aid=grantee_aid,
            perms=perms,
            expires_at=expires_at,
            max_uses=max_uses,
        )

    async def remove_acl(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        grantee_aid: str,
    ) -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.remove_acl(owner=owner, bucket=bucket, path=key, grantee_aid=grantee_aid)

    async def list_acl(self, path: str, *, owner: str | None = None, bucket: str = "default") -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.list_acl(owner=owner, bucket=bucket, path=key)

    async def set_visibility(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        visibility: str,
        allow_roles: list[str] | None = None,
    ) -> NodeView:
        owner = self._owner(owner)
        key = path_to_key(path)
        return NodeView.from_any(await self.lowlevel.set_visibility(
            owner=owner,
            bucket=bucket,
            path=key,
            visibility=visibility,
            allow_roles=allow_roles,
        ))

    async def check_access(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        operation: str = "read",
        token: str | None = None,
        follow_symlinks: bool = True,
    ) -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.check_access(
            owner=owner,
            bucket=bucket,
            path=key,
            operation=operation,
            token=token,
            follow_symlinks=follow_symlinks,
        )

    async def issue_token(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        expires_at: int | None = None,
        max_reads: int | None = None,
    ) -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.issue_token(owner=owner, bucket=bucket, path=key, expires_at=expires_at, max_reads=max_reads)

    async def revoke_token(
        self,
        path: str,
        *,
        owner: str | None = None,
        bucket: str = "default",
        token: str,
    ) -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.revoke_token(owner=owner, bucket=bucket, path=key, token=token)

    async def list_tokens(self, path: str, *, owner: str | None = None, bucket: str = "default") -> dict[str, Any]:
        owner = self._owner(owner)
        key = path_to_key(path)
        return await self.lowlevel.list_tokens(owner=owner, bucket=bucket, path=key)

    async def get_usage(self, *, owner: str | None = None, bucket: str = "default") -> UsageView:
        owner = self._owner(owner)
        result = await self.lowlevel.get_quota(owner=owner, bucket=bucket)
        if owner and "owner_aid" not in result:
            result["owner_aid"] = owner
        return UsageView.from_dict(result)
