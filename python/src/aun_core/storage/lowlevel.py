from __future__ import annotations

import asyncio
import base64
import ssl
import urllib.request
from typing import Any, BinaryIO

from .errors import map_storage_error


class _AllMethodRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        method = req.get_method()
        if code in (301, 302, 303, 307, 308) and method in {"PUT", "POST", "DELETE", "PATCH"}:
            return urllib.request.Request(
                newurl,
                data=req.data,
                method=method,
                headers={k: v for k, v in req.header_items() if k.lower() != "host"},
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(verify_ssl: bool):
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
        _AllMethodRedirectHandler(),
    )


class StorageLowLevel:
    def __init__(self, client: Any, *, verify_ssl: bool | None = None) -> None:
        self._client = client
        if verify_ssl is None:
            cfg = getattr(client, "_config_model", None)
            verify_ssl = bool(getattr(cfg, "verify_ssl", True))
        self.verify_ssl = bool(verify_ssl)

    async def _call(self, method: str, params: dict[str, Any] | None = None, *, path: str = "") -> dict[str, Any]:
        try:
            result = await self._client.call(method, params or {})
        except Exception as exc:
            raise map_storage_error(exc, path=path) from exc
        return result if isinstance(result, dict) else {"result": result}

    @staticmethod
    def _params(owner: str | None = None, bucket: str = "default", **kwargs: Any) -> dict[str, Any]:
        params = {key: value for key, value in kwargs.items() if value is not None}
        if owner:
            params["owner_aid"] = owner
        if bucket:
            params["bucket"] = bucket
        return params

    async def get_limits(self, *, owner: str | None = None, bucket: str = "default") -> dict[str, Any]:
        return await self._call("storage.get_limits", self._params(owner, bucket))

    async def get_quota(self, *, owner: str | None = None, bucket: str = "default") -> dict[str, Any]:
        return await self._call("storage.get_quota", self._params(owner, bucket))

    async def check_upload(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        size: int,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.check_upload",
            self._params(owner, bucket, object_key=object_key, size_bytes=size, sha256=sha256),
            path=object_key,
        )

    async def put_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        content: bytes,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        is_public: bool = False,
        expected_version: int | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.put_object",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                content=base64.b64encode(content).decode("ascii"),
                content_type=content_type,
                metadata=metadata,
                is_private=not is_public,
                expected_version=expected_version,
                overwrite=overwrite,
            ),
            path=object_key,
        )

    async def get_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        token: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.get_object",
            self._params(owner, bucket, object_key=object_key, token=token, offset=offset, limit=limit),
            path=object_key,
        )

    async def create_upload_session(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        size: int,
        content_type: str | None = None,
        expected_version: int | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.create_upload_session",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                size_bytes=size,
                content_type=content_type,
                expected_version=expected_version,
                overwrite=overwrite,
            ),
            path=object_key,
        )

    async def complete_upload(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        session_id: str | None = None,
        size: int,
        sha256: str,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        is_public: bool = False,
        expected_version: int | None = None,
        skip_blob: bool = False,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.complete_upload",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                session_id=session_id,
                size_bytes=size,
                sha256=sha256,
                content_type=content_type,
                metadata=metadata,
                is_private=not is_public,
                expected_version=expected_version,
                skip_blob=skip_blob,
                overwrite=overwrite,
            ),
            path=object_key,
        )

    async def create_download_ticket(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.create_download_ticket",
            self._params(owner, bucket, object_key=object_key, token=token),
            path=object_key,
        )

    async def create_share_link(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        allowed_aids: list[str] | None = None,
        expire_in_seconds: int | None = None,
        max_uses: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.create_share_link",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                allowed_aids=allowed_aids,
                expire_in_seconds=expire_in_seconds,
                max_uses=max_uses,
            ),
            path=object_key,
        )

    async def list_share_links(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.list_share_links",
            self._params(owner, bucket, object_key=object_key),
            path=object_key or "",
        )

    async def revoke_share_link(self, *, share_id: str) -> dict[str, Any]:
        return await self._call("storage.revoke_share_link", {"share_id": share_id})

    async def get_by_share(self, *, share_id: str) -> dict[str, Any]:
        return await self._call("storage.get_by_share", {"share_id": share_id})

    async def http_put(
        self,
        upload_url: str,
        data: bytes | BinaryIO,
        headers: dict[str, str] | None = None,
        on_progress=None,
    ) -> None:
        payload = data.read() if hasattr(data, "read") else data
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("http_put data must be bytes or binary file")
        if on_progress:
            on_progress(0, len(payload))

        def _run() -> None:
            opener = _build_opener(self.verify_ssl)
            req = urllib.request.Request(upload_url, data=bytes(payload), method="PUT")
            for key, value in (headers or {}).items():
                req.add_header(key, value)
            with opener.open(req, timeout=120) as resp:
                status = int(resp.status)
                if status < 200 or status >= 300:
                    raise RuntimeError(f"HTTP PUT failed: status={status}")

        try:
            await asyncio.to_thread(_run)
        except Exception as exc:
            raise map_storage_error(exc) from exc
        if on_progress:
            on_progress(len(payload), len(payload))

    async def http_get(
        self,
        download_url: str,
        headers: dict[str, str] | None = None,
        on_progress=None,
    ) -> bytes:
        def _run() -> bytes:
            opener = _build_opener(self.verify_ssl)
            req = urllib.request.Request(download_url, method="GET")
            for key, value in (headers or {}).items():
                req.add_header(key, value)
            with opener.open(req, timeout=120) as resp:
                return resp.read()

        try:
            data = await asyncio.to_thread(_run)
        except Exception as exc:
            raise map_storage_error(exc) from exc
        if on_progress:
            on_progress(len(data), len(data))
        return data

    async def head_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.head_object",
            self._params(owner, bucket, object_key=object_key, token=token),
            path=object_key,
        )

    async def list_objects(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        prefix: str = "",
        page: int = 1,
        size: int = 100,
        marker: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.list_objects",
            self._params(owner, bucket, prefix=prefix, page=page, size=size, marker=marker),
            path=prefix,
        )

    async def list_prefixes(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        prefix: str = "",
        size: int = 100,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.list_prefixes",
            self._params(owner, bucket, prefix=prefix, size=size),
            path=prefix,
        )

    async def delete_object(self, *, owner: str | None = None, bucket: str = "default", object_key: str) -> dict[str, Any]:
        return await self._call(
            "storage.delete_object",
            self._params(owner, bucket, object_key=object_key),
            path=object_key,
        )

    async def set_object_meta(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        metadata: dict[str, Any],
        content_type: str | None = None,
        merge: bool = True,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.set_object_meta",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                metadata=metadata,
                content_type=content_type,
                merge=merge,
                expected_version=expected_version,
            ),
            path=object_key,
        )

    async def append_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        object_key: str,
        content: bytes,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        expected_version: int | None = None,
        is_public: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.append_object",
            self._params(
                owner,
                bucket,
                object_key=object_key,
                content=base64.b64encode(content).decode("ascii"),
                content_type=content_type,
                metadata=metadata,
                expected_version=expected_version,
                is_private=not is_public,
            ),
            path=object_key,
        )

    async def batch_delete(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        items: list[dict[str, Any]],
        recursive: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.batch_delete",
            self._params(owner, bucket, items=items, recursive=recursive),
        )

    async def move_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        dst_parent_path: str,
        new_name: str,
        overwrite: bool = False,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.move_object",
            self._params(
                owner,
                bucket,
                path=path,
                dst_parent_path=dst_parent_path,
                new_name=new_name,
                conflict_policy="replace" if overwrite else "reject",
                expected_version=expected_version,
            ),
            path=path,
        )

    async def copy_object(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        src_path: str,
        dst_path: str,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.copy_object",
            self._params(
                owner,
                bucket,
                src_path=src_path,
                dst_path=dst_path,
                conflict_policy="replace" if overwrite else "reject",
            ),
            path=src_path,
        )

    async def create_folder(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        parents: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.create_folder",
            self._params(owner, bucket, path=path, mkdirs=parents),
            path=path,
        )

    async def get_folder(self, *, owner: str | None = None, bucket: str = "default", path: str) -> dict[str, Any]:
        return await self._call(
            "storage.get_folder",
            self._params(owner, bucket, path=path),
            path=path,
        )

    async def list_children(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        node_type: str = "all",
        page: int = 1,
        size: int = 50,
        order_by: str | None = None,
        order: str | None = None,
        include_metadata: bool | None = None,
        include_urls: bool | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.list_children",
            self._params(
                owner,
                bucket,
                path=path,
                type=node_type,
                page=page,
                size=size,
                order_by=order_by,
                order=order,
                include_metadata=include_metadata,
                include_urls=include_urls,
            ),
            path=path,
        )

    async def move_folder(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        dst_parent_path: str,
        new_name: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.move_folder",
            self._params(
                owner,
                bucket,
                path=path,
                dst_parent_path=dst_parent_path,
                new_name=new_name,
                expected_version=expected_version,
            ),
            path=path,
        )

    async def delete_folder(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        recursive: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.delete_folder",
            self._params(owner, bucket, path=path, recursive=recursive),
            path=path,
        )

    async def create_symlink(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        target: str,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.create_symlink",
            self._params(owner, bucket, path=path, target=target, overwrite=overwrite),
            path=path,
        )

    async def readlink(self, *, owner: str | None = None, bucket: str = "default", path: str) -> dict[str, Any]:
        return await self._call(
            "storage.readlink",
            self._params(owner, bucket, path=path),
            path=path,
        )

    async def atomic_repoint(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        new_target: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.atomic_repoint",
            self._params(owner, bucket, path=path, new_target=new_target, expected_version=expected_version),
            path=path,
        )

    async def rename_symlink(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        new_path: str,
        overwrite: bool = False,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.rename_symlink",
            self._params(
                owner,
                bucket,
                path=path,
                new_path=new_path,
                overwrite=overwrite,
                expected_version=expected_version,
            ),
            path=path,
        )

    async def delete_symlink(self, *, owner: str | None = None, bucket: str = "default", path: str) -> dict[str, Any]:
        return await self._call(
            "storage.delete_symlink",
            self._params(owner, bucket, path=path),
            path=path,
        )

    async def set_acl(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        grantee_aid: str,
        perms: str,
        expires_at: int | None = None,
        max_uses: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.set_acl",
            self._params(
                owner,
                bucket,
                path=path,
                grantee_aid=grantee_aid,
                perms=perms,
                expires_at=expires_at,
                max_uses=max_uses,
            ),
            path=path,
        )

    async def remove_acl(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        grantee_aid: str,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.remove_acl",
            self._params(owner, bucket, path=path, grantee_aid=grantee_aid),
            path=path,
        )

    async def list_acl(self, *, owner: str | None = None, bucket: str = "default", path: str) -> dict[str, Any]:
        return await self._call(
            "storage.list_acl",
            self._params(owner, bucket, path=path),
            path=path,
        )

    async def set_visibility(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        visibility: str,
        allow_roles: list[str] | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.set_visibility",
            self._params(owner, bucket, path=path, visibility=visibility, allow_roles=allow_roles),
            path=path,
        )

    async def check_access(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        operation: str = "read",
        token: str | None = None,
        follow_symlinks: bool = True,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.check_access",
            self._params(
                owner,
                bucket,
                path=path,
                operation=operation,
                token=token,
                follow_symlinks=follow_symlinks,
            ),
            path=path,
        )

    async def issue_token(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        expires_at: int | None = None,
        max_reads: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.issue_token",
            self._params(owner, bucket, path=path, expires_at=expires_at, max_reads=max_reads),
            path=path,
        )

    async def revoke_token(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        token: str,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.revoke_token",
            self._params(owner, bucket, path=path, token=token),
            path=path,
        )

    async def list_tokens(self, *, owner: str | None = None, bucket: str = "default", path: str) -> dict[str, Any]:
        return await self._call(
            "storage.list_tokens",
            self._params(owner, bucket, path=path),
            path=path,
        )

    async def fs_list(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str = "",
        page: int = 1,
        size: int = 100,
        marker: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.list",
            self._params(owner, bucket, path=path, page=page, size=size, marker=marker, token=token),
            path=path,
        )

    async def fs_stat(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.stat",
            self._params(owner, bucket, path=path, token=token),
            path=path,
        )

    async def fs_lstat(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.lstat",
            self._params(owner, bucket, path=path, token=token),
            path=path,
        )

    async def fs_mkdir(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        parents: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.mkdir",
            self._params(owner, bucket, path=path, parents=parents),
            path=path,
        )

    async def fs_remove(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        recursive: bool = False,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.remove",
            self._params(owner, bucket, path=path, recursive=recursive),
            path=path,
        )

    async def fs_rename(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        src: str,
        dst: str,
        overwrite: bool = False,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.rename",
            self._params(
                owner,
                bucket,
                src=src,
                dst=dst,
                overwrite=overwrite,
                expected_version=expected_version,
            ),
            path=src,
        )

    async def fs_copy(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        src: str,
        dst: str,
        overwrite: bool = False,
        follow_symlinks: bool = False,
        recursive: bool = False,
        dst_owner: str | None = None,
        dst_bucket: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.copy",
            self._params(
                owner,
                bucket,
                src=src,
                dst=dst,
                overwrite=overwrite,
                follow_symlinks=follow_symlinks,
                recursive=recursive,
                dst_owner_aid=dst_owner,
                dst_bucket=dst_bucket,
            ),
            path=src,
        )

    async def fs_find(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        name: str | None = None,
        node_type: str | None = None,
        size: str | None = None,
        mtime: str | None = None,
        page: int = 1,
        page_size: int = 1000,
        token: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.find",
            self._params(
                owner,
                bucket,
                path=path,
                name=name,
                type=node_type,
                size=size,
                mtime=mtime,
                page=page,
                page_size=page_size,
                token=token,
            ),
            path=path,
        )

    async def fs_df(self, *, owner: str | None = None, bucket: str = "default") -> dict[str, Any]:
        return await self._call(
            "storage.fs.df",
            self._params(owner, bucket),
        )

    async def fs_mount(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_path: str,
        source_aid: str | None = None,
        source_path: str | None = None,
        readonly: bool = True,
        expires_at: int | None = None,
        source_bucket: str | None = None,
        require_approval: bool = False,
        volume_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.mount",
            self._params(
                owner,
                bucket,
                mount_path=mount_path,
                source_aid=source_aid,
                source_path=source_path,
                readonly=readonly,
                expires_at=expires_at,
                source_bucket=source_bucket,
                require_approval=require_approval,
                volume_id=volume_id,
            ),
            path=mount_path,
        )

    async def fs_approve(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_path: str | None = None,
        mount_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.approve",
            self._params(owner, bucket, mount_path=mount_path, mount_id=mount_id, request_id=request_id),
            path=mount_path or mount_id or request_id or "",
        )

    async def fs_reject(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_path: str | None = None,
        mount_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.reject",
            self._params(owner, bucket, mount_path=mount_path, mount_id=mount_id, request_id=request_id),
            path=mount_path or mount_id or request_id or "",
        )

    async def fs_unmount(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        mount_path: str,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.unmount",
            self._params(owner, bucket, mount_path=mount_path),
            path=mount_path,
        )

    async def fs_invalidate_membership(
        self,
        *,
        group_id: str,
        group_owner_aid: str,
        member_aid: str | None = None,
        reason: str = "membership_changed",
        status: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.fs.invalidate_membership",
            {
                key: value
                for key, value in {
                    "group_id": group_id,
                    "group_owner_aid": group_owner_aid,
                    "member_aid": member_aid,
                    "reason": reason,
                    "status": status,
                }.items()
                if value is not None
            },
        )

    async def volume_create(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        volume_id: str | None = None,
        size_bytes: int,
        mount_point: str | None = None,
        expires_at: int | None = None,
        used_bytes: int | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.volume.create",
            self._params(
                owner,
                bucket,
                volume_id=volume_id,
                size_bytes=size_bytes,
                mount_point=mount_point,
                expires_at=expires_at,
                used_bytes=used_bytes,
                status=status,
            ),
        )

    async def volume_renew(
        self,
        *,
        volume_id: str,
        owner: str | None = None,
        bucket: str = "default",
        expires_at: int,
        status: str | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.volume.renew",
            self._params(owner, bucket, volume_id=volume_id, expires_at=expires_at, status=status),
        )

    async def volume_expire_due(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        now: int | None = None,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.volume.expire_due",
            self._params(owner, bucket, now=now),
        )

    async def resolve_path(
        self,
        *,
        owner: str | None = None,
        bucket: str = "default",
        path: str,
        expected_type: str = "any",
        follow_symlinks: bool = True,
    ) -> dict[str, Any]:
        return await self._call(
            "storage.resolve_path",
            self._params(owner, bucket, path=path, expected_type=expected_type, follow_symlinks=follow_symlinks),
            path=path,
        )
