from __future__ import annotations

import asyncio
import time
from typing import Any


class GroupPendingOpsPartialFailure(RuntimeError):
    """pending_ops 部分 storage op 已成功但 confirm 前失败。"""

    def __init__(
        self,
        message: str,
        *,
        failed_index: int,
        failed_op: dict[str, Any] | None,
        storage_results: dict[str, Any],
        op_results: list[Any],
        compensation_results: dict[str, Any],
        compensation_errors: list[dict[str, Any]],
        cause: BaseException,
    ) -> None:
        super().__init__(message)
        self.failed_index = failed_index
        self.failed_op = failed_op or {}
        self.storage_results = storage_results
        self.op_results = op_results
        self.compensation_results = compensation_results
        self.compensation_errors = compensation_errors
        self.__cause__ = cause

    def to_dict(self) -> dict[str, Any]:
        return {
            "failed_index": self.failed_index,
            "failed_op": self.failed_op,
            "storage_results": self.storage_results,
            "op_results": self.op_results,
            "compensation_results": self.compensation_results,
            "compensation_errors": self.compensation_errors,
        }


class _RpcFacade:
    def __init__(self, client: Any, prefix: str) -> None:
        self._client = client
        self._prefix = prefix

    @staticmethod
    def _params(params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update(kwargs)
        return {key: value for key, value in merged.items() if value is not None}

    async def _call(self, method_name: str, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._client.call(f"{self._prefix}.{method_name}", self._params(params, **kwargs))


class ThoughtFacade(_RpcFacade):
    async def put(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("put", params, **kwargs)

    async def get(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get", params, **kwargs)


class MessageFacade(_RpcFacade):
    def __init__(self, client: Any) -> None:
        super().__init__(client, "message")
        self.thought = ThoughtFacade(client, "message.thought")

    async def send(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("send", params, **kwargs)

    async def pull(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("pull", params, **kwargs)

    async def ack(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ack", params, **kwargs)

    async def recall(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("recall", params, **kwargs)

    async def query_online(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("query_online", params, **kwargs)


class GroupResourcesFacade(_RpcFacade):
    BASELINE_PATHS = ("announce", "public", "archive", "memberdata")
    GROUP_AID_CACHE_TTL_SECONDS = 30

    def __init__(self, client: Any) -> None:
        super().__init__(client, "group.resources")
        self._group_aid_cache: dict[str, tuple[str, float]] = {}

    def _self_aid(self) -> str:
        current = getattr(self._client, "current_aid", None)
        aid = (
            getattr(current, "aid", None)
            or getattr(self._client, "aid", None)
            or getattr(self._client, "_aid", None)
        )
        return str(aid or "").strip()

    def _ensure_can_sign_as(self, sign_as: str, *, aid_store: Any | None, operation: str) -> None:
        signer = str(sign_as or "").strip()
        if not signer:
            return
        if self._self_aid().lower() == signer.lower():
            return
        if aid_store is None:
            raise ValueError(f"{operation} requires aid_store to sign as {signer}")

    @classmethod
    def _folder_id_from_result(cls, result: Any, *, _depth: int = 0) -> str:
        if _depth > 16:
            raise ValueError("folder result nesting too deep")
        if not isinstance(result, dict):
            return ""
        for key in ("folder_id", "node_id", "resource_id", "object_id", "id"):
            value = str(result.get(key) or "").strip()
            if value:
                return value
        return cls._folder_id_from_result(result.get("node"), _depth=_depth + 1)

    async def _memberdata_namespace_key(self, params: dict[str, Any]) -> Any:
        explicit = params.get("group_aid") or params.get("groupAid")
        if explicit:
            return explicit
        group_id = str(params.get("group_id") or params.get("groupId") or "").strip()
        if not group_id:
            return ""
        cached = self._group_aid_cache.get(group_id)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0]
        result = None
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                result = await self._client.call("group.get", {"group_id": group_id})
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if not self._is_retryable_lookup_error(exc) or attempt == 2:
                    break
                await asyncio.sleep(0.05 * (2 ** attempt))
        if last_exc is not None:
            raise RuntimeError(f"memberdata namespace group_aid lookup failed for {group_id}") from last_exc
        group = result.get("group") if isinstance(result, dict) else None
        group_aid = str(group.get("group_aid") or "").strip() if isinstance(group, dict) else ""
        if not group_aid:
            raise RuntimeError(f"memberdata namespace group_aid missing for {group_id}")
        self._group_aid_cache[group_id] = (group_aid, now + self.GROUP_AID_CACHE_TTL_SECONDS)
        return group_aid

    @staticmethod
    def _is_retryable_lookup_error(exc: BaseException) -> bool:
        code = str(getattr(exc, "code", "") or "").lower()
        message = str(exc).lower()
        retry_markers = ("timeout", "timed out", "temporarily", "connection", "network", "econn", "unavailable")
        return code in {"timeout", "etimedout", "econnreset", "econnrefused", "eunavailable"} or any(
            marker in message for marker in retry_markers
        )

    def _resolve_memberdata_target(self, group_key: Any, resource_path: Any) -> tuple[str, str] | None:
        """成员挂载区透明路由：memberdata/{self_aid}/{rest} → 成员自己 storage 空间。

        协议约定（group-storage 设计 §4.4/§5.3）：成员挂载区的源固定指向成员自己空间
        的 {self_aid}/{group_aid}/{rest}。命中本人槽位时返回
        (owner_aid=self_aid, object_key={self_aid}/{group_aid}/{rest})；
        他人槽位或群自有区返回 None（不路由，由调用方走原 group.resources 流程）。
        """
        path = str(resource_path or "").strip().strip("/")
        parts = path.split("/")
        if len(parts) < 2 or parts[0].lower() != "memberdata":
            return None
        slot_aid = parts[1].strip()
        self_aid = self._self_aid()
        if not self_aid or slot_aid.lower() != self_aid.lower():
            return None
        namespace_key = str(group_key or "").strip().strip("/")
        if not namespace_key:
            return None
        rest = "/".join(parts[2:]).strip("/")
        source_root = f"{self_aid}/{namespace_key}"
        object_key = f"{source_root}/{rest}" if rest else source_root
        return self_aid, object_key

    def _is_memberdata_self_path(self, resource_path: Any) -> bool:
        path = str(resource_path or "").strip().strip("/")
        parts = path.split("/")
        if len(parts) < 2 or parts[0].lower() != "memberdata":
            return False
        self_aid = self._self_aid()
        return bool(self_aid and parts[1].strip().lower() == self_aid.lower())

    async def _resolve_memberdata_target_for_params(self, params: dict[str, Any]) -> tuple[str, str] | None:
        if not self._is_memberdata_self_path(params.get("resource_path")):
            return None
        return self._resolve_memberdata_target(await self._memberdata_namespace_key(params), params.get("resource_path"))

    async def put(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        target = await self._resolve_memberdata_target_for_params(merged)
        if target is not None:
            owner_aid, object_key = target
            storage_params: dict[str, Any] = {
                "owner_aid": owner_aid,
                "object_key": object_key,
                "content": merged.get("content", ""),
                "overwrite": merged.get("overwrite", False),
            }
            for src, dst in (("content_type", "content_type"), ("content_encoding", "content_encoding"),
                             ("metadata", "metadata"), ("expected_version", "expected_version")):
                if merged.get(src) is not None:
                    storage_params[dst] = merged.get(src)
            return await self._client.call("storage.put_object", storage_params)
        return await self._call("put", merged)

    async def create_folder(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        target = await self._resolve_memberdata_target_for_params(merged)
        if target is not None:
            owner_aid, path = target
            return await self._client.call("storage.fs.mkdir", {
                "owner_aid": owner_aid,
                "path": path,
                "parents": bool(merged.get("mkdirs", merged.get("parents", True))),
            })
        return await self._call("create_folder", merged)

    async def list_children(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list_children", params, **kwargs)

    async def rename(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("rename", params, **kwargs)

    async def move(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("move", params, **kwargs)

    async def mount_object(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("mount_object", params, **kwargs)

    async def unmount(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("unmount", params, **kwargs)

    async def resolve_path(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("resolve_path", params, **kwargs)

    async def get(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get", params, **kwargs)

    async def list(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list", params, **kwargs)

    async def update(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("update", params, **kwargs)

    async def get_access(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_access", params, **kwargs)

    async def resolve_access_ticket(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("resolve_access_ticket", params, **kwargs)

    async def delete(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        target = await self._resolve_memberdata_target_for_params(merged)
        if target is not None:
            owner_aid, path = target
            recursive = bool(merged.get("recursive", False))
            # memberdata 下既可能是文件也可能是目录：目录走 fs.remove(recursive)，
            # 文件走 delete_object。统一用 fs.remove（服务端对文件/目录均支持）。
            return await self._client.call("storage.fs.remove", {
                "owner_aid": owner_aid,
                "path": path,
                "recursive": recursive,
            })
        return await self._call("delete", merged)

    async def namespace_ready(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("namespace_ready", params, **kwargs)

    async def confirm(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("confirm", params, **kwargs)

    async def confirm_mount(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("confirm_mount", params, **kwargs)

    async def get_df(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_df", params, **kwargs)

    async def initialize_namespace(
        self,
        params: dict[str, Any] | None = None,
        *,
        group_id: str | None = None,
        group_aid: str | None = None,
        bucket: str = "default",
        paths: list[str] | tuple[str, ...] | None = None,
        aid_store: Any | None = None,
        connect_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        merged = self._params(params, **kwargs)
        if group_id is not None:
            merged["group_id"] = group_id
        if group_aid is not None:
            merged["group_aid"] = group_aid
        merged.setdefault("bucket", bucket or "default")
        gid = str(merged.get("group_id") or "").strip()
        gaid = str(merged.get("group_aid") or "").strip()
        if not gid:
            raise ValueError("initialize_namespace requires group_id")
        if not gaid:
            raise ValueError("initialize_namespace requires group_aid")
        raw_paths: Any = paths
        if raw_paths is None:
            for key in ("paths", "baseline_dirs", "baselineDirs", "directories", "dirs"):
                if key in merged:
                    raw_paths = merged.get(key)
                    break
        if raw_paths is None:
            selected_paths = tuple(self.BASELINE_PATHS)
        elif isinstance(raw_paths, (list, tuple)):
            cleaned_paths = tuple(str(item or "").strip().strip("/") for item in raw_paths)
            selected_paths = tuple(item for item in cleaned_paths if item) or tuple(self.BASELINE_PATHS)
        else:
            selected_paths = tuple(self.BASELINE_PATHS)
        folder_ids: dict[str, str] = {}
        signer = None
        self._ensure_can_sign_as(gaid, aid_store=aid_store, operation="initialize_namespace")
        if aid_store is not None:
            loaded = aid_store.load(gaid)
            if not getattr(loaded, "ok", False) or not getattr(loaded, "data", None):
                error = getattr(loaded, "error", None)
                message = getattr(error, "message", None) or f"group identity not found: {gaid}"
                raise ValueError(message)
            aid_obj = loaded.data.get("aid") if isinstance(loaded.data, dict) else None
            if aid_obj is None:
                raise ValueError(f"group identity missing AID object: {gaid}")
            from .client import AUNClient

            signer = AUNClient(aid_obj)
            await signer.connect(connect_options or {"heartbeat_interval": 0})
        try:
            for path in selected_paths:
                normalized_path = str(path or "").strip().strip("/")
                if not normalized_path:
                    continue
                mkdir_params = {
                    "owner_aid": gaid,
                    "bucket": str(merged.get("bucket") or "default"),
                    "path": normalized_path,
                    "parents": True,
                }
                if signer is None:
                    result = await self._client.call("storage.fs.mkdir", mkdir_params)
                else:
                    result = await signer.call("storage.fs.mkdir", mkdir_params)
                folder_id = self._folder_id_from_result(result)
                if folder_id:
                    folder_ids[normalized_path] = folder_id
            if "public" in selected_paths:
                visibility_params = {
                    "owner_aid": gaid,
                    "bucket": str(merged.get("bucket") or "default"),
                    "path": "public",
                    "visibility": "public",
                }
                if signer is None:
                    await self._client.call("storage.set_visibility", visibility_params)
                else:
                    await signer.call("storage.set_visibility", visibility_params)
            ready_params = {"group_id": gid, "group_aid": gaid, "folder_ids": folder_ids}
            if signer is None:
                return await self.namespace_ready(ready_params)
            return await signer.call("group.resources.namespace_ready", ready_params)
        finally:
            if signer is not None:
                await signer.close()

    async def execute_pending_ops(
        self,
        pending: dict[str, Any],
        *,
        aid_store: Any | None = None,
        connect_options: dict[str, Any] | None = None,
        sign_as: str | None = None,
        upload_data: bytes | bytearray | memoryview | Any | None = None,
    ) -> dict[str, Any]:
        if not isinstance(pending, dict):
            raise TypeError("pending must be a dict")
        ops = pending.get("pending_ops") or []
        if not isinstance(ops, list):
            raise ValueError("pending_ops must be a list")
        signer_clients: dict[str, Any] = {}
        default_sign_as = str(
            sign_as
            or pending.get("sign_as")
            or pending.get("signAs")
            or pending.get("group_aid")
            or pending.get("groupAid")
            or ""
        ).strip()
        allowed_pending_rpcs = {
            "storage.put_object",
            "storage.create_upload_session",
            "storage.complete_upload",
            "storage.http_put",
            "storage.delete_object",
            "storage.fs.mkdir",
            "storage.fs.rename",
            "storage.fs.remove",
            "storage.fs.mount",
            "storage.fs.unmount",
            "storage.issue_token",
            "storage.revoke_token",
            "storage.set_acl",
            "storage.remove_acl",
            "storage.set_visibility",
        }
        allowed_confirm_rpcs = {"group.resources.confirm", "group.resources.confirm_mount"}
        allowed_compensation_rpcs = {
            "storage.delete_object",
            "storage.fs.remove",
            "storage.fs.unmount",
            "storage.revoke_token",
            "storage.remove_acl",
            "storage.set_acl",
        }

        async def _call_rpc(rpc: str, params: dict[str, Any], sign_as: str) -> Any:
            if not sign_as:
                return await self._client.call(rpc, params)
            current = getattr(self._client, "current_aid", None)
            current_aid = (
                getattr(current, "aid", None)
                or getattr(self._client, "aid", None)
                or getattr(self._client, "_aid", None)
            )
            if str(current_aid or "").strip().lower() == sign_as.lower():
                return await self._client.call(rpc, params)
            if aid_store is None:
                raise ValueError(f"execute_pending_ops requires aid_store to sign as {sign_as}")
            signer = signer_clients.get(sign_as)
            if signer is None:
                loaded = aid_store.load(sign_as)
                if not getattr(loaded, "ok", False) or not getattr(loaded, "data", None):
                    error = getattr(loaded, "error", None)
                    message = getattr(error, "message", None) or f"signer identity not found: {sign_as}"
                    raise ValueError(message)
                aid_obj = loaded.data.get("aid") if isinstance(loaded.data, dict) else None
                if aid_obj is None:
                    raise ValueError(f"signer identity missing AID object: {sign_as}")
                from .client import AUNClient

                signer = AUNClient(aid_obj)
                await signer.connect(connect_options or {"heartbeat_interval": 0})
                signer_clients[sign_as] = signer
            return await signer.call(rpc, params)

        def _result_path_value(source: Any, path: str) -> Any:
            current = source
            for part in str(path or "").split("."):
                if not part:
                    continue
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit():
                    index = int(part)
                    current = current[index] if 0 <= index < len(current) else None
                else:
                    current = getattr(current, part, None)
                if current is None:
                    return None
            return current

        def _apply_result_mappings(params: dict[str, Any], op: dict[str, Any]) -> dict[str, Any]:
            mappings = op.get("params_from_results") or op.get("paramsFromResults") or {}
            if not isinstance(mappings, dict):
                return params
            result_context = {
                **storage_results,
                "results": storage_results,
                "storage_results": storage_results,
                "op_results": op_results,
            }
            for param_key, result_path in mappings.items():
                value = _result_path_value(result_context, str(result_path or ""))
                if value is not None:
                    params[str(param_key)] = value
            return params

        async def _http_put(params: dict[str, Any]) -> dict[str, Any]:
            upload_url = str(params.get("upload_url") or params.get("url") or "").strip()
            if not upload_url:
                raise ValueError("storage.http_put requires upload_url")
            data_ref = str(params.get("data_ref") or "upload_data").strip() or "upload_data"
            payload = params.get("data")
            if payload is None and data_ref == "upload_data":
                payload = upload_data
            if hasattr(payload, "read"):
                payload = payload.read()
            if isinstance(payload, memoryview):
                payload = payload.tobytes()
            if isinstance(payload, bytearray):
                payload = bytes(payload)
            if not isinstance(payload, bytes):
                raise ValueError("storage.http_put requires upload_data bytes")
            headers = dict(params.get("headers") or {}) if isinstance(params.get("headers"), dict) else {}
            content_type = str(params.get("content_type") or params.get("contentType") or "").strip()
            if content_type:
                headers.setdefault("Content-Type", content_type)
            putter = getattr(self._client, "http_put", None)
            if callable(putter):
                result = await putter(upload_url, payload, headers=headers)
            else:
                from .storage.lowlevel import StorageLowLevel

                await StorageLowLevel(self._client).http_put(upload_url, payload, headers=headers)
                result = None
            if isinstance(result, dict):
                base = dict(result)
            else:
                base = {"status": int(result)} if isinstance(result, int) else {"status": 200}
            base.setdefault("upload_url", upload_url)
            base.setdefault("size_bytes", len(payload))
            return base

        def _validate_rpc_plan() -> None:
            confirm_rpc = str(pending.get("confirm_rpc") or "group.resources.confirm").strip()
            if confirm_rpc not in allowed_confirm_rpcs:
                raise ValueError(f"unsupported confirm rpc: {confirm_rpc}")
            for op in ops:
                if not isinstance(op, dict):
                    raise ValueError("pending op must be an object")
                rpc = str(op.get("rpc") or op.get("method") or "").strip()
                if not rpc:
                    raise ValueError("pending op missing rpc")
                if rpc not in allowed_pending_rpcs:
                    raise ValueError(f"unsupported pending rpc: {rpc}")
                compensation = op.get("compensation")
                if isinstance(compensation, dict):
                    comp_rpc = str(compensation.get("rpc") or compensation.get("method") or "").strip()
                    if comp_rpc and comp_rpc not in allowed_compensation_rpcs:
                        raise ValueError(f"unsupported compensation rpc: {comp_rpc}")

        _validate_rpc_plan()

        async def _run_compensations(
            successful_ops: list[dict[str, Any]],
            storage_results: dict[str, Any],
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            if str(pending.get("failure_policy") or pending.get("failurePolicy") or "").strip() != "compensate_successful_ops_before_confirm":
                return {}, []
            compensation_results: dict[str, Any] = {}
            compensation_errors: list[dict[str, Any]] = []
            for item in reversed(successful_ops):
                op = item.get("op") or {}
                key = str(item.get("confirm_key") or "").strip()
                compensation = op.get("compensation")
                if not isinstance(compensation, dict):
                    continue
                depends_on = str(compensation.get("depends_on") or compensation.get("dependsOn") or key).strip()
                if depends_on and depends_on not in storage_results:
                    continue
                params = dict(compensation.get("params") or {})
                mappings = compensation.get("params_from_results") or compensation.get("paramsFromResults") or {}
                if isinstance(mappings, dict):
                    result_context = {
                        **storage_results,
                        "results": storage_results,
                        "storage_results": storage_results,
                        "op_results": op_results,
                    }
                    for param_key, result_path in mappings.items():
                        value = _result_path_value(result_context, str(result_path or ""))
                        if value is not None:
                            params[str(param_key)] = value
                rpc = str(compensation.get("rpc") or compensation.get("method") or "").strip()
                if not rpc:
                    continue
                if rpc not in allowed_compensation_rpcs:
                    raise ValueError(f"unsupported compensation rpc: {rpc}")
                comp_sign_as = str(
                    compensation.get("sign_as")
                    or compensation.get("signAs")
                    or op.get("sign_as")
                    or op.get("signAs")
                    or default_sign_as
                    or ""
                ).strip()
                comp_key = str(compensation.get("confirm_key") or compensation.get("confirmKey") or f"compensate:{key}").strip()
                try:
                    compensation_results[comp_key] = await _call_rpc(rpc, params, comp_sign_as)
                except Exception as exc:
                    compensation_errors.append({
                        "confirm_key": comp_key,
                        "rpc": rpc,
                        "error": str(exc),
                    })
            return compensation_results, compensation_errors

        storage_results: dict[str, Any] = {}
        op_results: list[Any] = []
        successful_ops: list[dict[str, Any]] = []
        last_key = ""
        last_result: Any = None
        try:
            for index, op in enumerate(ops):
                if not isinstance(op, dict):
                    raise ValueError("pending op must be an object")
                rpc = str(op.get("rpc") or "").strip()
                if not rpc:
                    raise ValueError("pending op missing rpc")
                if rpc not in allowed_pending_rpcs:
                    raise ValueError(f"unsupported pending rpc: {rpc}")
                params = dict(op.get("params") or {})
                params = _apply_result_mappings(params, op)
                if "data_ref" in op and "data_ref" not in params:
                    params["data_ref"] = op.get("data_ref")
                op_sign_as = str(op.get("sign_as") or op.get("signAs") or default_sign_as or "").strip()
                key = str(op.get("confirm_key") or f"op_{index}").strip()
                try:
                    if rpc == "storage.http_put":
                        result = await _http_put(params)
                    else:
                        result = await _call_rpc(rpc, params, op_sign_as)
                except Exception as exc:
                    compensation_results, compensation_errors = await _run_compensations(successful_ops, storage_results)
                    if not successful_ops and not compensation_results and not compensation_errors:
                        raise
                    raise GroupPendingOpsPartialFailure(
                        str(exc),
                        failed_index=index,
                        failed_op=op,
                        storage_results=storage_results,
                        op_results=op_results,
                        compensation_results=compensation_results,
                        compensation_errors=compensation_errors,
                        cause=exc,
                    ) from exc
                op_results.append(result)
                storage_results[key] = result
                successful_ops.append({"op": op, "confirm_key": key, "index": index})
                last_key = key
                last_result = result
            confirm_rpc = str(pending.get("confirm_rpc") or "group.resources.confirm").strip()
            if confirm_rpc not in allowed_confirm_rpcs:
                raise ValueError(f"unsupported confirm rpc: {confirm_rpc}")
            confirm_params = dict(pending.get("confirm_params") or {})
            if pending.get("group_id") is not None:
                confirm_params.setdefault("group_id", pending.get("group_id"))
            if pending.get("op_id") is not None:
                confirm_params.setdefault("op_id", pending.get("op_id"))
            confirm_params["storage_results"] = storage_results
            confirm_params["op_results"] = op_results
            if last_result is not None:
                confirm_params["storage_result"] = last_result
            if last_key:
                confirm_params.setdefault("confirm_key", last_key)
            confirm_sign_as = str(
                pending.get("confirm_sign_as")
                or pending.get("confirmSignAs")
                or default_sign_as
                or ""
            ).strip()
            try:
                confirmed = await _call_rpc(confirm_rpc, confirm_params, confirm_sign_as)
            except Exception as exc:
                # confirm 失败时触发补偿，避免 storage 操作已执行但 confirm 未确认的悬空状态
                compensation_results, compensation_errors = await _run_compensations(successful_ops, storage_results)
                raise GroupPendingOpsPartialFailure(
                    f"confirm failed: {exc}",
                    storage_results=storage_results,
                    op_results=op_results,
                    compensation_results=compensation_results,
                    compensation_errors=compensation_errors,
                    failed_index=len(ops),
                ) from exc
            return {
                "storage_results": storage_results,
                "confirmed": confirmed,
            }
        finally:
            for signer in signer_clients.values():
                close = getattr(signer, "close", None)
                if callable(close):
                    try:
                        await close()
                    except Exception as exc:
                        print(f"[aun-sdk] WARN: failed to close signer client: {exc}")


class GroupFacade(_RpcFacade):
    def __init__(self, client: Any) -> None:
        super().__init__(client, "group")
        self.resources = GroupResourcesFacade(client)
        self.thought = ThoughtFacade(client, "group.thought")

    async def create(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("create", params, **kwargs)

    async def bind_group_aid(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("bind_group_aid", params, **kwargs)

    async def bind_aid(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self.bind_group_aid(params, **kwargs)
 
    async def get(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get", params, **kwargs)

    async def get_info(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_info", params, **kwargs)

    async def update(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("update", params, **kwargs)

    async def list(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list", params, **kwargs)

    async def list_my(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list_my", params, **kwargs)

    async def search(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("search", params, **kwargs)

    async def get_public_info(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_public_info", params, **kwargs)

    async def suspend(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("suspend", params, **kwargs)

    async def resume(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("resume", params, **kwargs)

    async def dissolve(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("dissolve", params, **kwargs)

    async def get_stats(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_stats", params, **kwargs)

    async def add_member(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("add_member", params, **kwargs)

    async def get_members(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_members", params, **kwargs)

    async def check_membership(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("check_membership", params, **kwargs)

    async def kick(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("kick", params, **kwargs)

    async def leave(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("leave", params, **kwargs)

    async def set_role(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("set_role", params, **kwargs)

    async def transfer_owner(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("transfer_owner", params, **kwargs)

    async def complete_transfer(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("complete_transfer", params, **kwargs)

    async def ban(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ban", params, **kwargs)

    async def unban(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("unban", params, **kwargs)

    async def get_banlist(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_banlist", params, **kwargs)

    async def request_join(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("request_join", params, **kwargs)

    async def list_join_requests(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list_join_requests", params, **kwargs)

    async def review_join_request(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("review_join_request", params, **kwargs)

    async def batch_review_join_request(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("batch_review_join_request", params, **kwargs)

    async def create_invite_code(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("create_invite_code", params, **kwargs)

    async def list_invite_codes(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list_invite_codes", params, **kwargs)

    async def use_invite_code(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("use_invite_code", params, **kwargs)

    async def revoke_invite_code(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("revoke_invite_code", params, **kwargs)

    async def set_settings(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("set_settings", params, **kwargs)

    async def get_settings(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_settings", params, **kwargs)

    async def info(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("info", params, **kwargs)

    async def send(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("send", params, **kwargs)

    async def recall(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("recall", params, **kwargs)

    async def pull(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("pull", params, **kwargs)

    async def pull_events(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("pull_events", params, **kwargs)

    async def ack_messages(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ack_messages", params, **kwargs)

    async def ack_events(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ack_events", params, **kwargs)

    async def get_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_announcement", params, **kwargs)

    async def update_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("update_announcement", params, **kwargs)

    async def get_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_rules", params, **kwargs)

    async def update_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("update_rules", params, **kwargs)

    async def get_join_requirements(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_join_requirements", params, **kwargs)

    async def update_join_requirements(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("update_join_requirements", params, **kwargs)

    async def get_online_members(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_online_members", params, **kwargs)


class StreamFacade(_RpcFacade):
    def __init__(self, client: Any) -> None:
        super().__init__(client, "stream")

    async def create(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("create", params, **kwargs)

    async def close(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("close", params, **kwargs)

    async def get_info(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("get_info", params, **kwargs)

    async def list_active(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("list_active", params, **kwargs)


__all__ = [
    "GroupFacade",
    "GroupPendingOpsPartialFailure",
    "GroupResourcesFacade",
    "MessageFacade",
    "StreamFacade",
    "ThoughtFacade",
]
