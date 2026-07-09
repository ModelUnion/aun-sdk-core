from __future__ import annotations

import re
import time
from typing import Any

from .group_index import GROUP_INDEX_KEY, parse_group_index, prepare_group_settings_with_index, verify_group_index
from .validators import validate_group_id_format

_INDEXED_DOCUMENT_SETTING_KEY_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_INDEXED_DOCUMENT_SETTING_RESERVED_BASES = {
    "join",
    "dispatch_mode",
    "duty",
    "e2ee",
    "group",
    "group_index",
    "index",
    "name",
    "description",
    "visibility",
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


class GroupFacade(_RpcFacade):
    def __init__(self, client: Any) -> None:
        super().__init__(client, "group")
        from .group_fs import GroupFSVFS

        self.fs = GroupFSVFS(client)
        self.thought = ThoughtFacade(client, "group.thought")

    async def create(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("create", params, **kwargs)

    async def bind_group_aid(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("bind_group_aid", params, **kwargs)

    async def renew_group_aid(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("renew_group_aid", params, **kwargs)

    async def bind_aid(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self.bind_group_aid(params, **kwargs)

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

    async def suspend(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("suspend", params, **kwargs)

    async def resume(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("resume", params, **kwargs)

    async def dissolve(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("dissolve", params, **kwargs)

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

    async def check_group_index(self, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        merged = self._params(params, **kwargs)
        group_aid = str(merged.get("group_aid") or merged.get("group_id") or "").strip()
        if not group_aid:
            raise ValueError("group_aid is required")
        stale_fn = getattr(self._client, "is_group_index_stale", None)
        meta_fn = getattr(self._client, "get_group_index_remote_meta", None)
        local_fn = getattr(self._client, "get_group_index_local_etag", None)
        stale = bool(stale_fn(group_aid)) if callable(stale_fn) else False
        remote_meta = meta_fn(group_aid) if callable(meta_fn) else None
        if not isinstance(remote_meta, dict):
            remote_meta = {}
        remote_etag = str(remote_meta.get("etag") or "")
        local_etag = str(local_fn(group_aid) if callable(local_fn) else "")
        local_found = bool(local_etag)
        remote_found = bool(remote_etag)
        in_sync = local_found and remote_found and local_etag == remote_etag
        return {
            "group_aid": group_aid,
            "local_found": local_found,
            "remote_found": remote_found,
            "local_etag": local_etag,
            "remote_etag": remote_etag,
            "in_sync": in_sync,
            "needs_update": bool(stale or (remote_found and not in_sync)),
            "last_modified": remote_meta.get("last_modified"),
            "status": 200 if remote_found else 404,
            "cached": True,
        }

    async def get_group_index(self, params: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        merged = self._params(params, **kwargs)
        group_id = str(merged.get("group_id") or "").strip()
        if not group_id:
            raise ValueError("group_id is required")
        result = await self.get_settings(group_id=group_id, keys=[GROUP_INDEX_KEY])
        group_aid = str(result.get("group_aid") or group_id)
        group_index = None
        for item in result.get("settings", []) or []:
            if item.get("key") == GROUP_INDEX_KEY:
                group_index = item.get("value")
                break
        if not group_index:
            return {"group_id": result["group_id"], "group_aid": group_aid, "group_index": None, "meta": {}, "entries": []}
        parsed = parse_group_index(group_index)
        await self._verify_group_index(group_index, parsed)
        etag = str(parsed["meta"].get("etag") or "")
        entries = parsed["entries"]
        settings_map = await self._hydrate_group_index_settings(group_id, group_aid, entries, etag, group_index=group_index)
        mark_fresh = getattr(self._client, "mark_group_index_fresh", None)
        if callable(mark_fresh) and etag:
            mark_fresh(group_aid, etag=etag)
        return {
            "group_id": result["group_id"],
            "group_aid": group_aid,
            "group_index": group_index,
            "meta": parsed["meta"],
            "entries": entries,
            "settings": settings_map,
        }

    async def _verify_group_index(self, group_index: Any, parsed: dict[str, Any]) -> None:
        signed_by = str((parsed.get("meta") or {}).get("signed_by") or "").strip()
        if not signed_by:
            raise ValueError("group.index signed_by is required")
        signer = None
        current = getattr(self._client, "current_aid", None)
        if current is not None and getattr(current, "aid", "") == signed_by:
            signer = current
        if signer is None:
            lookup_peer = getattr(self._client, "lookup_peer", None)
            if callable(lookup_peer):
                signer = await lookup_peer(signed_by)
        if signer is None:
            raise ValueError(f"group.index signer is unavailable: {signed_by}")
        verified = verify_group_index(group_index, signer)
        if not verified.ok:
            message = verified.error.message if verified.error else "group.index verification failed"
            raise ValueError(message)
        data = verified.data or {}
        if not data.get("valid"):
            raise ValueError(f"group.index verification failed: {data.get('reason') or 'invalid signature'}")

    async def update_group_index(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        group_id = str(merged.get("group_id") or "").strip()
        settings = merged.get("settings")
        if not group_id:
            raise ValueError("group_id is required")
        if not isinstance(settings, dict) or not settings:
            raise ValueError("settings must be a non-empty object")
        signer = merged.get("signer") or getattr(self._client, "current_aid", None)
        if signer is None:
            raise ValueError("signer is required")
        last_modified = int(merged.get("last_modified") or time.time() * 1000)
        max_attempts = max(1, int(merged.get("max_attempts") or 2))

        last_error = None
        for _attempt in range(max_attempts):
            current = await self.get_settings(group_id=group_id, keys=[GROUP_INDEX_KEY])
            group_aid = str(current.get("group_aid") or group_id)
            current_index = None
            expected_etag = ""
            for item in current.get("settings", []) or []:
                if item.get("key") == GROUP_INDEX_KEY:
                    current_index = item.get("value")
                    if current_index:
                        expected_etag = str(parse_group_index(current_index)["meta"].get("etag") or "")
                    break
            signed_settings = prepare_group_settings_with_index(
                group_aid=group_aid,
                settings=settings,
                signer=signer,
                last_modified=last_modified,
                base_index=current_index,
            )
            try:
                result = await self.set_settings(
                    group_id=group_id,
                    settings=signed_settings,
                    expected_index_etag=expected_etag,
                )
                pushed = parse_group_index(signed_settings[GROUP_INDEX_KEY])
                pushed_etag = str(pushed["meta"].get("etag") or "")
                mark_fresh = getattr(self._client, "mark_group_index_fresh", None)
                if callable(mark_fresh) and pushed_etag:
                    mark_fresh(group_aid, etag=pushed_etag)
                cache_settings = getattr(self._client, "cache_group_index_settings", None)
                if callable(cache_settings):
                    cache_settings(group_aid, settings, entries=pushed["entries"], etag=pushed_etag, group_index=signed_settings[GROUP_INDEX_KEY])
                return result
            except Exception as exc:
                if "etag conflict" not in str(exc):
                    raise
                last_error = exc
        if last_error is not None:
            raise last_error
        raise RuntimeError("update_group_index failed")

    @staticmethod
    def _index_update_params(group_id: Any, settings: dict[str, Any], merged: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"group_id": group_id, "settings": settings}
        for key in ("signer", "last_modified", "max_attempts"):
            if key in merged:
                out[key] = merged[key]
        return out

    async def send(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        validate_group_id_format(merged.get("group_id"))
        return await self._call("send", merged)

    async def recall(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("recall", params, **kwargs)

    async def pull(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        merged = self._params(params, **kwargs)
        validate_group_id_format(merged.get("group_id"))
        return await self._call("pull", merged)

    async def pull_events(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("pull_events", params, **kwargs)

    async def ack_messages(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ack_messages", params, **kwargs)

    async def ack_events(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return await self._call("ack_events", params, **kwargs)

    @staticmethod
    def _settings_to_map(result: dict[str, Any]) -> dict[str, Any]:
        """将 get_settings 返回的 settings 数组转为 {key: value} 映射"""
        return {s["key"]: s["value"] for s in result.get("settings", [])}

    async def _hydrate_group_index_settings(
        self,
        group_id: str,
        group_aid: str,
        entries: list[dict[str, Any]],
        etag: str,
        group_index: Any | None = None,
    ) -> dict[str, Any]:
        keys = [
            str(item.get("key") or "")
            for item in entries
            if str(item.get("source") or "db") == "db" and str(item.get("key") or "")
        ]
        if not keys:
            return {}
        cached: dict[str, Any] = {}
        missing = list(keys)
        cache_by_entries = getattr(self._client, "get_group_index_cached_settings_by_entries", None)
        if callable(cache_by_entries):
            maybe = cache_by_entries(group_aid, keys, entries)
            if isinstance(maybe, tuple) and len(maybe) == 2:
                cached, missing = dict(maybe[0] or {}), [str(item) for item in maybe[1] or []]
            elif isinstance(maybe, dict):
                cached = dict(maybe.get("cached") or {})
                missing = [str(item) for item in maybe.get("missing") or []]
        fetched: dict[str, Any] = {}
        if missing:
            result = await self.get_settings(group_id=group_id, keys=missing)
            fetched = self._settings_to_map(result)
        settings = {**cached, **fetched}
        cache_settings = getattr(self._client, "cache_group_index_settings", None)
        if callable(cache_settings):
            cache_settings(group_aid, settings, entries=entries, etag=etag, group_index=group_index)
        return settings

    async def _get_indexed_settings(self, group_id: str, keys: list[str]) -> tuple[str, dict[str, Any]]:
        cached_fn = getattr(self._client, "get_group_index_cached_settings", None)
        if callable(cached_fn):
            cached = cached_fn(group_id, keys)
            if isinstance(cached, dict):
                return group_id, cached
        result = await self.get_settings(group_id=group_id, keys=keys)
        group_aid = str(result.get("group_aid") or group_id)
        settings = self._settings_to_map(result)
        cache_settings = getattr(self._client, "cache_group_index_settings", None)
        if callable(cache_settings):
            cache_settings(group_aid, settings)
            if group_aid != str(group_id):
                cache_settings(str(group_id), settings)
        return str(result.get("group_id") or group_id), settings

    @staticmethod
    def _indexed_document_key_name(merged: dict[str, Any]) -> str:
        raw = merged["key_name"] if "key_name" in merged else merged.get("keyName")
        key_name = str(raw or "").strip()
        if (
            not key_name
            or key_name.lower() in _INDEXED_DOCUMENT_SETTING_RESERVED_BASES
            or not _INDEXED_DOCUMENT_SETTING_KEY_NAME_RE.fullmatch(key_name)
        ):
            raise ValueError("key_name must match ^[A-Za-z][A-Za-z0-9_-]{0,63}$")
        return key_name

    @staticmethod
    def _document_setting_result(
        *,
        group_id: str,
        key_name: str,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        content_key = f"{key_name}.content"
        attachments_key = f"{key_name}.attachments"
        return {
            "group_id": group_id,
            "setting": {
                "group_id": group_id,
                "key_name": key_name,
                "content": settings.get(content_key, ""),
                "attachments": settings.get(attachments_key, []),
                "updated_by": settings.get(f"{content_key}.updated_by", ""),
                "updated_at": settings.get(f"{content_key}.updated_at", 0),
            },
        }

    async def get_setting_with_index(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """获取文档型 indexed setting（{key_name}.content / {key_name}.attachments）。"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")
        key_name = self._indexed_document_key_name(merged)
        result_group_id, settings = await self._get_indexed_settings(
            str(group_id),
            [f"{key_name}.content", f"{key_name}.attachments"],
        )
        return self._document_setting_result(group_id=result_group_id, key_name=key_name, settings=settings)

    async def update_setting_with_index(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """更新文档型 indexed setting，并通过 group.index CAS 传播。"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")
        key_name = self._indexed_document_key_name(merged)
        if "content" not in merged:
            raise ValueError("content is required")
        content = merged["content"]
        settings_update = {f"{key_name}.content": content}
        attachments = merged.get("attachments", [])
        if "attachments" in merged:
            settings_update[f"{key_name}.attachments"] = attachments

        result = await self.update_group_index(self._index_update_params(group_id, settings_update, merged))
        result_group_id = str(result.get("group_id") or group_id)
        return {
            "group_id": result_group_id,
            "setting": {
                "group_id": result_group_id,
                "key_name": key_name,
                "content": content,
                "attachments": attachments,
                "updated_by": "",
                "updated_at": 0,
            },
        }

    async def get_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取群公告（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        merged["key_name"] = "announcement"
        result = await self.get_setting_with_index(merged)
        setting = result["setting"]
        return {
            "group_id": result["group_id"],
            "announcement": {
                "group_id": setting["group_id"],
                "content": setting["content"],
                "attachments": setting["attachments"],
                "updated_by": setting["updated_by"],
                "updated_at": setting["updated_at"],
            }
        }

    async def update_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：更新群公告（基于 set_settings）"""
        merged = self._params(params, **kwargs)
        merged["key_name"] = "announcement"
        result = await self.update_setting_with_index(merged)
        setting = result["setting"]
        return {
            "group_id": result["group_id"],
            "announcement": {
                "group_id": result["group_id"],
                "content": setting["content"],
                "attachments": setting["attachments"],
            }
        }

    async def get_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取群规则（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        merged["key_name"] = "rules"
        result = await self.get_setting_with_index(merged)
        setting = result["setting"]
        return {
            "group_id": result["group_id"],
            "rules": {
                "group_id": setting["group_id"],
                "content": setting["content"],
                "attachments": setting["attachments"],
                "updated_by": setting["updated_by"],
                "updated_at": setting["updated_at"],
            }
        }

    async def update_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：更新群规则（基于 set_settings）"""
        merged = self._params(params, **kwargs)
        merged["key_name"] = "rules"
        result = await self.update_setting_with_index(merged)
        setting = result["setting"]
        return {
            "group_id": result["group_id"],
            "rules": {
                "group_id": result["group_id"],
                "content": setting["content"],
                "attachments": setting["attachments"],
            }
        }

    async def get_join_requirements(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取入群要求（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")

        result_group_id, settings = await self._get_indexed_settings(
            str(group_id),
            ["join.mode", "join.question", "join.auto_approve_patterns", "join.max_pending", "join.attachments"],
        )
        return {
            "group_id": result_group_id,
            "join_requirements": {
                "group_id": result_group_id,
                "mode": settings.get("join.mode", "open"),
                "question": settings.get("join.question", ""),
                "auto_approve_patterns": settings.get("join.auto_approve_patterns", []),
                "max_pending": settings.get("join.max_pending", 100),
                "attachments": settings.get("join.attachments", []),
                "updated_by": settings.get("join.mode.updated_by", ""),
                "updated_at": settings.get("join.mode.updated_at", 0)
            }
        }

    async def update_join_requirements(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：更新入群要求（基于 set_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")

        if not group_id:
            raise ValueError("group_id is required")

        settings_update = {}
        if "mode" in merged:
            settings_update["join.mode"] = merged["mode"]
        if "question" in merged:
            settings_update["join.question"] = merged["question"]
        if "auto_approve_patterns" in merged:
            settings_update["join.auto_approve_patterns"] = merged["auto_approve_patterns"]
        if "max_pending" in merged:
            settings_update["join.max_pending"] = merged["max_pending"]
        if "attachments" in merged:
            settings_update["join.attachments"] = merged["attachments"]

        if not settings_update:
            raise ValueError("at least one field to update is required")

        result = await self.update_group_index(self._index_update_params(group_id, settings_update, merged))

        return {
            "group_id": result["group_id"],
            "join_requirements": {
                "group_id": result["group_id"],
                "mode": merged.get("mode"),
                "question": merged.get("question"),
                "auto_approve_patterns": merged.get("auto_approve_patterns"),
                "max_pending": merged.get("max_pending"),
                "attachments": merged.get("attachments", [])
            }
        }

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
    "MessageFacade",
    "StreamFacade",
    "ThoughtFacade",
]
