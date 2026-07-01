from __future__ import annotations

from typing import Any

from .validators import validate_group_id_format


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

    async def get_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取群公告（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")

        result = await self.get_settings(
            group_id=group_id,
            keys=["announcement.content", "announcement.attachments"],
        )

        settings = self._settings_to_map(result)
        return {
            "group_id": result["group_id"],
            "announcement": {
                "group_id": result["group_id"],
                "content": settings.get("announcement.content", ""),
                "attachments": settings.get("announcement.attachments", []),
                "updated_by": settings.get("announcement.content.updated_by", ""),
                "updated_at": settings.get("announcement.content.updated_at", 0)
            }
        }

    async def update_announcement(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：更新群公告（基于 set_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        content = merged.get("content")
        attachments = merged.get("attachments")

        if not group_id:
            raise ValueError("group_id is required")
        if content is None:
            raise ValueError("content is required")

        settings_update = {"announcement.content": content}
        if attachments is not None:
            settings_update["announcement.attachments"] = attachments

        result = await self.set_settings(group_id=group_id, settings=settings_update)

        return {
            "group_id": result["group_id"],
            "announcement": {
                "group_id": result["group_id"],
                "content": content,
                "attachments": attachments or []
            }
        }

    async def get_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取群规则（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")

        result = await self.get_settings(
            group_id=group_id,
            keys=["rules.content", "rules.attachments"],
        )

        settings = self._settings_to_map(result)
        return {
            "group_id": result["group_id"],
            "rules": {
                "group_id": result["group_id"],
                "content": settings.get("rules.content", ""),
                "attachments": settings.get("rules.attachments", []),
                "updated_by": settings.get("rules.content.updated_by", ""),
                "updated_at": settings.get("rules.content.updated_at", 0)
            }
        }

    async def update_rules(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：更新群规则（基于 set_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        content = merged.get("content")
        attachments = merged.get("attachments")

        if not group_id:
            raise ValueError("group_id is required")
        if content is None:
            raise ValueError("content is required")

        settings_update = {"rules.content": content}
        if attachments is not None:
            settings_update["rules.attachments"] = attachments

        result = await self.set_settings(group_id=group_id, settings=settings_update)

        return {
            "group_id": result["group_id"],
            "rules": {
                "group_id": result["group_id"],
                "content": content,
                "attachments": attachments or []
            }
        }

    async def get_join_requirements(self, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """便利方法：获取入群要求（基于 get_settings）"""
        merged = self._params(params, **kwargs)
        group_id = merged.get("group_id")
        if not group_id:
            raise ValueError("group_id is required")

        result = await self.get_settings(
            group_id=group_id,
            keys=["join.mode", "join.question", "join.auto_approve_patterns", "join.max_pending"],
        )

        settings = self._settings_to_map(result)
        return {
            "group_id": result["group_id"],
            "join_requirements": {
                "group_id": result["group_id"],
                "mode": settings.get("join.mode", "open"),
                "question": settings.get("join.question", ""),
                "auto_approve_patterns": settings.get("join.auto_approve_patterns", []),
                "max_pending": settings.get("join.max_pending", 100),
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

        if not settings_update:
            raise ValueError("at least one field to update is required")

        result = await self.set_settings(group_id=group_id, settings=settings_update)

        return {
            "group_id": result["group_id"],
            "join_requirements": {
                "group_id": result["group_id"],
                "mode": merged.get("mode"),
                "question": merged.get("question"),
                "auto_approve_patterns": merged.get("auto_approve_patterns"),
                "max_pending": merged.get("max_pending")
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
