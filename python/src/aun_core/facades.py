from __future__ import annotations

from typing import Any


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
    "MessageFacade",
    "StreamFacade",
    "ThoughtFacade",
]
