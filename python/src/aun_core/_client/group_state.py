from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from typing import Any

from ..group_id import normalize_group_id
from .runtime import ClientRuntime


def _group_cache_ids(raw_group_id: Any, group_aid: str) -> list[str]:
    ids: list[str] = []
    for value in (group_aid, str(raw_group_id or "").strip()):
        if value and value not in ids:
            ids.append(value)
    return ids


class GroupStateCoordinator:
    """群 V2 状态链、提案与确认协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    async def postprocess_result(self, method: str, params: dict[str, Any], result: Any) -> Any:
        client = self.client
        # V2-only 客户端：群密钥/状态由 group.v2.bootstrap + group.v2.propose_state 体系管理。
        if method in {
            "group.create", "group.add_member", "group.kick", "group.remove_member", "group.leave",
            "group.review_join_request", "group.batch_review_join_request",
            "group.use_invite_code", "group.request_join",
        } and isinstance(result, dict) and getattr(client, "_v2_session", None):
            gid = ""
            if isinstance(result.get("group"), dict):
                gid = normalize_group_id(result["group"].get("group_aid") or result["group"].get("group_id", ""))
            if not gid:
                gid = normalize_group_id(params.get("group_aid") or params.get("group_id", ""))
            if gid:
                try:
                    await client._v2_auto_propose_state(gid)
                except Exception as exc:
                    client._log.debug("client", "V2 post-membership propose failed (non-fatal): group=%s err=%s", gid, exc)
                if method in {"group.create", "group.use_invite_code"}:
                    client._schedule_group_spk_registration(gid, reason=method)
                # group SPK 轮换只由 group.changed 成员关系事件或解密消费当前 group SPK 触发。
                # 这里不在本地 RPC 返回后直接轮换，避免 lazy/propose 路径和事件路径重复发。
        return result

    def handle_group_changed_v2_membership(self, data: dict[str, Any]) -> None:
        """处理 group.changed 中和 V2 群状态相关的缓存、SPK 与自动提案。"""
        client = self.client
        action = data.get("action", "")
        raw_group_id = data.get("group_aid") or data.get("group_id", "")
        group_id = normalize_group_id(raw_group_id)
        if group_id:
            bootstrap_cache = getattr(client, "_v2_bootstrap_cache", None)
            if bootstrap_cache is not None:
                for cache_group_id in _group_cache_ids(raw_group_id, group_id):
                    bootstrap_cache.pop(f"group:{cache_group_id}", None)
            membership_actions = {
                "member_added", "member_left", "member_removed", "role_changed",
                "owner_transferred", "joined", "join_approved", "invite_code_used",
            }
            if action in membership_actions and getattr(client, "_v2_session", None):
                joined_aid = str(
                    data.get("joined_aid")
                    or data.get("member_aid")
                    or data.get("aid")
                    or ""
                ).strip()
                actor_aid = str(data.get("actor_aid") or "").strip()
                self_aid = str(getattr(client, "_aid", "") or "").strip()
                join_actions = {"member_added", "joined", "join_approved", "invite_code_used"}
                is_self_join = (
                    action in join_actions
                    and self_aid
                    and (
                        joined_aid == self_aid
                        or (
                            not joined_aid
                            and action in {"joined", "invite_code_used"}
                            and actor_aid == self_aid
                        )
                    )
                )
                if is_self_join:
                    client._schedule_group_spk_registration(group_id, reason=f"group.changed:{action}")
                else:
                    client._schedule_group_spk_rotation(group_id, reason=f"group.changed:{action}")

        if (
            group_id
            and action in (
                "upsert", "member_added", "member_left", "member_removed",
                "role_changed", "owner_transferred", "joined", "join_approved",
                "invite_code_used",
            )
            and getattr(client, "_v2_session", None)
        ):
            self.schedule_auto_propose_state(group_id, leader_delay=True)

    async def on_group_state_committed(self, data: Any) -> None:
        """处理 event/group.state_committed：验签 → 验证 state_hash 链 → 更新本地存储。"""
        client = self.client
        _t_start = time.time()
        if not isinstance(data, dict):
            return
        group_id = normalize_group_id(data.get("group_aid") or data.get("group_id", ""))
        if not group_id:
            return
        client._log.debug("client", "_on_group_state_committed enter: group=%s state_version=%s", group_id, data.get("state_version", "-"))

        cs = data.get("client_signature")
        if cs and isinstance(cs, dict):
            if client._should_skip_event_signature(data):
                data.pop("client_signature", None)
            else:
                verified = await client._verify_event_signature(data, cs)
                if verified is False:
                    client._log.warn(
                        "client",
                        "state_committed 提交者签名验证失败 group=%s actor=%s",
                        group_id, data.get("actor_aid"),
                    )
                    return
                data["_verified"] = verified

        state_version = int(data.get("state_version") or 0)
        state_hash = str(data.get("state_hash") or "").strip()
        prev_state_hash = str(data.get("prev_state_hash") or "").strip()
        key_epoch = int(data.get("key_epoch") or 0)
        membership_snapshot = str(data.get("membership_snapshot") or "").strip()
        policy_snapshot = str(data.get("policy_snapshot") or "").strip()

        local_state = client._token_store.load_group_state(client._aid, group_id)
        if local_state and local_state["state_hash"] and local_state["state_hash"] != prev_state_hash:
            client._log.warn(
                "client",
                "state_hash 链不连续 group=%s local_sv=%d event_sv=%d",
                group_id, local_state["state_version"], state_version,
            )
            try:
                server_state = await client._transport.call("group.get_state", {"group_id": group_id})
                if server_state and "state_version" in server_state:
                    sv = int(server_state["state_version"])
                    s_hash = str(server_state.get("state_hash", ""))
                    s_epoch = int(server_state.get("key_epoch", 0))
                    s_members_json = str(server_state.get("membership_snapshot", ""))
                    s_policy_json = str(server_state.get("policy_snapshot", ""))
                    s_prev = str(server_state.get("prev_state_hash", ""))
                    if s_members_json and s_hash:
                        from ..e2ee import compute_state_hash as _csh
                        s_members = json.loads(s_members_json) if s_members_json else []
                        s_policy = json.loads(s_policy_json) if s_policy_json else {}
                        computed = _csh(
                            group_id=group_id, state_version=sv, key_epoch=s_epoch,
                            members=s_members, policy=s_policy, prev_state_hash=s_prev,
                        )
                        if computed != s_hash:
                            client._log.warn(
                                "client",
                                "回源 state_hash 验证失败 group=%s sv=%d expected=%s got=%s",
                                group_id, sv, s_hash, computed,
                            )
                            return
                    client._token_store.save_group_state(
                        client._aid,
                        group_id=group_id,
                        state_version=sv,
                        state_hash=s_hash,
                        key_epoch=s_epoch,
                        membership_json=s_members_json or membership_snapshot,
                        policy_json=s_policy_json or policy_snapshot,
                    )
            except Exception as exc:
                client._log.warn("client", "state origin fetch failed group=%s: %s", group_id, exc)
            return

        members = json.loads(membership_snapshot) if membership_snapshot else []
        policy = json.loads(policy_snapshot) if policy_snapshot else {}
        from ..e2ee import compute_state_hash
        computed = compute_state_hash(
            group_id=group_id, state_version=state_version, key_epoch=key_epoch,
            members=members, policy=policy, prev_state_hash=prev_state_hash,
        )
        if computed != state_hash:
            client._log.warn(
                "client",
                "state_hash 重算不匹配 group=%s sv=%d expected=%s got=%s",
                group_id, state_version, state_hash, computed,
            )
            return

        client._token_store.save_group_state(
            client._aid,
            group_id=group_id, state_version=state_version, state_hash=state_hash,
            key_epoch=key_epoch, membership_json=membership_snapshot, policy_json=policy_snapshot,
        )
        client._log.debug("client", "_on_group_state_committed exit: elapsed=%.3fs group=%s state_version=%d", time.time() - _t_start, group_id, state_version)

    async def verify_state_signature(self, group_id: str, bootstrap: dict) -> None:
        """验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。"""
        from ..client import _length_prefixed_bytes_key
        from ..errors import E2EEError

        client = self.client
        if not isinstance(bootstrap, dict):
            return
        state_signature = str(bootstrap.get("state_signature", "") or "")
        actor_aid = str(bootstrap.get("state_actor_aid", "") or "")
        state_hash_signed = str(bootstrap.get("state_hash_signed", "") or "")
        membership_snapshot = str(bootstrap.get("state_membership_snapshot", "") or "")
        state_version = int(bootstrap.get("state_version", 0) or 0)
        if state_version == 0 or not state_signature or not actor_aid:
            return

        try:
            sign_payload = json.dumps({
                "group_id": group_id,
                "state_version": state_version,
                "state_hash": state_hash_signed,
                "membership_snapshot": membership_snapshot,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            sig_bytes = base64.b64decode(state_signature)

            sig_cache_key = hashlib.sha256(
                _length_prefixed_bytes_key(actor_aid.encode("utf-8"), sign_payload)
                + sig_bytes
            ).digest()
            now_ts = time.time()
            cached_exp = client._v2_sig_cache.get(sig_cache_key)
            if cached_exp is not None and cached_exp > now_ts:
                client._log.debug("client", "V2 state signature cache hit: group=%s sv=%d", group_id, state_version)
            else:
                cert_pem_bytes = await client._fetch_peer_cert(actor_aid)
                cert_pem = cert_pem_bytes.decode("utf-8") if isinstance(cert_pem_bytes, bytes) else str(cert_pem_bytes or "")
                if not cert_pem:
                    client._log.warn("client", "V2 state verify: no cert for actor=%s, group=%s", actor_aid, group_id)
                    raise E2EEError(f"V2 state verify: cannot fetch actor cert for {actor_aid}")

                from cryptography.x509 import load_pem_x509_certificate
                from cryptography.hazmat.primitives.asymmetric import ec as _ec
                from cryptography.hazmat.primitives import hashes as _hashes
                cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
                pub_key = cert.public_key()
                pub_key.verify(sig_bytes, sign_payload, _ec.ECDSA(_hashes.SHA256()))
                client._v2_sig_cache[sig_cache_key] = now_ts + client._V2_SIG_CACHE_TTL
                if len(client._v2_sig_cache) > client._V2_SIG_CACHE_MAX:
                    stale = [k for k, exp in client._v2_sig_cache.items() if exp <= now_ts]
                    for k in stale:
                        client._v2_sig_cache.pop(k, None)
                    if len(client._v2_sig_cache) > client._V2_SIG_CACHE_MAX:
                        oldest = sorted(client._v2_sig_cache.items(), key=lambda x: x[1])[: client._V2_SIG_CACHE_MAX // 4]
                        for k, _ in oldest:
                            client._v2_sig_cache.pop(k, None)
                client._log.debug("client", "V2 state signature verified: group=%s sv=%d actor=%s", group_id, state_version, actor_aid)

            try:
                signed_snapshot = json.loads(membership_snapshot) if membership_snapshot.startswith("[") else None
                if signed_snapshot:
                    server_members = set(bootstrap.get("member_aids", []))
                    signed_members = set(signed_snapshot)
                    extra = server_members - signed_members
                    if extra:
                        try:
                            req_resp = await client.call("group.get_settings", {"group_id": group_id, "keys": ["join.mode"]})
                            settings = {s["key"]: s["value"] for s in req_resp.get("settings", [])}
                            mode = str(settings.get("join.mode", "") or "").strip()
                        except Exception:
                            mode = ""
                        if mode not in ("open", "invite_code", "invite_only"):
                            client._log.warn(
                                "client",
                                "V2 state tamper detected: group=%s pending_extra=%s mode=%s",
                                group_id, sorted(extra), mode,
                            )
                            await client._dispatcher.publish("group.v2.state_tampered", {
                                "group_id": group_id,
                                "pending_extra": sorted(extra),
                                "mode": mode,
                            })
            except Exception:
                pass
        except E2EEError:
            raise
        except Exception as exc:
            client._log.warn("client", "V2 state signature verification failed: group=%s err=%s", group_id, exc)
            raise E2EEError(f"V2 state signature verification failed: {exc}")

    async def check_fork(self, group_id: str, server_chain: str) -> None:
        """分叉检测：比对服务端 state_chain 与本地存储。"""
        client = self.client
        if not server_chain:
            return
        try:
            local = client._v2_state_chains.get(group_id)
            if local is None:
                client._v2_state_chains[group_id] = (0, server_chain)
                return
            local_chain = local[1]
            if local_chain == server_chain:
                return
            try:
                state_resp = await client.call("group.get_state", {"group_id": group_id})
                if isinstance(state_resp, dict):
                    server_sv = int(state_resp.get("state_version", 0))
                    local_sv = local[0]
                    if server_sv > local_sv:
                        client._v2_state_chains[group_id] = (server_sv, server_chain)
                        return
                    if server_sv < local_sv:
                        client._log.warn("client", "V2 state chain rollback detected: group=%s server_sv=%d local_sv=%d", group_id, server_sv, local_sv)
            except Exception:
                pass
            client._log.warn(
                "client",
                "V2 state chain fork detected: group=%s local_chain=%s... server_chain=%s...",
                group_id, local_chain[:16], server_chain[:16],
            )
            await client._dispatcher.publish("group.v2.fork_detected", {
                "group_id": group_id,
                "local_chain": local_chain,
                "server_chain": server_chain,
            })
        except Exception as exc:
            client._log.debug("client", "V2 fork check failed (non-fatal): %s", exc)

    def maybe_trigger_auto_propose(self, group_id: str) -> None:
        """lazy sync 路径：发现 pending members 时异步触发 auto propose（fire-and-forget，去重）。"""
        client = self.client
        if not client._v2_auto_state_management_enabled:
            return
        now = time.time()
        last = client._v2_lazy_propose_triggered.get(group_id, 0.0)
        if now - last < 10.0:
            return
        client._v2_lazy_propose_triggered[group_id] = now
        self.schedule_auto_propose_state(group_id, leader_delay=True)

    def schedule_auto_propose_state(self, group_id: str, *, leader_delay: bool = False) -> None:
        client = self.client
        state_value = getattr(client._public_state, "value", client._public_state)
        if getattr(client, "_closing", False) or state_value != "ready":
            return
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()

        async def _run() -> None:
            await client._delivery().run_background_rpc(
                lambda: client._v2_auto_propose_state(group_id, leader_delay=leader_delay)
            )

        self.track_auto_state_task(loop.create_task(_run()))

    def schedule_auto_confirm_pending_proposals(self) -> None:
        client = self.client
        state_value = getattr(client._public_state, "value", client._public_state)
        if (
            not client._v2_auto_state_management_enabled
            or getattr(client, "_closing", False)
            or state_value != "ready"
        ):
            return
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()

        async def _run() -> None:
            await client._delivery().run_background_rpc(
                lambda: client._v2_auto_confirm_pending_proposals()
            )

        self.track_auto_state_task(loop.create_task(_run()))

    def track_auto_state_task(self, task: asyncio.Task) -> None:
        client = self.client
        tasks = getattr(client, "_v2_auto_state_tasks", None)
        if tasks is None:
            tasks = set()
            client._v2_auto_state_tasks = tasks
        tasks.add(task)

        def _discard(done_task: asyncio.Task) -> None:
            tasks.discard(done_task)
            try:
                done_task.exception()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        task.add_done_callback(_discard)

    async def auto_propose_state(self, group_id: str, *, leader_delay: bool = False) -> None:
        client = self.client
        if not client._v2_auto_state_management_enabled:
            return
        normalized_group_id = normalize_group_id(group_id) if group_id else ""
        if not normalized_group_id:
            return
        if leader_delay:
            should_continue = await client._v2_auto_propose_leader_delay(normalized_group_id)
            if not should_continue:
                return
        async with client._v2_auto_propose_locks_guard:
            lock = client._v2_auto_propose_locks.get(normalized_group_id)
            if lock is None:
                lock = asyncio.Lock()
                client._v2_auto_propose_locks[normalized_group_id] = lock
        async with lock:
            await client._do_v2_auto_propose_state(normalized_group_id)

    async def auto_propose_leader_delay(self, group_id: str) -> bool:
        """事件触发路径的 leader 选举：仅在线 owner/admin 参与。"""
        from ..client import _length_prefixed_text_key, _v2_device_id_from_device, _v2_wrap_capabilities

        client = self.client
        try:
            members_resp = await client.call("group.get_online_members", {"group_id": group_id})
            members = members_resp.get("members") or members_resp.get("items") or members_resp.get("online_members") or []
            my_aid = client._aid or ""
            my_role = ""
            online_admin_aids: list[str] = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                aid = str(m.get("aid") or "").strip()
                role = str(m.get("role") or "").strip()
                if not aid:
                    continue
                if "online" in m and not m.get("online"):
                    continue
                if role in ("owner", "admin"):
                    online_admin_aids.append(aid)
                if aid == my_aid:
                    my_role = role
            online_admin_aids = sorted(set(online_admin_aids))
            if my_role not in ("owner", "admin"):
                return False

            bootstrap_resp = await client.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            devices = bootstrap_resp.get("devices", []) if isinstance(bootstrap_resp, dict) else []
            online_admin_set = set(online_admin_aids)
            candidates: list[str] = []
            for dev in devices:
                if not isinstance(dev, dict):
                    continue
                aid = str(dev.get("aid") or "").strip()
                has_device_id, device_id = _v2_device_id_from_device(dev)
                if aid in online_admin_set and has_device_id:
                    candidates.append(f"{aid}\x1f{device_id}")
            if not candidates:
                candidates = [f"{aid}\x1f" for aid in online_admin_aids]
            my_key = f"{my_aid}\x1f{client._device_id or ''}"
            if my_key not in candidates:
                candidates.append(my_key)
            leader = sorted(set(candidates))[0]
            if leader == my_key:
                client._log.debug("client", "V2 auto propose leader elected: group=%s leader=%s", group_id, leader)
                return True

            seed = _length_prefixed_text_key(group_id, my_key).encode("utf-8")
            delay_ms = 2000 + (int.from_bytes(hashlib.sha256(seed).digest()[:4], "big") % 4000)
            client._log.debug(
                "client",
                "V2 auto propose non-leader delay: group=%s leader=%s self=%s delay_ms=%d",
                group_id, leader, my_key, delay_ms,
            )
            await asyncio.sleep(delay_ms / 1000)
            return True
        except Exception as exc:
            client._log.debug("client", "V2 auto propose leader check failed, fallback immediate: group=%s err=%s", group_id, exc)
            return True

    def verify_committed_state_base(self, group_id: str, state_resp: dict[str, Any]) -> bool:
        client = self.client
        current_sv = int(state_resp.get("state_version") or 0)
        if current_sv <= 0:
            return True
        current_sh = str(state_resp.get("state_hash") or "").strip()
        membership_snapshot = str(state_resp.get("membership_snapshot") or "").strip()
        if not current_sh or not membership_snapshot:
            client._log.warn("client", "V2 committed state base incomplete: group=%s sv=%d", group_id, current_sv)
            return False
        try:
            parsed = json.loads(membership_snapshot)
            if isinstance(parsed, list):
                client._log.debug(
                    "client",
                    "V2 committed state base uses legacy snapshot array, accepting as hash anchor: group=%s sv=%d",
                    group_id,
                    current_sv,
                )
                return True
            if not isinstance(parsed, dict):
                client._log.warn("client", "V2 committed state base snapshot is not object: group=%s sv=%d", group_id, current_sv)
                return False
            from ..v2.state.commitment import compute_state_commitment
            computed = compute_state_commitment(group_id, current_sv, parsed)
            if computed != current_sh:
                client._log.warn("client", "V2 committed state base hash mismatch: group=%s sv=%d", group_id, current_sv)
                return False
            return True
        except Exception as exc:
            client._log.warn("client", "V2 committed state base verification failed: group=%s sv=%d err=%s", group_id, current_sv, exc)
            return False

    async def do_auto_propose_state(self, group_id: str) -> None:
        """成员变更后自动 propose state（仅 owner/admin 执行）。"""
        from ..client import _v2_wrap_capabilities

        client = self.client
        try:
            members_resp = await client.call("group.get_members", {"group_id": group_id})
            members = members_resp.get("members") or members_resp.get("items") or []
            my_aid = client._aid or ""
            my_role = ""
            member_aids = []
            admin_aids = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                aid = str(m.get("aid") or "").strip()
                role = str(m.get("role") or "").strip()
                if aid:
                    member_aids.append(aid)
                    if role in ("owner", "admin"):
                        admin_aids.append(aid)
                if aid == my_aid:
                    my_role = role

            if my_role not in ("owner", "admin"):
                return

            proposal_resp = await client.call("group.v2.get_proposal", {"group_id": group_id})
            if isinstance(proposal_resp, dict):
                pending_proposal = proposal_resp.get("proposal")
                if isinstance(pending_proposal, dict) and pending_proposal.get("proposal_id"):
                    confirmed = await client._v2_confirm_pending_proposal(group_id)
                    if confirmed:
                        return
                    auto_confirm_at = int(pending_proposal.get("auto_confirm_at") or 0)
                    now_ms = int(time.time() * 1000)
                    if auto_confirm_at > now_ms:
                        wait_s = min((auto_confirm_at - now_ms) / 1000 + 0.5, 35.0)
                        client._log.debug("client", "V2 auto propose: pending proposal exists, waiting %.1fs group=%s", wait_s, group_id)
                        await asyncio.sleep(wait_s)

            bootstrap_resp = await client.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            all_devices = bootstrap_resp.get("devices", []) if isinstance(bootstrap_resp, dict) else []
            audit_recipients = bootstrap_resp.get("audit_recipients", []) if isinstance(bootstrap_resp, dict) else []
            audit_aids_list = sorted(set(
                str(r.get("aid") or "").strip() for r in audit_recipients if str(r.get("aid") or "").strip()
            ))

            members_with_devices = {}
            for aid in member_aids:
                members_with_devices[aid] = []
            for dev in all_devices:
                dev_aid = str(dev.get("aid") or "").strip()
                if dev_aid in members_with_devices:
                    members_with_devices[dev_aid].append({
                        "device_id": str(dev.get("device_id") or ""),
                        "ik_fp": str(dev.get("ik_fp") or ""),
                    })

            members_payload = [
                {"aid": aid, "devices": devices}
                for aid, devices in members_with_devices.items()
            ]
            state_payload = {
                "members": members_payload,
                "audit_aids": audit_aids_list,
                "admin_set": {"admin_aids": sorted(admin_aids), "threshold": 1},
                "join_policy_hash": None,
                "recovery_quorum": None,
                "history_policy": "recent_7_days",
                "wrap_protocol": "3DH",
            }

            state_resp = await client.call("group.get_state", {"group_id": group_id})
            if not isinstance(state_resp, dict):
                return
            if not client._v2_verify_committed_state_base(group_id, state_resp):
                return
            current_sv = int(state_resp.get("state_version", 0))
            current_sh = str(state_resp.get("state_hash", ""))
            key_epoch = int(state_resp.get("key_epoch", 0))

            from ..v2.state.commitment import compute_state_commitment
            state_hash = compute_state_commitment(group_id, current_sv + 1, state_payload)

            membership_snapshot = json.dumps(state_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if client._v2_auto_propose_last_snapshot.get(group_id) == membership_snapshot:
                return
            current_membership_snapshot = str(state_resp.get("membership_snapshot") or "")
            if current_membership_snapshot and current_membership_snapshot == membership_snapshot:
                client._v2_auto_propose_last_snapshot[group_id] = membership_snapshot
                return
            signature = ""
            current_aid = client._current_aid
            if current_aid and current_aid.private_key_pem:
                try:
                    from cryptography.hazmat.primitives.asymmetric import ec as _ec
                    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
                    sign_payload = json.dumps({
                        "group_id": group_id,
                        "state_version": current_sv + 1,
                        "state_hash": state_hash,
                        "membership_snapshot": membership_snapshot,
                    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    pk = _ser.load_pem_private_key(current_aid.private_key_pem.encode("utf-8"), password=None)
                    sig = pk.sign(sign_payload, _ec.ECDSA(_hashes.SHA256()))
                    signature = base64.b64encode(sig).decode("ascii")
                except Exception as _sig_exc:
                    client._log.debug("client", "propose_state signature failed: %s", _sig_exc)

            propose_result = await client.call("group.v2.propose_state", {
                "group_id": group_id,
                "state_version": current_sv + 1,
                "key_epoch": key_epoch,
                "state_hash": state_hash,
                "prev_state_hash": current_sh,
                "membership_snapshot": membership_snapshot,
                "signature": signature,
                "reason": "membership_changed",
                "auto_confirm_seconds": 30,
            })
            client._log.debug("client", "V2 auto propose_state: group=%s sv=%d", group_id, current_sv + 1)
            proposal_id = ""
            if isinstance(propose_result, dict):
                proposal_id = str(propose_result.get("proposal_id") or "").strip()
            if proposal_id:
                try:
                    await client.call("group.v2.confirm_state", {"proposal_id": proposal_id})
                    client._v2_auto_propose_last_snapshot[group_id] = membership_snapshot
                    client._log.debug("client", "V2 auto confirm_state: group=%s proposal=%s", group_id, proposal_id)
                except Exception as confirm_exc:
                    client._log.debug("client", "V2 auto confirm_state failed (non-fatal): group=%s err=%s", group_id, confirm_exc)
        except Exception as exc:
            client._log.debug("client", "V2 auto propose_state failed (non-fatal): group=%s err=%s", group_id, exc)

    def verify_pending_proposal_against_base(
        self,
        group_id: str,
        proposal: dict[str, Any],
        state_resp: dict[str, Any],
    ) -> bool:
        client = self.client
        if not client._v2_verify_committed_state_base(group_id, state_resp):
            return False
        current_sv = int(state_resp.get("state_version") or 0)
        current_sh = str(state_resp.get("state_hash") or "").strip()
        proposal_sv = int(proposal.get("state_version") or 0)
        proposal_hash = str(proposal.get("state_hash") or "").strip()
        proposal_prev = str(proposal.get("prev_state_hash") or "").strip()
        membership_snapshot = str(proposal.get("membership_snapshot") or "").strip()
        if proposal_sv != current_sv + 1 or proposal_prev != current_sh or not proposal_hash or not membership_snapshot:
            client._log.warn(
                "client",
                "V2 pending proposal base mismatch: group=%s current_sv=%d proposal_sv=%d",
                group_id, current_sv, proposal_sv,
            )
            return False
        try:
            parsed = json.loads(membership_snapshot)
            if not isinstance(parsed, dict):
                return False
            from ..v2.state.commitment import compute_state_commitment
            computed = compute_state_commitment(group_id, proposal_sv, parsed)
            if computed != proposal_hash:
                client._log.warn("client", "V2 pending proposal hash mismatch: group=%s proposal_sv=%d", group_id, proposal_sv)
                return False
            return True
        except Exception as exc:
            client._log.warn("client", "V2 pending proposal verification failed: group=%s err=%s", group_id, exc)
            return False

    async def confirm_pending_proposal(self, group_id: str) -> bool:
        client = self.client
        proposal_resp = await client.call("group.v2.get_proposal", {"group_id": group_id})
        proposal = proposal_resp.get("proposal") if isinstance(proposal_resp, dict) else None
        if not isinstance(proposal, dict):
            return False
        proposal_id = str(proposal.get("proposal_id") or "").strip()
        if not proposal_id:
            return False

        state_resp = await client.call("group.get_state", {"group_id": group_id})
        if not isinstance(state_resp, dict):
            return False
        current_sv = int(state_resp.get("state_version") or 0)
        proposal_sv = int(proposal.get("state_version") or 0)
        if proposal_sv <= current_sv:
            client._log.debug(
                "client",
                "V2 pending proposal already settled: group=%s current_sv=%d proposal_sv=%d",
                group_id, current_sv, proposal_sv,
            )
            return False
        if not client._v2_verify_pending_proposal_against_base(group_id, proposal, state_resp):
            return False

        await client.call("group.v2.confirm_state", {"proposal_id": proposal_id})
        client._log.info("client", "V2 confirmed pending proposal: group=%s proposal=%s", group_id, proposal_id)
        return True

    async def auto_confirm_pending_proposals(self) -> None:
        """Owner/admin 上线时自动检查：confirm pending proposals 或发起新 propose。"""
        client = self.client
        if not client._v2_auto_state_management_enabled:
            return
        try:
            my_aid = client._aid or ""
            if not my_aid:
                return
            groups_resp = await client.call("group.list_my", {})
            groups = groups_resp.get("groups") or groups_resp.get("items") or []
            for g in groups:
                if not isinstance(g, dict):
                    continue
                group_id = normalize_group_id(g.get("group_aid") or g.get("group_id", ""))
                my_role = str(g.get("role") or g.get("my_role") or "").strip()
                if not group_id or my_role not in ("owner", "admin"):
                    continue
                try:
                    confirmed = await client._delivery().run_background_rpc(
                        lambda: client._v2_confirm_pending_proposal(group_id)
                    )
                    if not confirmed:
                        await client._delivery().run_background_rpc(
                            lambda: client._v2_auto_propose_state(group_id)
                        )
                except Exception as exc:
                    client._log.debug("client", "V2 auto confirm/propose failed (non-fatal): group=%s err=%s", group_id, exc)
        except Exception as exc:
            client._log.debug("client", "V2 auto confirm pending proposals failed (non-fatal): %s", exc)

    async def on_v2_state_proposed(self, data: Any) -> None:
        client = self.client
        if not isinstance(data, dict) or not client._v2_session:
            return
        group_id = normalize_group_id(data.get("group_aid") or data.get("group_id", ""))
        if not group_id:
            return
        await client._dispatcher.publish("group.v2.state_proposed", data)
        if not client._v2_auto_state_management_enabled:
            return
        try:
            await client._delivery().run_background_rpc(
                lambda: client._v2_confirm_pending_proposal(group_id)
            )
        except Exception as exc:
            client._log.debug("client", "V2 state_proposed handling failed (non-fatal): group=%s err=%s", group_id, exc)

    async def on_v2_state_retry_needed(self, data: Any) -> None:
        client = self.client
        if not isinstance(data, dict) or not client._v2_session:
            return
        group_id = normalize_group_id(data.get("group_aid") or data.get("group_id", ""))
        if not group_id:
            return
        await client._dispatcher.publish("group.v2.state_retry_needed", data)
        try:
            await client._delivery().run_background_rpc(
                lambda: client._v2_auto_propose_state(group_id, leader_delay=True)
            )
        except Exception as exc:
            client._log.debug("client", "V2 state_retry_needed handling failed (non-fatal): group=%s err=%s", group_id, exc)

    async def on_v2_state_confirmed(self, data: Any) -> None:
        client = self.client
        if not isinstance(data, dict):
            return
        raw_group_id = data.get("group_aid") or data.get("group_id", "")
        group_id = normalize_group_id(raw_group_id)
        if group_id:
            for cache_group_id in _group_cache_ids(raw_group_id, group_id):
                client._v2_bootstrap_cache.pop(f"group:{cache_group_id}", None)
                target_cache = getattr(client, "_v2_target_set_cache", None)
                if isinstance(target_cache, dict):
                    target_cache.pop(f"group:{cache_group_id}", None)
        await client._dispatcher.publish("group.v2.state_confirmed", data)
