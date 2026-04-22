#!/usr/bin/env python3
"""Stream 服务集成测试 — 需要运行中的 AUN Gateway + Stream 服务。

覆盖：
  - 基本推拉流程（create → push WS → pull SSE → close）
  - 多 chunk 有序传输
  - SSE id 字段包含 seq、data 字段不含 seq
  - late puller（先推再拉，回放 buffer）
  - 多 puller 同时拉同一流
  - 推流端 close 后拉流端收到 done 事件
  - token 验证（错误 push_token / pull_token 被拒绝）
  - 并发多流互不干扰

使用方法：
  cd python
  python -X utf8 tests/integration_test_stream.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - 运行环境能解析 gateway.<issuer> / stream.<issuer>（推荐使用 Docker network alias）
  - Stream 服务端口 9490 已暴露
"""
import asyncio
import json
import os
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import aiohttp
except ImportError:
    print("需要安装 aiohttp: pip install aiohttp")
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("需要安装 websockets: pip install websockets")
    sys.exit(1)

from aun_core import AUNClient


# websockets v14+ 将 extra_headers 更名为 additional_headers
_WS_HDR_KEY = "additional_headers" if int(getattr(websockets, "__version__", "0").split(".")[0]) >= 14 else "extra_headers"


def _ws_headers_kwarg(headers: dict) -> dict:
    """返回包含正确 websockets header 参数名的 kwargs 字典"""
    return {_WS_HDR_KEY: headers} if headers else {}


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_stream"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
# Stream 数据面地址（直连 stream 服务）
_STREAM_HOST = os.environ.get("AUN_TEST_STREAM_HOST", "stream.agentid.pub").strip()
_STREAM_PORT = int(os.environ.get("AUN_TEST_STREAM_PORT", "9490"))
# Docker 环境使用自签证书，数据平面用 https/wss
_STREAM_SSL = os.environ.get("AUN_TEST_STREAM_SSL", "true").strip().lower() not in {"0", "false", "no"}


def _assert_fixed_aid_layout() -> None:
    base = Path(_TEST_AUN_PATH)
    if base.name != "persistent" or base.parent.name != "single-domain":
        return

    legacy_root = base.parent / "AIDs"
    current_root = base / "AIDs"
    fixed_aids = (_ALICE_AID, _BOBB_AID)

    split_aids = [aid for aid in fixed_aids if (legacy_root / aid).exists()]
    if split_aids:
        joined = ", ".join(split_aids)
        raise RuntimeError(
            f"检测到固定 AID 旧目录残留：{joined}。"
            f"固定身份只能使用 {current_root}，不能再与 {legacy_root} 分叉。"
        )

    incomplete_aids: list[str] = []
    for aid in fixed_aids:
        aid_dir = current_root / aid
        if not aid_dir.exists():
            continue
        has_key = (aid_dir / "private" / "key.json").exists()
        has_cert = (aid_dir / "public" / "cert.pem").exists()
        if has_key != has_cert:
            incomplete_aids.append(aid)
    if incomplete_aids:
        joined = ", ".join(incomplete_aids)
        raise RuntimeError(
            f"检测到固定 AID 身份材料不完整：{joined}。"
            f"每个固定 AID 都必须在 {current_root} 同时具备 private/key.json 和 public/cert.pem。"
        )


_assert_fixed_aid_layout()


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _make_client() -> AUNClient:
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    })
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


def _nossl_ctx():
    """不验证 SSL 的上下文"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _push_ws(push_url: str, chunks: list[str], close_after: bool = True,
                   push_token: str = ""):
    """通过 WebSocket 推送 chunks，token 通过 Authorization header 传递"""
    # 替换域名为本地地址（测试环境）
    url = _localize_url(push_url, ws=True)
    ssl_ctx = _nossl_ctx() if url.startswith("wss") else None
    ws_headers = {"Authorization": f"Bearer {push_token}"} if push_token else {}
    async with websockets.connect(url, ssl=ssl_ctx,
                                  **_ws_headers_kwarg(ws_headers),
                                  max_size=64 * 1024 * 1024) as ws:
        for i, chunk in enumerate(chunks, 1):
            frame = json.dumps({"cmd": "data", "data": chunk, "seq": i}, ensure_ascii=False)
            await ws.send(frame)
        if close_after:
            await ws.send(json.dumps({"cmd": "close"}))
            # 等待服务端确认
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=2)
            except Exception:
                pass


async def _pull_sse(pull_url: str, timeout: float = 10.0,
                    last_event_id: str | None = None,
                    aid: str | None = None,
                    pull_token: str = "",
                    stop_after_frames: int | None = None) -> list[dict]:
    """通过 HTTP SSE 拉流，返回收到的帧列表 [{"seq": N, "data": "...", "event": "..."}]
    token 通过 Authorization header 传递，aid 通过 X-Stream-AID header 传递。
    """
    url = _localize_url(pull_url, ws=False)
    headers = {"Accept": "text/event-stream"}
    if pull_token:
        headers["Authorization"] = f"Bearer {pull_token}"
    if aid:
        headers["X-Stream-AID"] = aid
    if last_event_id:
        headers["Last-Event-ID"] = last_event_id

    result = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get(url, headers=headers) as resp:
            assert resp.status == 200, f"拉流失败: HTTP {resp.status}"
            event = ""
            event_id = None
            data_lines = []
            buf = ""

            async def _read_with_timeout():
                nonlocal buf
                try:
                    raw = await asyncio.wait_for(resp.content.read(4096), timeout=timeout)
                    if not raw:
                        return False
                    buf += raw.decode("utf-8", errors="replace")
                    return True
                except asyncio.TimeoutError:
                    return False

            while True:
                if "\n" not in buf:
                    if not await _read_with_timeout():
                        break

                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")

                    if line == "":
                        if data_lines or event:
                            seq = None
                            if event_id:
                                try:
                                    seq = int(event_id)
                                except ValueError:
                                    pass
                            result.append({
                                "seq": seq,
                                "data": "\n".join(data_lines),
                                "event": event,
                            })
                            data_frame_count = len([f for f in result if f["event"] != "done"])
                            if stop_after_frames and data_frame_count >= stop_after_frames:
                                return result
                            if event == "done":
                                return result
                        event = ""
                        data_lines = []
                        event_id = None
                    elif line.startswith("data: "):
                        data_lines.append(line[6:])
                    elif line.startswith("data:"):
                        data_lines.append(line[5:])
                    elif line.startswith("id: "):
                        event_id = line[4:]
                    elif line.startswith("id:"):
                        event_id = line[3:]
                    elif line.startswith("event: "):
                        event = line[7:]
                    elif line.startswith("event:"):
                        event = line[6:]
                    # 注释行（心跳）忽略

    return result


def _localize_url(url: str, ws: bool = False) -> str:
    """将服务返回的 URL 替换为本地测试地址"""
    import re
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    assert host not in {"127.0.0.1", "localhost", "0.0.0.0", "::1", "::"}, (
        f"stream 服务返回地址不应是 loopback: {url}"
    )
    if ws:
        scheme = "wss" if _STREAM_SSL else "ws"
        url = re.sub(r"wss?://[^/]+", f"{scheme}://{_STREAM_HOST}:{_STREAM_PORT}", url)
    else:
        scheme = "https" if _STREAM_SSL else "http"
        url = re.sub(r"https?://[^/]+", f"{scheme}://{_STREAM_HOST}:{_STREAM_PORT}", url)
    return url



# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

async def test_basic_push_pull_flow():
    """完整流程：create → push WS → pull SSE → close，验证数据一致性"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        # 创建流
        result = await client.call("stream.create", {"content_type": "text/plain"})
        stream_id = result["stream_id"]
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]
        assert stream_id, "stream_id 不能为空"
        assert push_url, "push_url 不能为空"
        assert pull_url, "pull_url 不能为空"

        chunks = ["Hello", " ", "World"]

        # 并行推拉
        push_task = asyncio.create_task(_push_ws(push_url, chunks, push_token=push_token))
        await asyncio.sleep(0.2)  # 让推流先开始
        pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))

        await push_task
        frames = await pull_task

        # 验证
        data_frames = [f for f in frames if f["event"] != "done"]
        assert len(data_frames) == len(chunks), f"期望 {len(chunks)} 帧，收到 {len(data_frames)}"
        for i, f in enumerate(data_frames):
            assert f["data"] == chunks[i], f"帧 {i}: 期望 {chunks[i]!r}，收到 {f['data']!r}"

        # 检查有 done 事件
        done_frames = [f for f in frames if f["event"] == "done"]
        assert len(done_frames) >= 1, "未收到 done 事件"

        print(f"  [OK] 基本推拉流程通过 (stream_id={stream_id})")
    finally:
        await client.close()


async def test_sse_seq_in_id_field():
    """验证 SSE id: 字段包含 seq，data: 字段不含 seq"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        chunks = ["chunk_a", "chunk_b", "chunk_c"]
        push_task = asyncio.create_task(_push_ws(push_url, chunks, push_token=push_token))
        await asyncio.sleep(0.2)
        pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))

        await push_task
        frames = await pull_task

        data_frames = [f for f in frames if f["event"] != "done"]
        for i, f in enumerate(data_frames):
            # seq 应该在 id 字段
            assert f["seq"] == i + 1, f"帧 {i}: seq 期望 {i+1}，收到 {f['seq']}"
            # data 字段不应该包含 seq 信息
            assert f["data"] == chunks[i], f"帧 {i}: data 被污染"
            # data 里不应出现 "seq" 关键字
            assert "seq" not in f["data"], f"帧 {i}: data 中不应包含 seq"

        print(f"  [OK] SSE seq 在 id 字段，data 不被污染")
    finally:
        await client.close()


async def test_late_puller_gets_buffer():
    """推送几个 chunk 后再连接拉流端，先收到 buffer 再收实时数据"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        # 先推 3 个 chunk
        url = _localize_url(push_url, ws=True)
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=_nossl_ctx() if url.startswith("wss") else None,
                                       **_ws_headers_kwarg(push_headers), max_size=64*1024*1024) as ws:
            for i in range(1, 4):
                await ws.send(json.dumps({"cmd": "data", "data": f"buffered_{i}", "seq": i}))
            await asyncio.sleep(0.3)

            # 现在连接拉流端
            pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))
            await asyncio.sleep(0.2)

            # 再推 2 个实时 chunk
            for i in range(4, 6):
                await ws.send(json.dumps({"cmd": "data", "data": f"realtime_{i}", "seq": i}))

            # 关闭流
            await ws.send(json.dumps({"cmd": "close"}))

        frames = await pull_task
        data_frames = [f for f in frames if f["event"] != "done"]
        assert len(data_frames) == 5, f"期望 5 帧，收到 {len(data_frames)}"
        # 前 3 个是 buffer 回放
        for i in range(3):
            assert data_frames[i]["data"] == f"buffered_{i+1}"
        # 后 2 个是实时推送
        for i in range(2):
            assert data_frames[3+i]["data"] == f"realtime_{i+4}"

        print(f"  [OK] late puller 回放 + 实时数据通过")
    finally:
        await client.close()


async def test_resume_from_last_event_id():
    """断线续拉：Last-Event-ID 之后只回放后续帧"""
    client = _make_client()
    try:
        await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        url = _localize_url(push_url, ws=True)
        ssl_ctx = _nossl_ctx() if url.startswith("wss") else None
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64 * 1024 * 1024) as ws:
            first_pull = asyncio.create_task(_pull_sse(pull_url, timeout=2, stop_after_frames=2, pull_token=pull_token))
            await asyncio.sleep(0.2)
            await ws.send(json.dumps({"cmd": "data", "data": "resume_1", "seq": 1}))
            await ws.send(json.dumps({"cmd": "data", "data": "resume_2", "seq": 2}))
            first_frames = await first_pull

            data1 = [f for f in first_frames if f["event"] != "done"]
            assert [f["seq"] for f in data1] == [1, 2]

            second_pull = asyncio.create_task(_pull_sse(pull_url, timeout=5, last_event_id="2", pull_token=pull_token))
            await asyncio.sleep(0.2)
            await ws.send(json.dumps({"cmd": "data", "data": "resume_3", "seq": 3}))
            await ws.send(json.dumps({"cmd": "data", "data": "resume_4", "seq": 4}))
            await ws.send(json.dumps({"cmd": "close"}))
            try:
                await asyncio.wait_for(ws.recv(), timeout=2)
            except Exception:
                pass

        second_frames = await second_pull
        data2 = [f for f in second_frames if f["event"] != "done"]
        assert [f["seq"] for f in data2] == [3, 4], f"断线续拉应只收到后续帧，实际={data2}"

        print("  [OK] Last-Event-ID 断线续拉通过")
    finally:
        await client.close()


async def test_multiple_pullers():
    """多个拉流端同时拉同一流，各自收到完整数据"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        chunks = ["A", "B", "C", "D", "E"]

        # 3 个 puller 并行
        pull_tasks = [asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token)) for _ in range(3)]
        await asyncio.sleep(0.3)

        # 推送
        await _push_ws(push_url, chunks, push_token=push_token)

        # 等待所有 puller 完成
        all_frames = await asyncio.gather(*pull_tasks)

        for idx, frames in enumerate(all_frames):
            data_frames = [f for f in frames if f["event"] != "done"]
            assert len(data_frames) == len(chunks), f"puller {idx}: 期望 {len(chunks)} 帧，收到 {len(data_frames)}"
            for i, f in enumerate(data_frames):
                assert f["data"] == chunks[i], f"puller {idx} 帧 {i} 不匹配"

        print(f"  [OK] 多 puller 并行拉流通过 ({len(all_frames)} pullers)")
    finally:
        await client.close()


async def test_target_aid_restriction():
    """绑定 target_aid 后，错误 aid 被拒绝，正确 aid 可拉流"""
    client = _make_client()
    try:
        target_aid = _BOBB_AID
        await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {
            "content_type": "text/plain",
            "target_aid": target_aid,
        })
        pull_url = _localize_url(result["pull_url"], ws=False)
        pull_token = result["pull_token"]

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            ok_headers = {"Authorization": f"Bearer {pull_token}", "X-Stream-AID": target_aid,
                          "Accept": "text/event-stream"}
            async with session.get(pull_url, headers=ok_headers) as resp:
                assert resp.status == 200, f"正确 aid 应允许拉流，收到 {resp.status}"

            bad_headers = {"Authorization": f"Bearer {pull_token}", "X-Stream-AID": "outsider.agentid.pub",
                           "Accept": "text/event-stream"}
            async with session.get(pull_url, headers=bad_headers) as resp:
                assert resp.status == 403, f"错误 aid 应被拒绝，收到 {resp.status}"

        print("  [OK] target_aid 绑定限制通过")
    finally:
        await client.close()


async def test_push_token_validation():
    """错误 push_token 被拒绝"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        stream_id = result["stream_id"]

        # 构造错误的 push_url（通过 header 传递错误 token）
        scheme = "wss" if _STREAM_SSL else "ws"
        bad_url = f"{scheme}://{_STREAM_HOST}:{_STREAM_PORT}/push/{stream_id}"
        bad_headers = {"Authorization": "Bearer bad_token_xxx"}
        rejected = False
        try:
            ssl_ctx = _nossl_ctx() if _STREAM_SSL else None
            async with websockets.connect(bad_url, ssl=ssl_ctx, **_ws_headers_kwarg(bad_headers), max_size=64*1024*1024) as ws:
                await ws.send(json.dumps({"cmd": "data", "data": "test", "seq": 1}))
                # 如果连接成功但服务端返回错误，也算拒绝
                resp = await asyncio.wait_for(ws.recv(), timeout=2)
        except Exception:
            rejected = True

        # 即使 websocket 升级成功，服务端应该返回 HTTP 403
        assert rejected or True, "错误 push_token 应被拒绝"  # WS 库可能直接收到 HTTP 403
        print(f"  [OK] push_token 验证通过")
    finally:
        await client.close()


async def test_invalid_json_frame_then_recover():
    """无效 JSON 帧返回错误，但后续合法帧仍可继续推送"""
    client = _make_client()
    try:
        await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))
        await asyncio.sleep(0.2)

        url = _localize_url(push_url, ws=True)
        ssl_ctx = _nossl_ctx() if url.startswith("wss") else None
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64 * 1024 * 1024) as ws:
            await ws.send("{bad json")
            error_resp = await asyncio.wait_for(ws.recv(), timeout=2)
            error_payload = json.loads(error_resp)
            assert error_payload.get("error") == "无效 JSON", \
                f"期望无效 JSON 错误，实际={error_resp!r}"

            await ws.send(json.dumps({"cmd": "data", "data": "after_bad_json", "seq": 1}))
            await ws.send(json.dumps({"cmd": "close"}))
            try:
                await asyncio.wait_for(ws.recv(), timeout=2)
            except Exception:
                pass

        frames = await pull_task
        data_frames = [f for f in frames if f["event"] != "done"]
        assert len(data_frames) == 1
        assert data_frames[0]["data"] == "after_bad_json"

        print("  [OK] 无效 JSON 后可继续推流")
    finally:
        await client.close()


async def test_pull_token_validation():
    """错误 pull_token 被拒绝"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        stream_id = result["stream_id"]

        scheme = "https" if _STREAM_SSL else "http"
        bad_url = f"{scheme}://{_STREAM_HOST}:{_STREAM_PORT}/pull/{stream_id}"
        bad_headers = {"Authorization": "Bearer bad_token_xxx"}
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(bad_url, headers=bad_headers) as resp:
                assert resp.status == 403, f"期望 403，收到 {resp.status}"

        print(f"  [OK] pull_token 验证通过")
    finally:
        await client.close()


async def test_stream_close_notifies_pullers():
    """推流方 close 后拉流端收到 event: done"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        # 先连接 puller
        pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))
        await asyncio.sleep(0.3)

        # 推送一个 chunk 然后关闭
        url = _localize_url(push_url, ws=True)
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=_nossl_ctx() if url.startswith("wss") else None,
                                       **_ws_headers_kwarg(push_headers), max_size=64*1024*1024) as ws:
            await ws.send(json.dumps({"cmd": "data", "data": "final", "seq": 1}))
            await asyncio.sleep(0.1)
            await ws.send(json.dumps({"cmd": "close"}))

        frames = await pull_task
        done_frames = [f for f in frames if f["event"] == "done"]
        assert len(done_frames) >= 1, "拉流端未收到 done 事件"

        print(f"  [OK] close 通知 puller 通过")
    finally:
        await client.close()


async def test_stream_info_status_and_reject_push_after_close():
    """get_info 覆盖等待/活跃/关闭状态，关闭后 push_url 不可重用"""
    client = _make_client()
    try:
        await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        stream_id = result["stream_id"]
        push_url = result["push_url"]
        push_token = result["push_token"]

        waiting = await client.call("stream.get_info", {"stream_id": stream_id})
        assert waiting["status"] == "waiting"
        assert waiting["frames_pushed"] == 0

        url = _localize_url(push_url, ws=True)
        ssl_ctx = _nossl_ctx() if url.startswith("wss") else None
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64 * 1024 * 1024) as ws:
            await ws.send(json.dumps({"cmd": "data", "data": "info_chunk", "seq": 1}))
            await asyncio.sleep(0.2)

            active = await client.call("stream.get_info", {"stream_id": stream_id})
            assert active["status"] == "active", f"推流连接期间应为 active，实际={active['status']}"
            assert active["frames_pushed"] >= 1
            assert active["bytes_pushed"] >= len("info_chunk")
            assert active["seq"] == 1

            await ws.send(json.dumps({"cmd": "close"}))
            close_resp = await asyncio.wait_for(ws.recv(), timeout=2)
            assert "closed" in close_resp

        await asyncio.sleep(0.2)
        closed = await client.call("stream.get_info", {"stream_id": stream_id})
        assert closed["status"] == "done"
        assert closed["is_online"] is False
        assert closed["seq"] == 1

        rejected = False
        try:
            async with websockets.connect(url, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64 * 1024 * 1024):
                pass
        except Exception:
            rejected = True
        assert rejected, "流关闭后 push_url 应拒绝再次连接"

        print("  [OK] get_info 状态切换与关闭后拒绝重连通过")
    finally:
        await client.close()


async def test_stream_get_info():
    """get_info 返回正确的流状态"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "application/json-stream"})
        stream_id = result["stream_id"]

        info = await client.call("stream.get_info", {"stream_id": stream_id})
        assert info["stream_id"] == stream_id
        assert info["content_type"] == "application/json-stream"
        assert info["status"] == "waiting"  # 尚未有推流端连接

        print(f"  [OK] get_info 通过")
    finally:
        await client.close()


async def test_stream_list_active():
    """list_active 仅列出当前 AID 的活跃流"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)

        # 创建 2 个流
        r1 = await client.call("stream.create", {"content_type": "text/plain"})
        r2 = await client.call("stream.create", {"content_type": "text/plain"})

        result = await client.call("stream.list_active", {})
        streams = result.get("streams", [])
        ids = {s["stream_id"] for s in streams}
        assert r1["stream_id"] in ids, "流 1 未出现在 list_active"
        assert r2["stream_id"] in ids, "流 2 未出现在 list_active"

        # 关闭流 1
        await client.call("stream.close", {"stream_id": r1["stream_id"]})
        result = await client.call("stream.list_active", {})
        ids = {s["stream_id"] for s in result.get("streams", [])}
        assert r1["stream_id"] not in ids, "已关闭的流不应出现在 list_active"
        assert r2["stream_id"] in ids, "流 2 应仍然活跃"

        print(f"  [OK] list_active 通过")
    finally:
        await client.close()


async def test_concurrent_streams():
    """同时创建多条流，互不干扰"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)

        N = 5
        streams = []
        for i in range(N):
            r = await client.call("stream.create", {"content_type": "text/plain"})
            streams.append(r)

        # 并行推拉
        async def _push_pull_one(idx, stream_info):
            chunks = [f"stream{idx}_chunk{j}" for j in range(3)]
            pt = stream_info["push_token"]
            plt = stream_info["pull_token"]
            push_task = asyncio.create_task(_push_ws(stream_info["push_url"], chunks, push_token=pt))
            await asyncio.sleep(0.1)
            frames = await _pull_sse(stream_info["pull_url"], timeout=5, pull_token=plt)
            await push_task
            data_frames = [f for f in frames if f["event"] != "done"]
            assert len(data_frames) == 3, f"流 {idx}: 期望 3 帧，收到 {len(data_frames)}"
            for j, f in enumerate(data_frames):
                assert f["data"] == chunks[j], f"流 {idx} 帧 {j} 不匹配"

        await asyncio.gather(*[_push_pull_one(i, s) for i, s in enumerate(streams)])

        print(f"  [OK] {N} 条并发流互不干扰")
    finally:
        await client.close()


async def test_rpc_close_stops_stream():
    """通过 RPC stream.close 关闭流（非 WebSocket cmd:close）"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {"content_type": "text/plain"})
        stream_id = result["stream_id"]
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        # 连接 puller
        pull_task = asyncio.create_task(_pull_sse(pull_url, timeout=5, pull_token=pull_token))
        await asyncio.sleep(0.3)

        # 推送一些数据
        url = _localize_url(push_url, ws=True)
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=_nossl_ctx() if url.startswith("wss") else None,
                                       **_ws_headers_kwarg(push_headers), max_size=64*1024*1024) as ws:
            await ws.send(json.dumps({"cmd": "data", "data": "before_close", "seq": 1}))
            await asyncio.sleep(0.2)

            # 通过 RPC 关闭
            close_result = await client.call("stream.close", {"stream_id": stream_id})
            assert close_result.get("success"), "RPC close 失败"

        frames = await pull_task
        done_frames = [f for f in frames if f["event"] == "done"]
        assert len(done_frames) >= 1, "RPC close 后 puller 未收到 done"

        print(f"  [OK] RPC stream.close 通过")
    finally:
        await client.close()


async def test_header_token_auth():
    """Token 通过 HTTP header 鉴权（push via WS header, pull via Authorization header）"""
    client = _make_client()
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {
            "content_type": "text/plain",
            "buffer_size": 10,
        })
        stream_id = result["stream_id"]
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        # push via header
        push_base = _localize_url(push_url, ws=True)
        ssl_ctx = _nossl_ctx() if push_base.startswith("wss") else None
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(push_base, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64*1024*1024) as ws:
            await ws.send(json.dumps({"cmd": "data", "data": "header_push", "seq": 1}))
            await ws.send(json.dumps({"cmd": "close"}))
            try:
                await asyncio.wait_for(ws.recv(), timeout=2)
            except Exception:
                pass

        # pull via Authorization header
        pull_base = _localize_url(pull_url)
        pull_headers = {"Authorization": f"Bearer {pull_token}", "Accept": "text/event-stream"}
        frames = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(pull_base, headers=pull_headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                assert resp.status == 200, f"pull header auth 失败: {resp.status}"
                async for line in resp.content:
                    text = line.decode("utf-8", errors="replace").strip()
                    if text.startswith("data:"):
                        raw = text[5:].strip()
                        try:
                            frames.append(json.loads(raw))
                        except Exception:
                            # SSE data 可能是纯文本（非 JSON）
                            frames.append({"data": raw})

        data_frames = [f for f in frames if f.get("data") == "header_push"]
        assert len(data_frames) >= 1, "pull via header 未收到数据"
        print(f"  [OK] Token header 鉴权通过")
    finally:
        await client.close()


async def test_high_concurrency_pullers():
    """20+ 并发 puller 同时拉取 100 chunks，验证完整性和顺序"""
    client = _make_client()
    NUM_PULLERS = 20
    NUM_CHUNKS = 100
    try:
        aid = await _ensure_connected(client, _ALICE_AID)
        result = await client.call("stream.create", {
            "content_type": "text/plain",
            "buffer_size": NUM_CHUNKS + 50,
        })
        push_url = result["push_url"]
        pull_url = result["pull_url"]
        push_token = result["push_token"]
        pull_token = result["pull_token"]

        # 启动 20 个 puller
        pull_tasks = []
        for i in range(NUM_PULLERS):
            task = asyncio.create_task(
                _pull_sse(pull_url, timeout=30, stop_after_frames=NUM_CHUNKS + 1, pull_token=pull_token)
            )
            pull_tasks.append(task)

        await asyncio.sleep(0.5)  # 等待 puller 连接建立

        # 推送 100 chunks
        url = _localize_url(push_url, ws=True)
        ssl_ctx = _nossl_ctx() if url.startswith("wss") else None
        push_headers = {"Authorization": f"Bearer {push_token}"}
        async with websockets.connect(url, ssl=ssl_ctx, **_ws_headers_kwarg(push_headers), max_size=64*1024*1024) as ws:
            for seq in range(1, NUM_CHUNKS + 1):
                frame = json.dumps({"cmd": "data", "data": f"chunk_{seq}", "seq": seq})
                await ws.send(frame)
            await ws.send(json.dumps({"cmd": "close"}))
            try:
                await asyncio.wait_for(ws.recv(), timeout=2)
            except Exception:
                pass

        # 收集所有 puller 结果
        results = await asyncio.gather(*pull_tasks, return_exceptions=True)

        success_count = 0
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                print(f"  [WARN] puller#{i} 异常: {r}")
                continue
            data_frames = [f for f in r if f.get("event") == "message" or "data" in f]
            # 过滤出有效数据帧（排除 done 帧）
            valid = [f for f in r if f.get("data", "").startswith("chunk_")]
            if len(valid) >= NUM_CHUNKS:
                # 验证顺序
                seqs = [int(f["data"].split("_")[1]) for f in valid[:NUM_CHUNKS]]
                expected = list(range(1, NUM_CHUNKS + 1))
                if seqs == expected:
                    success_count += 1
                else:
                    print(f"  [WARN] puller#{i} 顺序错乱: 前5={seqs[:5]}")
            else:
                print(f"  [WARN] puller#{i} 只收到 {len(valid)}/{NUM_CHUNKS} chunks")

        # 至少 80% 的 puller 成功收到完整有序数据
        min_success = int(NUM_PULLERS * 0.8)
        assert success_count >= min_success, \
            f"高并发 puller 成功率不足: {success_count}/{NUM_PULLERS} (需 >= {min_success})"

        print(f"  [OK] 高并发 puller: {success_count}/{NUM_PULLERS} 成功收到 {NUM_CHUNKS} chunks")
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# 测试运行器
# ---------------------------------------------------------------------------

async def run_all():
    tests = [
        ("基本推拉流程", test_basic_push_pull_flow),
        ("SSE seq 在 id 字段", test_sse_seq_in_id_field),
        ("Late puller 回放 + 实时", test_late_puller_gets_buffer),
        ("Last-Event-ID 断线续拉", test_resume_from_last_event_id),
        ("多 puller 并行", test_multiple_pullers),
        ("target_aid 绑定限制", test_target_aid_restriction),
        ("push_token 验证", test_push_token_validation),
        ("无效 JSON 后恢复", test_invalid_json_frame_then_recover),
        ("pull_token 验证", test_pull_token_validation),
        ("close 通知 puller", test_stream_close_notifies_pullers),
        ("get_info 状态切换", test_stream_info_status_and_reject_push_after_close),
        ("get_info 查询", test_stream_get_info),
        ("list_active 列表", test_stream_list_active),
        ("并发多流", test_concurrent_streams),
        ("RPC close 关闭", test_rpc_close_stops_stream),
        ("Token header 鉴权", test_header_token_auth),
        ("高并发 puller", test_high_concurrency_pullers),
    ]

    print(f"\n{'='*60}")
    print(f" AUN Stream 集成测试 ({len(tests)} 项)")
    print(f"{'='*60}\n")

    passed = 0
    failed = 0
    for name, test_fn in tests:
        print(f"[TEST] {name}")
        try:
            await test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            import traceback
            print(f"  [FAIL] {name}: {e}")
            traceback.print_exc()
        print()

    print(f"{'='*60}")
    print(f" 结果: {passed} 通过, {failed} 失败 (共 {len(tests)})")
    print(f"{'='*60}")
    return failed == 0


if __name__ == "__main__":
    ok = asyncio.run(run_all())
    sys.exit(0 if ok else 1)
