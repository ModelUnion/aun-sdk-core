#!/usr/bin/env python3
"""手动测试 Message 模块 enter/exit span"""
import asyncio
import json
import websockets

async def test_message_trace():
    """直接连接 Kernel，调用 message RPC 并启用 trace"""
    uri = "ws://127.0.0.1:20000/kernel"

    async with websockets.connect(uri) as ws:
        # 1. 发送 auth（使用 message 模块的身份）
        auth_req = {
            "jsonrpc": "2.0",
            "id": "auth-1",
            "method": "auth",
            "params": {
                "module_name": "test_client",
                "auth_token": "test-token-12345"
            }
        }
        await ws.send(json.dumps(auth_req))
        auth_resp = await ws.recv()
        print(f"Auth response: {auth_resp}")

        # 2. 调用 message.health（简单方法，启用 diag trace）
        health_req = {
            "jsonrpc": "2.0",
            "id": "health-1",
            "method": "message.health",
            "params": {
                "_trace": {
                    "trace_id": "test-trace-001",
                    "request_id": "req-001",
                    "mode": "diag"
                }
            }
        }
        await ws.send(json.dumps(health_req))
        health_resp = await ws.recv()
        resp_obj = json.loads(health_resp)
        print(f"\nHealth response:")
        print(json.dumps(resp_obj, indent=2, ensure_ascii=False))

        # 检查 _trace 字段
        if "_trace" in resp_obj:
            trace = resp_obj["_trace"]
            print(f"\n=== Trace spans ===")
            for span in trace.get("spans", []):
                action = span.get("action", "?")
                node = span.get("node", "?")
                method = span.get("method", "")
                status = span.get("status", "")
                ms = span.get("ms", "")
                print(f"  {node}.{action} method={method} status={status} ms={ms}")

if __name__ == "__main__":
    asyncio.run(test_message_trace())
