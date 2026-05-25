"""
诊断 V2 P2P Push 自动接收失败问题
使用 trace 功能追踪消息发送和事件推送的完整路径
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from aun_core.client import AUNClient

async def main():
    # 初始化客户端
    aun_path = os.environ.get("AUN_DATA_ROOT", "/data/aun/single-domain/persistent")
    alice = AUNClient(path=aun_path, aid="alice.agentid.pub", debug=True)
    bob = AUNClient(path=aun_path, aid="bobb.agentid.pub", debug=True)
    
    print("\n[SETUP] 连接 Alice 和 Bob...")
    await alice.connect()
    await bob.connect()
    
    # 启用 trace
    alice.set_trace_mode("diag")
    bob.set_trace_mode("diag")
    
    print("\n[TEST] Alice 发送加密消息给 Bob（期望触发 push）")
    result = await alice.call("message.send", {
        "to": "bobb.agentid.pub",
        "payload": {"text": "push-trace-test"},
        "encrypted": True,
    })
    
    print(f"\n[RESULT] Send result:")
    print(f"  message_id: {result.get('message_id')}")
    print(f"  status: {result.get('status')}")
    print(f"  delivery_mode: {result.get('delivery_mode')}")
    
    if "trace_info" in result:
        trace = result["trace_info"]["trace"]
        print(f"\n[TRACE] Trace ID: {trace['trace_id']}")
        print(f"[TRACE] Spans ({len(trace.get('spans', []))}):")
        for i, span in enumerate(trace.get("spans", [])):
            node = span.get("node", "?")
            action = span.get("action", "?")
            ms = span.get("ms", "?")
            print(f"  [{i}] {node}.{action} ms={ms}")
    
    print("\n[WAIT] 等待 2 秒接收 push 事件...")
    await asyncio.sleep(2)
    
    events = bob.get_events()
    print(f"\n[EVENTS] Bob 收到 {len(events)} 个事件:")
    for evt in events:
        event_name = evt.get("event", "?")
        print(f"  - {event_name}")
        if event_name == "message.received":
            data = evt.get("data", {})
            print(f"    message_id: {data.get('message_id')}")
            print(f"    from: {data.get('from')}")
        if "_trace" in evt:
            trace = evt["_trace"]
            print(f"    trace_id: {trace.get('trace_id')}")
    
    if len(events) == 0:
        print("\n[FAIL] 未收到任何事件！")
        print("[DEBUG] 检查 Bob 的连接状态和订阅...")
        # 这里可以添加更多诊断信息
    
    await alice.disconnect()
    await bob.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
