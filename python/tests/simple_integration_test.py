#!/usr/bin/env python3
"""简化的集成测试 — 验证服务端连通性。

使用方法：
  python tests/simple_integration_test.py

环境变量：
  AUN_GATEWAY_HTTP  — Gateway HTTP URL（默认 http://localhost:20001）
"""
import asyncio
import os
import sys

import aiohttp

GATEWAY_HTTP = os.environ.get("AUN_GATEWAY_HTTP", "http://localhost:20001")


async def test_server_connection():
    """测试服务端连接"""
    print("\n=== 测试: 服务端连通性 ===")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{GATEWAY_HTTP}/health") as resp:
                if resp.status == 200:
                    print("服务端正常运行")
                    return True
                else:
                    print(f"服务端返回 status {resp.status}")
                    return False
    except Exception as e:
        print(f"连接失败: {e}")
        return False


async def main():
    print("=" * 60)
    print("AUN 服务端连通性测试")
    print(f"Gateway: {GATEWAY_HTTP}")
    print("=" * 60)

    results = []
    results.append(await test_server_connection())

    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"通过: {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
