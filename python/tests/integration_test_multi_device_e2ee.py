#!/usr/bin/env python3
"""单域多设备 E2EE 专项集成测试。"""

import asyncio
import importlib.util
import sys
from pathlib import Path


def _load_shared_module():
    current = Path(__file__).resolve()
    target = current.with_name("integration_test_e2ee.py")
    spec = importlib.util.spec_from_file_location("integration_test_e2ee_shared", target)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


async def main() -> int:
    shared = _load_shared_module()

    print("=" * 60)
    print("Multi-Device E2EE Integration Tests")
    print("=" * 60)

    tests = [
        ("Multi-device recipient+self", shared.test_multi_device_recipient_and_self_sync),
        ("Multi-device offline pull", shared.test_multi_device_offline_pull),
    ]

    results = []
    for name, fn in tests:
        result = await fn()
        results.append((name, result))
        await asyncio.sleep(0.5)

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, ok in results:
        status = "[PASS]" if ok else "[FAIL]"
        print(f"  {status} {name}")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    if passed == total:
        print("\n[PASS] All multi-device integration tests passed!")
        return 0
    print(f"\n[FAIL] {total - passed} test(s) failed")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
