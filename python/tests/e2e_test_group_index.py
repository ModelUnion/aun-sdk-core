#!/usr/bin/env python3
"""group.index 域 E2E 入口，复用集成测试场景。"""
import asyncio

from integration_test_group_index import main


if __name__ == "__main__":
    asyncio.run(main())
