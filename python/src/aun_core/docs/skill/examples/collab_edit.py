"""
协作层（collab）
================

演示 client.collab（CollabClient 门面）的版本化文档协作：
create / read / submit（乐观锁）/ merge（撞版本）/ history / snapshot。

collab 是「锚定在某块存储上的自包含版本化目录」，授权下沉 storage ACL。
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "aun-sdk-core", "python", "src"))

from _helpers import make_client, ensure_connected, close_clients, DEVICE_SHORT


async def main():
    client = make_client("demo-collab")
    aid = await ensure_connected(client, f"demo-collab-{DEVICE_SHORT}.agentid.pub")
    print(f"AID: {aid}\n")

    collab = client.collab  # CollabClient 门面
    root = f"{aid}:/projects/myapp"

    # ── create：创建协作文档（首版本 version=1） ──
    res = await collab.create(root, "design.md", "./design.md")
    print(f"[create] design.md version={res['version']}")

    # ── read：读当前内容 + version（submit 的 base_version 来源） ──
    cur = await collab.read(root, "design.md")
    print(f"[read] version={cur['version']} author={cur['author']}")

    # ── submit：乐观锁提交新版本 ──
    res = await collab.submit(root, "design.md", "./design.md", cur["version"])
    if res["ok"]:
        print(f"[submit] 成功 version={res['version']}")
    else:
        # 撞版本：数据已安全保存，merge 后用 current_version 作新 base_version 重提
        print(f"[submit] 撞版本，当前 version={res['current_version']}")
        await collab.merge(root, "design.md", "./design.md", cur["version"])
        res = await collab.submit(root, "design.md", "./design.md", res["current_version"])
        print(f"[resubmit] version={res['version']}")

    # ── history：查版本台账 ──
    history = await collab.history(root, "design.md")
    print(f"[history] {len(history)} 个版本")

    # ── snapshot：目录级快照（语义化版本自动判定） ──
    snap = await collab.snapshot.create(root, message="里程碑 v1")
    print(f"[snapshot] version={snap['version']} bump={snap['bump']}")

    await close_clients(client)


asyncio.run(main())
