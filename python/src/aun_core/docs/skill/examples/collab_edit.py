"""
协作层（collab）
================

演示 client.collab（CollabClient 门面）的版本化文档协作：
create / show / commit（乐观锁）/ merge（撞版本）/ log / tag.create。

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

    # ── show：读当前内容 + version（commit 的 onto 来源） ──
    cur = await collab.show(root, "design.md")
    print(f"[show] version={cur['version']} author={cur['author']}")

    # ── commit：乐观锁提交新版本 ──
    res = await collab.commit(root, "design.md", "./design.md", cur["version"])
    if res["ok"]:
        print(f"[commit] 成功 version={res['version']}")
    else:
        # 撞版本：数据已安全保存，merge 后用 current_version 作新 onto 重提
        print(f"[commit] 撞版本，当前 version={res['current_version']}")
        await collab.merge(root, "design.md", "./design.md", cur["version"])
        res = await collab.commit(root, "design.md", "./design.md", res["current_version"])
        print(f"[resubmit] version={res['version']}")

    # ── log：查版本台账 ──
    history = await collab.log(root, "design.md")
    print(f"[log] {len(history)} 个版本")

    # ── tag.create：目录级标签（语义化版本自动判定） ──
    snap = await collab.tag.create(root, message="里程碑 v1")
    print(f"[tag.create] version={snap['version']} bump={snap['bump']}")

    await close_clients(client)


asyncio.run(main())
