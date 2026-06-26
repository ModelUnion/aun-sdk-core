"""
Storage POSIX VFS
=================

演示 client.storage（StorageVFS 门面）的类 Linux 文件系统操作：
write_bytes / list / stat / lstat / touch / mkdir / symlink / set_acl / df。

VFS 在对象存储之上提供 ls/find/df/du/stat/lstat/touch/mkdir/rm/mv/cp/mount 语义，
寻址统一为 <AID>:<Unix 绝对路径>。
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "aun-sdk-core", "python", "src"))

from _helpers import make_client, ensure_connected, close_clients, DEVICE_SHORT


async def main():
    client = make_client("demo-vfs")
    aid = await ensure_connected(client, f"demo-vfs-{DEVICE_SHORT}.agentid.pub")
    print(f"AID: {aid}\n")

    fs = client.storage  # StorageVFS 门面

    # ── mkdir：建目录（类 mkdir -p） ──
    await fs.mkdir("projects/myapp", parents=True)
    print("[mkdir] projects/myapp")

    # ── write_bytes：写文件 ──
    await fs.write_bytes("projects/myapp/readme.md", b"# MyApp\n", content_type="text/markdown")
    await fs.write_bytes("projects/myapp/v1.md", b"version 1\n")
    print("[write] readme.md, v1.md")

    # ── list：列目录（ls） ──
    listing = await fs.list("projects/myapp")
    for node in listing.get("nodes", listing.get("items", [])):
        print(f"  {node['type']:7} {node['name']}")

    # ── stat：查节点 ──
    st = await fs.stat("projects/myapp/readme.md")
    print(f"[stat] size={st.get('size')} mtime={st.get('mtime')}")

    # ── symlink：软链进 /public 即对外发布 ──
    await fs.mkdir("public", parents=True)
    await fs.symlink("public/latest.md", "projects/myapp/v1.md")
    print("[symlink] public/latest.md -> projects/myapp/v1.md")

    # ── set_acl：授予他人读写权限 ──
    await fs.set_acl("projects/myapp/", grantee_aid="bob.agentid.pub", perms="rw")
    print("[set_acl] bob 获得 projects/myapp/ 的 rw 权限")

    # ── df：配额/用量 ──
    usage = await fs.df()
    print(f"[df] used={usage.get('used_bytes')} avail={usage.get('avail_bytes')}")

    await close_clients(client)


asyncio.run(main())
