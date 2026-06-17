# group.fs.mv

移动或改名群文件系统节点。当前不支持跨 owner move；跨 owner 迁移请使用 `group.fs.cp` 后再删除源。

## 调用示例

```python
node = await client.call("group.fs.mv", {
    "src": "team.agentid.pub:/docs/a.md",
    "dst": "team.agentid.pub:/docs/b.md",
    "overwrite": False
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `src` / `path` | string | 是 | — | 源群路径 |
| `dst` / `dst_path` | string | 是 | — | 目标群路径 |
| `overwrite` / `force` | boolean | 否 | `false` | 目标存在时覆盖 |
| `src_group_id` / `src_group_aid` | string | 否 | — | 源裸路径定位 |
| `dst_group_id` / `dst_group_aid` | string | 否 | — | 目标裸路径定位 |

## 返回值

目标节点视图。跨 owner move 返回 `EXDEV`。

## 相关方法

- [group.fs.cp](group.fs.cp.md) — 复制
- [group.fs.rm](group.fs.rm.md) — 删除
