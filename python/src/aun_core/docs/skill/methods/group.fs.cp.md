# group.fs.cp

复制群文件系统节点。支持跨 owner 复制；目录复制需传 `recursive=true`。

## 调用示例

```python
node = await client.call("group.fs.cp", {
    "src": "team.agentid.pub:/docs/a.md",
    "dst": "team.agentid.pub:/archive/a.md",
    "overwrite": True
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `src` / `src_path` | string | 是 | — | 源群路径 |
| `dst` / `dst_path` | string | 是 | — | 目标群路径 |
| `overwrite` / `force` | boolean | 否 | `false` | 目标存在时覆盖 |
| `recursive` | boolean | 否 | `false` | 递归复制目录 |
| `src_group_id` / `src_group_aid` | string | 否 | — | 源裸路径定位 |
| `dst_group_id` / `dst_group_aid` | string | 否 | — | 目标裸路径定位 |

## 返回值

目标节点视图。

## 相关方法

- [group.fs.mv](group.fs.mv.md) — 移动/改名
