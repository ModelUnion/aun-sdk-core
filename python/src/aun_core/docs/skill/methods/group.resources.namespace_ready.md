# group.resources.namespace_ready

群命名空间初始化回调记账。群主以 group_aid 身份在 storage 建好基线目录（announce/public/archive/memberdata）后，调此方法让 group 服务把根节点镜像入 `group_resources` 表。

> 群存储新架构：storage 是唯一文件系统与唯一鉴权器，`group_resources` 表退化为索引镜像 + 群业务属性。

## 调用示例

```python
result = await client.call("group.resources.namespace_ready", {
    "group_id": "team",
    "folder_ids": {"announce": "fld_1", "public": "fld_2"}
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群 ID |
| `folder_ids` | object | 否 | — | 基线路径 → storage folder_id 映射 |

调用者须为群 owner/admin，或以 group_aid 身份（通过当前群身份签名校验）。

## 返回值

`{group_id, group_aid, namespace_ready: true, baseline_paths: [...], items: [...]}`。

## 相关方法

- [group.resources.confirm](group.resources.confirm.md) — 写操作完成记账
