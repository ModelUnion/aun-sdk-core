# group.fs.lstat

查看群文件系统链接节点本身，不跟随链接。参数和返回值同 `group.fs.stat`。

## 调用示例

```python
node = await client.call("group.fs.lstat", {"path": "team.agentid.pub:/docs/latest"})
```

## 相关方法

- [group.fs.stat](group.fs.stat.md) — 跟随链接查看节点
