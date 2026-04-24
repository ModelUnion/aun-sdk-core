# AUN 集成测试与 E2E 运行指南

本文档只说明当前仓库里 AUN 服务与 AUN SDK 在 Docker 单域、双域环境中的集成测试和 E2E 测试运行方式。

## 基本原则

- 不修改 `/etc/hosts`，统一使用 Docker network alias 做域名解析。
- 不硬编码 `gateway_url`，Gateway 统一通过 `https://{issuer}/.well-known/aun-gateway` 或 `http://{issuer}/.well-known/aun-gateway` 发现。
- 服务端对外返回的 URL 必须是 `{svc}.{issuer-domain}` 风格，不能出现 `127.0.0.1`、`localhost`、`0.0.0.0`、`::1`。
- 双域测试脚本统一在 Docker 测试容器里直接运行，不再依赖宿主机 `docker exec` 套娃。
- Windows Git Bash 运行 `docker exec` / `docker run` 且命令里包含容器内绝对路径（如 `/tests/...`、`/test/...`、`/workspace/...`）时，统一在命令前加 `MSYS_NO_PATHCONV=1`，避免 Git Bash 把容器路径错误改写成宿主机路径。
- 单域 Docker 测试容器默认使用 `AUN_TEST_AUN_PATH=/data/aun/single-domain/persistent`，固定身份长期复用统一落在这条路径下。
- 双域固定身份统一落在 `D:\modelunion\kite\docker-deploy\federation-test\client-data`，容器内路径固定为 `/data/aun`。
- **所有语言 SDK 的集成/E2E 测试必须串行运行**，不可并行执行多个测试进程。各语言 SDK 共享同一套 AID 身份材料（私钥、证书、SQLite/SQLCipher 数据库），并行运行会导致数据库锁冲突、密钥材料竞争写入、以及不可预测的认证失败。推荐按 Python → TypeScript → Go → JS 的顺序依次运行。
- 如果改了 `extensions/services` 下的服务端代码，必须重新 build Docker 镜像并重启对应容器。
- 如果只改了 `aun-sdk-core/python/src` 或测试脚本，单域 `sdk-tester`、双域 `client-a/client-b` 都是目录挂载，通常不需要 rebuild 镜像，直接重跑即可。
- `kite-sdk-tester`、`client-a`、`client-b` 使用预构建的 `aun-sdk-tester` 镜像（`Dockerfile.sdk-tester`），已内置所有 Python 测试依赖（含 `sqlcipher3`），`--force-recreate` 后无需手动安装。
- 单域环境当前提供 `kite-sdk-tester`（Python）与 `kite-ts-tester`（TypeScript）常驻测试容器；双域环境提供 `client-a`、`client-b`、`ts-tester`、`go-tester`。
- TS 测试容器（单域 `kite-ts-tester`、双域 `ts-tester`）使用独立 Docker volume 挂载 `/workspace/ts/node_modules`，避免宿主机 Windows `node_modules` 污染 Linux 容器。
- TS 测试容器启动时会检查 `node_modules/better-sqlite3/build/Release/better_sqlite3.node` 是否为 Linux ELF；若缺失或仍是 Windows 二进制，会自动执行 `npm install --legacy-peer-deps` 修复依赖。
- 如果改了 `aun-sdk-core/ts/package.json` 或 `package-lock.json`，需要重建对应 TS 测试容器，或在容器内手动重新执行 `npm install --legacy-peer-deps`。
- Go 在 Linux 容器里运行时，推荐把宿主机 `C:\go\pkg\mod` 只读挂进容器作为 `GOMODCACHE=/go/pkg/mod`，避免测试容器临时联网拉依赖。
- TS/Go 双域 reconnect 测试不是单纯 `docker exec` 一条命令，需要宿主机在测试进程写出 marker 后协调执行 `docker restart federation-kite-b`。

### 测试环境数据保护（最高优先级）

**严格禁止未经用户明确同意的以下操作：**

- **禁止删除或清空 AID 身份材料**：包括私钥（`*.key`）、证书（`*.crt`）、种子文件（`.seed`）、`key.json`、SQLCipher 数据库（`*.db`）等。这些文件一旦丢失，对应 AID 将永久无法恢复。
- **禁止删除或清空持久化身份目录**：包括 `client-data/`、`data/sdk-tester-aun/`、容器内 `/data/aun/` 下的任何 AID 子目录。
- **禁止擅自执行数据库清理命令**：如 `DELETE FROM agentid_cert`、`DROP TABLE` 等。
- **禁止擅自执行 `setup_aids.py` 重建身份**：除非用户明确要求。

**可以安全执行的操作：**

- 读取、查看身份文件和数据库记录（只读）
- 运行测试脚本（测试脚本本身不应修改持久化身份）
- 查看容器日志和状态

**原则：测试环境的固定身份是长期复用资产，不是一次性消耗品。任何涉及身份材料增删改的操作都必须先征得用户同意。**

## 目录约定

- 单域 Docker 环境：`D:\modelunion\kite\docker-deploy`
- 双域 Docker 环境：`D:\modelunion\kite\docker-deploy\federation-test`
- AUN SDK Python 测试：`D:\modelunion\kite\aun-sdk-core\python\tests`
- AUN SDK TypeScript 测试：`D:\modelunion\kite\aun-sdk-core\ts\tests`
- AUN SDK Go 测试：`D:\modelunion\kite\aun-sdk-core\go`
- 双域测试脚本：`D:\modelunion\kite\docker-deploy\federation-test\tests`

## 一次性准备

先构建服务镜像和测试容器镜像：

```powershell
cd D:\modelunion\kite\docker-deploy
docker compose -f docker-compose.build.yml build kite sdk-tester
```

`aun-sdk-tester` 镜像（`Dockerfile.sdk-tester`）已内置所有 Python 测试依赖（含 `sqlcipher3`）。正常情况下，单域 `kite-sdk-tester`、双域 `client-a/client-b` 启动后即可直接运行测试，无需手动安装。

如果因网络或镜像原因 `aun-sdk-tester` 构建失败，回退到裸 `python:3.13-slim` 容器时，需要在首次启动后手动安装依赖（后续只要容器被 `--force-recreate` 重建，也需要重新安装）：

```powershell
docker exec kite-sdk-tester python -m pip install -U pip pytest aiohttp websockets cryptography requests sqlcipher3
docker exec client-a python -m pip install -U pip pytest aiohttp websockets cryptography requests sqlcipher3
docker exec client-b python -m pip install -U pip pytest aiohttp websockets cryptography requests sqlcipher3
```

如果只是重启服务容器 `kite` / `kite-a` / `kite-b`，而没有重建 `sdk-tester`、`client-a`、`client-b`，不需要重新安装依赖。使用预构建的 `aun-sdk-tester` 镜像时，即使 `--force-recreate` 也无需手动补依赖，因为依赖已烘焙在镜像中。

双域固定身份的持久化目录：

- 宿主机：`D:\modelunion\kite\docker-deploy\federation-test\client-data`
- 容器内：`/data/aun`

固定身份默认约定：

- `alice.aid.com`
- `bobb.aid.net`
- `charlie.aid.com`
- `dave.aid.net`

## 单域环境

### 启动

```powershell
cd D:\modelunion\kite\docker-deploy
docker compose up -d
```

当前 `docker-compose.yml` 已为 `kite` 服务配置这些 network aliases：

- `agentid.pub`
- `gateway.agentid.pub`
- `stream.agentid.pub`
- `storage.agentid.pub`
- `group.agentid.pub`

并额外提供测试容器 `kite-sdk-tester`（Python）和 `kite-ts-tester`（TypeScript），用于在同一 Docker 网络内直接跑 SDK 集成测试。

当前单域 `kite-sdk-tester` 默认环境变量：

- `AUN_TEST_AUN_PATH=/data/aun/single-domain/persistent`
- `AUN_DATA_ROOT=/data/aun`

单域固定身份的**唯一有效目录**是：

- 容器内：`/data/aun/single-domain/persistent`
- 宿主机：`D:\modelunion\kite\docker-deploy\data\sdk-tester-aun\single-domain\persistent`

`docker-compose.yml`、单域固定 AID 测试脚本、以及本文档都必须以这条路径为唯一真源，不能再让固定身份在 `single-domain/AIDs/...` 和 `single-domain/persistent/AIDs/...` 之间分叉。

如果历史目录中还残留 `single-domain/AIDs/...`，应视为旧格式脏数据，不再继续复用，也不要把其中的文件和 `persistent` 目录混拷。

### 进入测试容器

```powershell
docker exec -it kite-sdk-tester sh
docker exec -it kite-ts-tester bash
```

容器内约定：

- SDK 源码：`/sdk/src`
- 测试目录：`/tests`
- `PYTHONPATH=/sdk/src`
- 固定身份目录唯一使用 `/data/aun/single-domain/persistent`
- `kite-ts-tester` 挂载 `D:\modelunion\kite\aun-sdk-core\ts -> /workspace/ts`
- `kite-ts-tester` 的 `/workspace/ts/node_modules` 使用容器内独立 volume，与宿主机 Windows `node_modules` 隔离
- `kite-ts-tester` 使用独立的数据目录（`/data/aun`），不与 Python `kite-sdk-tester` 共享身份数据。Python SDK 使用 SQLCipher 加密数据库，TS SDK 使用 better-sqlite3（无加密），两者的本地存储格式不兼容，共用会导致"数据库损坏"错误。

### 典型测试命令

直接运行脚本：

```powershell
# Windows Git Bash 下运行时统一加 MSYS_NO_PATHCONV=1
MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_stream.py
MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/test_integration_auth_flow.py
MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_e2ee.py
MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_multi_device_e2ee.py
MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/e2e_test_group_e2ee.py
```

其中固定 AID 单域测试脚本默认会优先使用 `AUN_DATA_ROOT/single-domain/persistent`。如果检测到旧目录残留或固定身份只有半套文件，会直接报错并停止，而不是继续运行把环境写得更脏。

运行 pytest：

```powershell
docker exec kite-sdk-tester python -m pytest /tests/unit -q -p no:cacheprovider
docker exec kite-sdk-tester python -m pytest /tests/test_integration_auth_flow.py -q -p no:cacheprovider
```

### 特别说明：重连测试

`python/tests/integration_test_reconnect.py` 需要直接执行这些宿主机命令：

- `docker compose restart kite`
- `docker network disconnect docker-deploy_kite-net kite-app`
- `docker network connect docker-deploy_kite-net kite-app`

所以它应在宿主机运行，而不是 `kite-sdk-tester` 容器内运行：

```powershell
cd D:\modelunion\kite\aun-sdk-core\python
python tests/integration_test_reconnect.py
```

运行前要确保宿主机能够解析 `gateway.agentid.pub`。推荐方式不是改 hosts，而是让测试进程也运行在 Docker 网络内；如果必须在宿主机直跑，请确保你已有等效域名解析方案。

### TypeScript 集成 / E2E

单域当前提供常驻 `kite-ts-tester` 服务。容器启动时会自动校验并修复 Linux 版 `better-sqlite3` 依赖，因此直接在容器内运行即可。

集成测试：

```powershell
MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc "cd /workspace/ts && npx vitest run tests/integration/e2ee.test.ts"
```

E2E 测试：

```powershell
MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc "cd /workspace/ts && npx vitest run tests/e2e/group-e2ee.test.ts"
```

Gap 补洞测试（P2P + 群消息）：

```powershell
MSYS_NO_PATHCONV=1 docker exec -w /workspace/ts kite-ts-tester node_modules/.bin/vitest run tests/integration/message-gap.test.ts tests/integration/group-gap.test.ts
```

gap 测试每次运行使用随机动态 AID + 临时目录，不依赖固定身份，也不需要 `AUN_TEST_AUN_PATH`。

单域 reconnect 集成测试当前由宿主机 Node 进程直接协调 `docker compose restart kite`，不适合放进临时 Docker 测试容器：

```powershell
cd D:\modelunion\kite\aun-sdk-core\ts
npm install
npx vitest run tests/integration/reconnect.test.ts
```

运行这条 reconnect 用例前，要确保宿主机本身能解析 `agentid.pub`、`gateway.agentid.pub`，否则请先准备等效域名解析方案。

### Go 集成 / E2E

单域 Go 测试同样通过临时容器接入 `docker-deploy_kite-net`。下面命令默认复用宿主机 `C:\go\pkg\mod` 作为只读模块缓存。Windows Git Bash 下运行时统一在命令前加 `MSYS_NO_PATHCONV=1`。

集成测试：

```powershell
MSYS_NO_PATHCONV=1 docker run --rm --network docker-deploy_kite-net `
  -v D:\modelunion\kite\aun-sdk-core\go:/workspace/go `
  -v C:\go\pkg\mod:/go/pkg/mod:ro `
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= -e NO_PROXY=* `
  -e GOMODCACHE=/go/pkg/mod `
  -e GOCACHE=/workspace/go/.codex_gocache_linux `
  -e GOTMPDIR=/workspace/go/.codex_gotmp_linux `
  golang:1.22-bookworm sh -lc "mkdir -p /workspace/go/.codex_gocache_linux /workspace/go/.codex_gotmp_linux && cd /workspace/go && /usr/local/go/bin/go test -tags integration . -run Integration -count=1 -v"
```

E2E 测试：

```powershell
MSYS_NO_PATHCONV=1 docker run --rm --network docker-deploy_kite-net `
  -v D:\modelunion\kite\aun-sdk-core\go:/workspace/go `
  -v C:\go\pkg\mod:/go/pkg/mod:ro `
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= -e NO_PROXY=* `
  -e GOMODCACHE=/go/pkg/mod `
  -e GOCACHE=/workspace/go/.codex_gocache_linux `
  -e GOTMPDIR=/workspace/go/.codex_gotmp_linux `
  golang:1.22-bookworm sh -lc "mkdir -p /workspace/go/.codex_gocache_linux /workspace/go/.codex_gotmp_linux && cd /workspace/go && /usr/local/go/bin/go test -tags integration . -run GroupE2E -count=1 -v"
```

Go 当前还没有单域 Docker reconnect 用例；单域侧目前覆盖的是 `integration_test.go` 和 `e2e_group_test.go`。

## 双域环境

### 启动

```powershell
cd D:\modelunion\kite\docker-deploy\federation-test
docker compose up -d
```

当前双域编排会把 `kite-a`、`kite-b` 放进同一个 `federation-net` 网络，并配置这些 aliases：

- `aid.com`
- `gateway.aid.com`
- `stream.aid.com`
- `storage.aid.com`
- `group.aid.com`
- `aid.net`
- `gateway.aid.net`
- `stream.aid.net`
- `storage.aid.net`
- `group.aid.net`

所以 `client-a`、`client-b` 可以直接在容器网络里解析两个域的 Name Service、Gateway、Stream、Storage、Group。

### 进入测试容器

```powershell
docker exec -it client-a sh
docker exec -it client-b sh
docker exec -it ts-tester bash
docker exec -it go-tester sh
```

容器内约定：

- 测试目录：`/test`
- SDK 源码：`/sdk/src`
- 持久化身份目录：`/data/aun`
- `AUN_DATA_ROOT=/data/aun`
- `PYTHONPATH=/sdk/src`
- `ts-tester` 挂载 `D:\modelunion\kite\aun-sdk-core\ts -> /workspace/ts`
- `ts-tester` 的 `/workspace/ts/node_modules` 使用容器内独立 volume，与宿主机 Windows `node_modules` 隔离
- `go-tester` 挂载 `D:\modelunion\kite\aun-sdk-core\go -> /workspace/go`

### 建议执行顺序

默认不要清理固定 AID 的数据库记录。固定身份的目标就是长期复用，只有在确认本地持久化身份与数据库中的证书记录发生脏数据冲突时，才执行下面的清理步骤。

典型的“脏数据冲突”包括：

- 本地 `client-data` 中已有固定 AID 身份，但数据库中存在另一份不匹配的旧证书记录。
- 同一个固定 AID 被不同机器、不同目录或历史脚本重复创建，导致本地私钥与服务端证书不再配套。

只有出现以上冲突时，才清理数据库中的固定 AID 证书记录：

```powershell
docker exec federation-mysql-a mysql -uroot -proot aun_cert -e "delete from agentid_cert where agentid in ('alice.aid.com','bob.aid.net','bobb.aid.net','charlie.aid.com','dave.aid.net');"
docker exec federation-mysql-b mysql -uroot -proot aun_cert -e "delete from agentid_cert where agentid in ('alice.aid.com','bob.aid.net','bobb.aid.net','charlie.aid.com','dave.aid.net');"
```

然后准备固定测试身份：

```powershell
docker exec client-a python /test/setup_aids.py
```

再跑基础连通性与 discovery 回归：

```powershell
docker exec client-a python /test/federation_ping.py
docker exec client-a python /test/gateway_to_gateway.py
docker exec client-a python /test/cross_domain_p2p.py
docker exec client-a python /test/e2e_plaintext.py
```

再跑主要业务路径：

```powershell
docker exec client-a python /test/cross_domain_stream.py
docker exec client-a python /test/e2e_offline.py
docker exec client-a python /test/e2e_encrypted.py
docker exec client-a python /test/test_e2ee_cross_domain.py
docker exec client-a python /test/e2e_group.py
docker exec client-a python /test/e2e_storage.py
```

以下测试脚本内部会调用 `docker exec` 操作另一个容器（"套娃"模式），**必须在宿主机 PowerShell 中运行**，不能在容器内运行：

```powershell
# 宿主机 PowerShell 执行（Windows Git Bash 下加 MSYS_NO_PATHCONV=1）
docker exec client-a python /test/e2e_real.py
docker exec client-a python /test/e2e_comprehensive.py
docker exec client-a python /test/e2e_coverage_gaps.py
```

这三个脚本都需要容器内能访问 `docker` CLI，当前 `aun-sdk-tester` 镜像未内置 Docker CLI，因此暂时无法在容器内直接运行。如需运行，可在宿主机安装 Docker SDK 后从宿主机直接执行。

`client-b` 与 `client-a` 共享同一个 `/data/aun` 宿主持久化目录，因此如需从另一侧复核，也可以在 `client-b` 中对称执行。

### TypeScript 集成 / E2E

普通双域集成与 E2E 直接在 `ts-tester` 容器里运行即可。容器启动时会自动校验并修复 Linux 版 `better-sqlite3` 依赖。

```powershell
MSYS_NO_PATHCONV=1 docker exec ts-tester bash -lc "cd /workspace/ts && npx vitest run tests/integration/federation.test.ts tests/integration/federation-storage.test.ts"
```

双域 reconnect 需要宿主机配合重启远端域 `kite-b`。推荐在宿主机 PowerShell 执行：

```powershell
$marker = 'D:\modelunion\kite\aun-sdk-core\ts\.codex_fed_reconnect_marker_ts'
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
$job = Start-Job -ScriptBlock {
  docker exec ts-tester bash -lc "cd /workspace/ts && AUN_RECONNECT_MARKER=/workspace/ts/.codex_fed_reconnect_marker_ts npx vitest run tests/integration/federation-reconnect.test.ts"
}
while (-not (Test-Path -LiteralPath $marker)) { Start-Sleep -Seconds 1 }
docker restart federation-kite-b
Wait-Job $job
Receive-Job $job
Remove-Job $job
```

### Go 集成 / E2E

普通双域 Go 用例可以直接跑完整 `Federation` 子集；如果没有设置 `AUN_RECONNECT_MARKER`，reconnect 子用例会自动跳过，只执行 message/group/storage 这几类普通双域场景。Windows Git Bash 下运行时统一在命令前加 `MSYS_NO_PATHCONV=1`。

```powershell
MSYS_NO_PATHCONV=1 docker run --rm --network federation-test_federation-net `
  -v D:\modelunion\kite\aun-sdk-core\go:/workspace/go `
  -v C:\go\pkg\mod:/go/pkg/mod:ro `
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= -e NO_PROXY=* `
  -e GOMODCACHE=/go/pkg/mod `
  -e GOCACHE=/workspace/go/.codex_gocache_linux `
  -e GOTMPDIR=/workspace/go/.codex_gotmp_linux `
  golang:1.22-bookworm sh -lc "mkdir -p /workspace/go/.codex_gocache_linux /workspace/go/.codex_gotmp_linux && cd /workspace/go && /usr/local/go/bin/go test -tags integration . -run Federation -count=1 -v"
```

如果要把双域 reconnect 也纳入同一轮验证，推荐在宿主机 PowerShell 用 marker 协调远端域重启：

```powershell
$marker = 'D:\modelunion\kite\aun-sdk-core\go\.codex_fed_reconnect_marker_go'
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
$job = Start-Job -ScriptBlock {
  docker run --rm --network federation-test_federation-net -v D:\modelunion\kite\aun-sdk-core\go:/workspace/go -v C:\go\pkg\mod:/go/pkg/mod:ro -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= -e NO_PROXY=* -e AUN_RECONNECT_MARKER=/workspace/go/.codex_fed_reconnect_marker_go -e GOMODCACHE=/go/pkg/mod -e GOCACHE=/workspace/go/.codex_gocache_linux -e GOTMPDIR=/workspace/go/.codex_gotmp_linux golang:1.22-bookworm sh -lc "mkdir -p /workspace/go/.codex_gocache_linux /workspace/go/.codex_gotmp_linux && cd /workspace/go && /usr/local/go/bin/go test -tags integration . -run FederationReconnect -count=1 -v"
}
while (-not (Test-Path -LiteralPath $marker)) { Start-Sleep -Seconds 1 }
docker restart federation-kite-b
Wait-Job $job
Receive-Job $job
Remove-Job $job
```

## 何时需要 rebuild / restart

### 改了服务端代码

例如修改了这些目录中的任意内容：

- `D:\modelunion\kite\extensions\services\gateway`
- `D:\modelunion\kite\extensions\services\nameservice`
- `D:\modelunion\kite\extensions\services\stream`
- `D:\modelunion\kite\extensions\services\storage`
- `D:\modelunion\kite\extensions\services\group`
- 其他 AUN 服务模块

需要重新 build 镜像：

```powershell
cd D:\modelunion\kite\docker-deploy
docker compose -f docker-compose.build.yml build kite
```

单域重启：

```powershell
cd D:\modelunion\kite\docker-deploy
docker compose up -d --force-recreate kite sdk-tester
```

双域重启：

```powershell
cd D:\modelunion\kite\docker-deploy\federation-test
docker compose up -d --force-recreate kite-a kite-b client-a client-b
```

使用预构建的 `aun-sdk-tester` 镜像时，`--force-recreate` 不会丢失依赖，无需手动重装。

### 只改了 SDK 或测试脚本

通常不需要 rebuild，直接重跑测试即可。因为：

- 单域 `sdk-tester` 挂载了 `../aun-sdk-core/python/src` 和 `../aun-sdk-core/python/tests`
- 双域 `client-a/client-b` 挂载了 `../../aun-sdk-core/python/src` 和 `./tests`

## 故障排查

- 先看 Name Service 的 `/.well-known/aun-gateway` 是否能返回非 loopback 的 Gateway URL。
- 再看测试容器内是否能解析 `gateway.{issuer}`、`stream.{issuer}`、`storage.{issuer}`、`group.{issuer}`。
- 如果测试脚本拿到的是 `127.0.0.1` 或 `localhost`，优先视为服务端 URL 生成逻辑有 bug，而不是测试环境问题。
- 如果固定 `alice.aid.com` / `bobb.aid.net` 登录失败，先区分两种情况：
- 如果是”本地身份存在，但数据库里没有对应证书记录”，不要清库。这不是脏数据冲突，而是服务端登记缺失。应以本地持久化身份为准，执行一次补登记或导入，把现有证书恢复到数据库。
- 如果是”本地身份与数据库中的证书不匹配”，这才属于脏数据冲突。此时再清理上面的固定 AID 记录，然后重新执行 `/test/setup_aids.py`。
- 如果改了服务端代码但测试结果没变化，通常是镜像没 rebuild 或容器没重启。
- 双域问题优先分别检查 `client-a -> aid.com`、`client-a -> aid.net`、`client-b -> aid.net`、`client-b -> aid.com` 四条路径。
- TS 如果在 Linux 容器里直接使用宿主机 `node_modules`，优先怀疑原生模块 ABI 不匹配，而不是业务代码本身。
- Go 如果在容器里跑测试时开始重新联网下载模块，优先检查 `C:\go\pkg\mod -> /go/pkg/mod` 的只读挂载和 `GOMODCACHE=/go/pkg/mod` 是否生效。

### 常见踩坑

- **`ModuleNotFoundError: No module named 'sqlcipher3'`**：SDK 依赖 `sqlcipher3`，`Dockerfile.sdk-tester` 中通过 `sqlcipher3-binary` 安装（自带预编译库，无需系统级 `libsqlcipher-dev`）。如果手动 pip 安装，使用 `pip install sqlcipher3-binary` 而不是 `pip install sqlcipher3`（后者需要编译环境）。
- **`message.send does not accept delivery_mode`**：SDK 新版本要求 `delivery_mode` 在 `connect()` 时配置，不能在 `message.send` 参数中传入。测试脚本中的 `”delivery_mode”: {“mode”: “fanout”}` 应从 `message.send` 调用中移除，改到 `make_client()` 或 `connect()` 参数中。
- **套娃型测试报 `FileNotFoundError: 'docker'`**：`e2e_real.py`、`e2e_comprehensive.py`、`e2e_coverage_gaps.py` 内部调用 `docker exec` 操控其他容器。这些脚本必须在宿主机运行（`python tests/e2e_xxx.py`），不能通过 `docker exec client-a python /test/...` 在容器内执行。
- **`sqlcipher_page_cipher: hmac check failed`**：SQLCipher 数据库文件的加密密钥与当前 `.seed` 不匹配。通常是多个测试进程使用不同 seed 访问了同一个 `.db` 文件。临时 AID（非固定身份）的数据库可安全删除重建；固定 AID 的数据库需谨慎处理。

## 当前边界

- `integration_test_reconnect.py` 仍是宿主机脚本，不适合放进测试容器。
- `ts/tests/integration/reconnect.test.ts` 也是宿主机协调型测试，用于控制单域 `docker compose restart kite`，不适合直接塞进单域临时测试容器。
- Go 当前没有单域 Docker reconnect 用例；双域 reconnect 已通过 `federation_reconnect_test.go` 覆盖。
- 浏览器版 JS SDK 当前只有 skip 的占位集成测试与真实浏览器 E2E 骨架，不属于本文这套常规 Docker 单域/双域回归矩阵；如需执行，应改用 Playwright/Cypress 等真实浏览器方案，并复用同一套 Docker 服务环境。JS SDK 的单元测试可直接在宿主机运行：`cd aun-sdk-core/js && npx vitest run`。
- 双域 `e2e_real.py`、`e2e_comprehensive.py`、`e2e_coverage_gaps.py` 内部会调用 `docker exec` 操控其他容器，需要从宿主机运行，不能在 `client-a/client-b` 容器内执行。
- 其余单域集成测试、双域 federation/E2E 脚本应优先在 Docker 测试容器内运行，以保证与服务端网络环境一致。
