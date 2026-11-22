# Fishing 架构设计与无 QEMU 多架构构建笔记

## 1. 模块边界与安全隔离

- **数据层（`internal/store`）**：使用 `honeypots.json`（临时文件写入后原子重命名）和 `logs.jsonl`（追加写入 NDJSON），兼顾断电安全与日志可观测性；内存保留最近 10000 条日志用于低延迟检索。
- **SSH 仿真层（`internal/sshpot`）**：
  - 独立实现 RFC 4254 会话通道，显式拒绝非 `"session"` 通道请求（禁用 `direct-tcpip` 等端口转发能力）。
  - 所有连接均经过 `PasswordCallback` 记录 `auth_attempt`（含来源 IP、源端口、客户端版本、用户名与口令及校验结果），并采用恒定时间比对。
  - 会话交互层 `FakeShell` 完全在内存中维护目录树与虚拟文件，不调用 `os/exec`、不接触宿主机文件系统，且对 `wget`/`curl` 等指令返回仿真解析失败而不产生真实外联。
  - 已在实现过程中修正 `"pty-req"` 与 `"window-change"` 请求体结构字段缺失问题（补充 `PixelWidth`、`PixelHeight`、`Modes`），确保标准 SSH 客户端在申请 PTY 后能够稳定进入 `golang.org/x/term` 行编辑循环。
- **生命周期管理层（`internal/manager`）**：创建蜜罐时先校验端口与配置合法性并立即绑定 TCP 监听，成功后再落盘；服务重启时通过 `Restore()` 自动拉起预期状态为 `running` 的实例，绑定失败时标记为 `error` 并在控制台展示具体错误原因。

## 2. 无 QEMU Alpine 多架构容器化与 CI 设计

- **无 QEMU 核心原理与低权限运行**：
  - `Dockerfile` 构建阶段声明 `FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder`，始终在宿主 CI 机器（`linux/amd64`）原生指令集上运行 Go 工具链，利用 Go 内置的 `CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64}` 直接交叉编译出目标架构静态二进制，同时在构建阶段提前准备好 `/out/data` 空目录；`ARG TARGETOS` 与 `ARG TARGETARCH` 保持无默认值声明，确保 BuildKit 自动注入目标平台。
  - 运行阶段使用 `FROM alpine:3.21`，且**完全不包含任何 `RUN` 指令**，仅通过 `COPY --from=builder` 拷贝 CA 证书、只读可执行文件（`--chmod=555`）与数据目录（`--chown=10001:10001 --chmod=750`），并显式设置 `USER 10001:10001` 以非特权用户运行。
  - `docker-compose.yml` 配套启用 `read_only: true`、`cap_drop: ["ALL"]`、`security_opt: ["no-new-privileges:true"]` 与命名卷 `fishing-data:/data`，在不引入 QEMU 的前提下满足最小权限隔离要求。
- **前端路由与日志导出**：
  - 首页仅保留全局概览与蜜罐实例列表；通过 URL Hash 路由（`#/honeypots/<id>`）进入具体蜜罐详情后方展示该实例日志，避免首页信息拥挤并减少无用轮询。
  - 后端新增 `GET /api/honeypots/{id}` 与 `GET /api/honeypots/{id}/logs/export`（支持 `jsonl` 与 `csv`，`csv` 附带 UTF-8 BOM 并对以 `=`, `+`, `-`, `@`, `\t`, `\r` 开头的不可信字段进行公式注入中和）。
- **CI 发布策略（`.github/workflows/release.yml`）**：
  - GitHub Releases 任务交叉编译 `linux/amd64`、`linux/arm64`、`darwin/amd64`、`darwin/arm64`、`windows/amd64` 并生成 `checksums.txt`。
  - 容器发布任务对 `${GITHUB_REPOSITORY}` 做小写规范化后推送至 `ghcr.io`。
