# Fishing SSH 蜜罐平台

Fishing 是一个基于 Go 语言与嵌入式静态前端构建的轻量级 SSH 蜜罐平台。用户可通过控制台创建、启停并管理仿真 SSH 蜜罐实例，实时审计连接来源 IP、认证尝试凭据以及建立会话后输入的指令序列。

## 核心能力

- **SSH 蜜罐管理**：在控制台选择蜜罐类型（当前版本支持 SSH）、监听端口、登录用户名与密码即可即时创建并启动监听；支持启停与删除操作，配置持久化存储于数据目录。
- **访问与命令审计**：记录每次连接尝试的来源 IP、源端口、SSH 客户端版本、认证用户名与密码及认证结果；登录成功后完整采集 `exec` 指令与交互式 `shell` 中输入的所有命令。
- **纯内存 SSH 仿真**：内置内存虚拟文件系统与常规 Linux 响应（`id`、`whoami`、`uname`、`pwd`、`cd`、`ls`、`cat`、`ps`、`ip`、`ss`、`df`、`free`、`uptime`、`history` 等），不调用宿主机系统命令、不读取宿主机文件、不发起外部网络请求且禁用端口转发。
- **嵌入式终端风控制台**：前端采用原生静态 HTML/CSS/JS 并通过 `embed.FS` 编译入单个二进制文件中，无需额外部署静态资源服务器。
- **无 QEMU 的 Alpine 多架构容器构建**：构建阶段利用 Go 原生交叉编译生成静态二进制，运行阶段基于 `alpine:3.21` 且不含目标架构 `RUN` 指令，可在 `ubuntu-latest` CI Runner 上直接产出 `linux/amd64` 与 `linux/arm64` 多架构容器镜像。

## 快速启动

### 本地源码运行

```bash
go run . -addr :8080 -data-dir ./data -bind-host 0.0.0.0
```

启动后访问 `http://127.0.0.1:8080` 进入控制台界面。点击「`[+ 添加蜜罐]`」，填写端口（例如 `2222`）、用户名与密码后提交即可完成创建并开始监听。

### 使用 Docker Compose 运行

```bash
docker compose up -d --build
```

默认配置将管理端端口 `8080` 与预留蜜罐端口段 `2222-2232` 映射至宿主机，并将运行数据持久化于 `./data`。若需在 Linux 宿主机上动态创建并监听 `22` 等任意端口，可在 `docker-compose.yml` 中启用 `network_mode: host` 并移除 `ports` 字段。

使用已发布的 GHCR 镜像时，可通过环境变量指定镜像地址：

```bash
FISHING_IMAGE=ghcr.io/<owner>/fishing:latest docker compose up -d
```

## 运行参数与环境变量

| CLI 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `-addr` | `FISHING_ADDR` | `:8080` | Web 控制台与 HTTP API 监听地址 |
| `-data-dir` | `FISHING_DATA_DIR` | `./data` | 配置文件、SSH 宿主密钥与审计日志存储目录 |
| `-bind-host` | `FISHING_BIND_HOST` | `0.0.0.0` | SSH 蜜罐实例监听绑定的主机地址 |

## CI/CD 与发布流程

- `.github/workflows/ci.yml`：在推送至 `main` 或发起 Pull Request 时执行 `go vet`、`go test -race`、Go 跨平台编译校验及无 QEMU 的 `linux/amd64,linux/arm64` Alpine 镜像构建检查。
- `.github/workflows/release.yml`：推送 `v*` 标签或手动触发时，自动交叉编译多平台二进制压缩包（含 SHA-256 校验文件）发布至 GitHub Releases，并构建推送 `linux/amd64,linux/arm64` 多架构 Alpine 镜像至 `ghcr.io`。
