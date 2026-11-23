# SentryCloud Monitor

原创服务器与域名监控开发项目：深色仪表盘、Cloudflare Workers + D1 控制面，以及可选 Linux Python 探测器。本项目没有使用 CF-Server-Monitor-Pro 源代码。目前未部署到 Cloudflare，也没有更改 Cloudflare、DNS 或任何云资源。

## 功能

通过逐机注册、可单独撤销的探测器，保留 HTTP/HTTPS 与 TCP 定时检查、响应时间、历史记录和状态变化通知。Worker 只存配置、派发带短期租约的任务、接收结果并保存历史；它不再直接访问用户配置的站点或 TCP 地址。探测器只主动向 Worker 建立 HTTPS 连接，不需开放入站端口。

探测器上报 CPU、内存、磁盘、累计网络流量和运行时间；可选检查 TLS 证书有效期。到期阈值默认为 30 天，可通过 `CERT_EXPIRY_ALERT_DAYS` 设为 1–365 天。临期、过期、续期恢复以及证书验证/网络探测失败和恢复均可经 webhook 或 Telegram 告警；告警尽力而为，没有通知重试队列。

管理员密码登录支持可选 TOTP，可在 Google Authenticator 中手动输入密钥绑定（暂不生成二维码）。项目包含 D1 schema、数据库迁移、Wrangler 本地配置和自动化测试；`wrangler.toml` 数据库 ID 是占位符。

## 安全架构与未完成事项

探测器逐次解析全部 DNS A/AAAA 地址，发现任何非公网、特殊、私网、回环、链路本地、共享/CGNAT、组播、保留或文档地址就 fail-closed；实际连接固定到已校验的数值 IP，HTTPS 保留域名用于 Host、SNI、CA 链与主机名验证。每次重试、重定向都重新解析并检查。证书验证失败会作为独立错误保存和告警。

这仍是**未经过专业安全审计的开发版，不应直接部署到生产**。需要 Cloudflare Access/MFA、探测器主机最低权限和 egress 防火墙、D1 备份/保留策略及生产环境验证。管理员仍使用 PBKDF2-SHA-256 100,000 次迭代（运行时兼容折中），登录限速基础，session 没有服务端主动撤销。外部定时触发、主机连通性、真实证书告警与通知尚未在 Cloudflare 生产环境验证，Telegram 和生产 webhook 也未测试。

## 本地开发

以下流程仅适用于一次性本地 D1 和测试数据；不要对含真实数据的数据库运行集成 Smoke 测试。需要 Node.js、npm、Python 3。

1. 在 `worker/` 安装测试依赖：`npm ci`。
2. 在项目根目录 `.dev.vars` 设置彼此不同的 `SESSION_SECRET`、`BOOTSTRAP_KEY`（各至少 32 个随机字符）和 `APP_ORIGIN=http://127.0.0.1:8787`。不要提交 `.dev.vars`。可选设置 `CERT_EXPIRY_ALERT_DAYS=30` 与本地 webhook URL。此新方案不需要共享 `AGENT_TOKEN`。
3. 用一次性本地 D1 初始化 schema，并在另一个终端只监听回环地址启动 Wrangler：

   ```sh
   ./worker/node_modules/.bin/wrangler d1 execute sentrycloud-monitor-local --local --file=worker/schema.sql --persist-to=.wrangler/local-integration
   ./worker/node_modules/.bin/wrangler dev --local --ip 127.0.0.1 --port 8787 --persist-to=.wrangler/local-integration
   ```

4. 运行 Worker 类型与安全测试：`cd worker && npm run typecheck && npm test`；运行探测器单测：`cd agent && python3 -m unittest discover -v`。如需完整 Smoke 测试，再启动本地 Worker 并运行 `python3 tests/local_smoke.py`；它会创建一次性管理员、注册探测器并访问 `example.com` 执行 HTTP/TCP 集成检查，同时测试本地模拟 webhook；仅对全新本地数据库使用。

本地管理员通过 `/api/bootstrap` 初始化；每台探测器需登录后调用 `POST /api/probes` 注册，将一次性返回的 ID 与令牌配置到 agent 环境变量。详细 API、数据库迁移和最小权限运行步骤见 [`worker/README.md`](worker/README.md) 与 [`agent/README.md`](agent/README.md)。
