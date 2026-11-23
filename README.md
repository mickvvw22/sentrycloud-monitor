# SentryCloud Monitor

独立开发的服务器与域名监控项目：Cloudflare Workers + D1 控制面，以及可选 Linux Python 探测器。当前控制台部署在 [SentryCloud Monitor](https://sentrycloud-monitor.13367014968.workers.dev)。本项目不是 CF-Server-Monitor-Pro 的代码副本。

## 功能

通过逐机注册、可单独撤销的探测器，支持 HTTP/HTTPS 与 TCP 定时检查、响应时间、历史记录和状态变化通知。Worker 只存配置、派发带短期租约的任务、接收结果并保存历史；它不再直接访问用户配置的站点或 TCP 地址。探测器只主动向 Worker 建立 HTTPS 连接，不需开放入站端口。

探测器上报 CPU、内存、磁盘、累计网络流量和运行时间；可选检查 TLS 证书有效期。到期阈值默认为 30 天，可通过 `CERT_EXPIRY_ALERT_DAYS` 设为 1–365 天。临期、过期、续期恢复以及证书验证/网络探测失败和恢复均可经 webhook 或 Telegram 告警；告警尽力而为，没有通知重试队列。

管理员可在已认证控制台中选择默认玻璃风格或 Custom Theme，设置 HTTPS 背景图、面板透明度和模糊度，并编辑自定义 CSS 与 Script。CSS 仅在 Custom Theme 下应用；自定义 Script 只在已认证管理面板加载后执行，不会在登录页或匿名页面运行，但它仍可修改管理界面并代表当前会话发起操作，因此只应保存完全信任的代码。管理员登录支持可选 TOTP；TOTP 仍为关闭状态。项目包含 D1 schema、数据库迁移、Wrangler 本地配置和自动化测试。

**Altare 探测器尚未部署，因此目前不能声称对 Altare 或其他特定目标的持续监控已启用。** Worker 中的 Cron 只扫描已上报的证书告警，不会自行探测 HTTP/TCP 站点。

## 安全架构与未完成事项

探测器逐次解析全部 DNS A/AAAA 地址，发现任何非公网、特殊、私网、回环、链路本地、共享/CGNAT、组播、保留或文档地址就 fail-closed；实际连接固定到已校验的数值 IP，HTTPS 保留域名用于 Host、SNI、CA 链与主机名验证。每次重试、重定向都重新解析并检查。证书验证失败会作为独立错误保存和告警。

这仍是**未经过专业安全审计的开发版，不应被视为生产级高保障服务**。建议使用外层 Access/MFA、探测器主机最低权限和 egress 防火墙、D1 备份/留存策略及完整生产验证。管理员密码仍使用 PBKDF2-SHA-256 100,000 次迭代（运行时兼容折中），登录限速基础，session 没有服务端主动撤销。外部定时触发、主机连通性、真实证书告警与通知尚未在 Cloudflare 生产环境验证。

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

本地管理员通过 `/api/bootstrap` 初始化；每台探测器需登录后调用 `POST /api/probes` 注册，将一次性返回的 ID 与令牌配置到 agent 环境变量。详细 API、D1 迁移和最小权限运行步骤见 [`worker/README.md`](worker/README.md) 与 [`agent/README.md`](agent/README.md)。
