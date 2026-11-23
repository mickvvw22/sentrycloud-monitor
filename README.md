# SentryCloud Monitor

独立编写的服务器与域名监控项目开发版。前端是自适应深色仪表盘，后端为 Cloudflare Workers + D1，Linux 主机可运行独立 Python 采集器。本项目未使用 CF-Server-Monitor-Pro 的源代码；尚未公开、部署或关联云端账号。

## 已实现

- HTTP/HTTPS 和 TCP 定时检查、响应时间及历史记录；检查频率可配置，Cloudflare Cron 模板设为每分钟。
- Linux 采集器上报 CPU、内存、磁盘、累计网络流量和运行时间。
- 可选的 TLS 证书到期探测由采集器完成，结果可以保存并显示在服务器卡片中。
- 管理员密码登录，可选 TOTP：在 Google Authenticator 中手动输入密钥绑定；当前不生成二维码。
- 站点首次探测失败以及状态改变时，向配置的 webhook 或 Telegram 发送尽力而为的故障/恢复通知。
- Cloudflare Wrangler 本地配置、D1 表结构与自动化测试；`wrangler.toml` 的数据库 ID 是占位符，并非真实云资源。

## 未完成或有局限

这是 **未经过专业安全审计的开发版，不应部署到生产**。尚未在 Cloudflare 创建资源或完成 GitHub 关联。上线前需要单独配置 Cloudflare Access / MFA 和适当网络隔离，审计认证及会话、限制管理员与采集器权限，并验证计划的账号、额度和运行环境。

- Cloudflare Workers 对密码派生的限制使本项目使用 PBKDF2-SHA-256 100,000 次迭代，这是兼容性折中，不应仅依赖此密码保护；还需要更完善的防暴力破解与密钥保护。
- DNS 重绑定等出站风险未彻底解决；HTTP 检查限制端口 80/443。Workers TCP 接口也限制私网、Cloudflare IP、端口 25 等目标，实际可连接性取决于平台。
- 证书检查需要配置并运行 Linux 采集器，不会在 Worker 自动探测；无证书到期告警、通知重试队列或完善的告警去抖。Webhook 在本地模拟器中测试过，Telegram 及真实生产通知未测试。
- 所有采集器当前共用一个 token；尚无逐机器令牌隔离、历史指标保留策略或公开状态页。管理员 session 目前没有服务端主动撤销功能。
- 本地计划任务通过手动触发测试过；未在 Cloudflare 实际测试部署、自动定时或实时告警。手机验证器绑定流程通过程序生成的标准 TOTP 代码验证过，但未在用户手机上实测。

## 本地开发

以下命令仅适用于独立测试目录及一次性本地数据库，**不要对包含真实数据的数据库运行测试**。需要 Node.js、npm 和 Python 3；`wrangler.toml` 的 `workers_dev = false` 也不代表可以绕过部署授权。

1. 安装 Worker 测试依赖：`cd worker && npm ci`。
2. 回到项目根目录，在 `.dev.vars` 创建 `SESSION_SECRET`、`BOOTSTRAP_KEY`、`AGENT_TOKEN` 三个各至少 32 字符的不同随机值，以及 `APP_ORIGIN=http://127.0.0.1:8787`。不要提交该文件。
3. 用本地 D1 创建表：

   ```sh
   ./worker/node_modules/.bin/wrangler d1 execute sentrycloud-monitor-local --local --file=worker/schema.sql --persist-to=.wrangler/local-integration
   ```

4. 仅监听本机启动：

   ```sh
   ./worker/node_modules/.bin/wrangler dev --local --ip 127.0.0.1 --port 8787 --persist-to=.wrangler/local-integration
   ```

5. 测试 Worker：`cd worker && npm run typecheck && npm test`；测试采集器：`cd agent && python3 -m unittest discover -v`。`tests/local_smoke.py` 是创建测试管理员和目标的集成测试，需要全新的一次性本地 D1，并且 `.dev.vars` 中另设 `NOTIFY_WEBHOOK_URL=http://127.0.0.1:8788/alerts`；测试会向 `example.com` 发起 HTTP/TCP 请求。

本地管理员初始化通过 `/api/bootstrap` 完成，需提供本地 bootstrap key、用户名及至少 12 字符的密码，并带上与 `APP_ORIGIN` 一致的 Origin；具体 API、限制见 `worker/README.md`。采集器配置见 `agent/README.md`。
