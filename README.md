# SentryCloud Monitor

独立编写的服务器与域名监控开发版：自适应深色仪表盘、Cloudflare Workers + D1 后端，以及可选 Linux Python 采集器。本项目使用原创代码，未使用 CF-Server-Monitor-Pro 的源代码；目前仍未部署到 Cloudflare。

## 已实现

- HTTP/HTTPS 与 TCP 定时检查、响应时间和历史记录；检查频率可配置，Cloudflare Cron 模板设为每分钟。
- Linux 采集器上报 CPU、内存、磁盘、累计网络流量和运行时间。
- 可选 TLS 证书探测、到期状态展示，以及默认在到期 30 天内和证书过期时的告警；续期回到安全窗口后发送恢复通知。阈值可通过 `CERT_EXPIRY_ALERT_DAYS` 设为 1–365 天。
- 管理员密码登录，可选 TOTP：在 Google Authenticator 中手动输入密钥绑定；当前不生成二维码。
- 目标故障/恢复以及证书临期、过期、续期恢复通知支持 webhook 或 Telegram；同一状态不重复提醒，采集列表中暂时缺报的证书重新出现时会再次评估；通知为尽力而为。
- Wrangler 本地配置、D1 表结构与自动化测试；`wrangler.toml` 中的数据库 ID 是占位符，并非真实云资源。

## 未完成或有局限

这是**未经过专业安全审计的开发版，不应直接部署到生产**。上线前需要配置 Cloudflare Access / MFA 和适当网络隔离，审计认证与会话、限制管理员和采集器权限，并验证账号、额度和运行环境。尚未在 Cloudflare 创建资源或完成实际部署。

- Cloudflare Workers 对密码派生的限制使本项目使用 PBKDF2-SHA-256 100,000 次迭代，这是兼容性折中，不应仅依赖此密码保护；还需要更完善的防暴力破解与密钥保护。
- DNS 重绑定等出站风险未彻底解决；HTTP 检查限制端口 80/443。Workers TCP 接口也限制私网、Cloudflare IP、端口 25 等目标，实际可连接性取决于平台。
- 证书到期提醒依赖采集器成功读取有效的 `expires_at`；无效证书或探测失败可能无法得知到期时间。通知没有重试队列；Webhook 在本地模拟器中测试过，Telegram 及真实生产通知未测试。
- 所有采集器共用一个 token；尚无逐机器令牌隔离、历史指标保留策略或公开状态页。管理员 session 没有服务端主动撤销功能。
- 本地计划任务通过手动触发测试过；未在 Cloudflare 验证实际部署、自动定时或实时告警。TOTP 绑定用程序生成的标准代码验证过，但未在用户手机上实测。

## 本地开发

以下命令仅适用于独立测试目录及一次性本地数据库，**不要对包含真实数据的数据库运行测试**。需要 Node.js、npm 和 Python 3；`wrangler.toml` 的 `workers_dev = false` 也不代表可以绕过部署授权。

1. 安装 Worker 测试依赖：`cd worker && npm ci`。
2. 回到项目根目录，在 `.dev.vars` 创建 `SESSION_SECRET`、`BOOTSTRAP_KEY`、`AGENT_TOKEN` 三个彼此不同、各至少 32 字符的随机值，以及 `APP_ORIGIN=http://127.0.0.1:8787`。不要提交该文件。可选设置 `CERT_EXPIRY_ALERT_DAYS=30` 和 `NOTIFY_WEBHOOK_URL=http://127.0.0.1:8788/alerts` 进行本地告警测试。
3. 用本地 D1 创建表：

   ```sh
   ./worker/node_modules/.bin/wrangler d1 execute sentrycloud-monitor-local --local --file=worker/schema.sql --persist-to=.wrangler/local-integration
   ```

4. 仅监听本机启动：

   ```sh
   ./worker/node_modules/.bin/wrangler dev --local --ip 127.0.0.1 --port 8787 --persist-to=.wrangler/local-integration
   ```

5. 测试 Worker：`cd worker && npm run typecheck && npm test`；测试采集器：`cd agent && python3 -m unittest discover -v`。`tests/local_smoke.py` 是创建测试管理员和监控目标的集成测试，需要全新的一次性本地 D1；它会向 `example.com` 发起 HTTP/TCP 请求，并测试本地模拟 webhook。不要针对真实或生产数据库运行。

本地管理员初始化通过 `/api/bootstrap` 完成，需提供本地 bootstrap key、用户名及至少 12 字符的密码，并带上与 `APP_ORIGIN` 一致的 Origin；具体 API、限制见 `worker/README.md`。采集器配置见 `agent/README.md`。
