# SentryCloud Monitor Worker

原创 Cloudflare Workers + D1 后端 MVP，仅改动本 worker 目录。**未经过外部安全审计，未生产就绪。**

## 配置

必须设置：

- `DB`：D1 binding。
- `SESSION_SECRET`、`BOOTSTRAP_KEY`、`AGENT_TOKEN`：各至少 32 个字符的高熵随机 secret；缺失或过短时除 `/health` 外 fail-closed。
- `APP_ORIGIN`：唯一允许的前端 origin；不配置不会启用任意来源 CORS。

可选通知配置：`NOTIFY_WEBHOOK_URL`、`TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID`。

使用 `wrangler d1 execute <database> --file=schema.sql` 初始化。已有原始 MVP 数据库先执行一次 `migration-certificates.sql`；不要对已经存在 `certificates` 列的数据库重复执行该迁移。

## 端点

- `GET /health`：无需应用密钥，仅返回存活状态。
- `POST /api/bootstrap`：body `{key, username, password}`，仅空库；密码至少 12 字符，要求同源 `Origin`。
- `POST /api/login`：body `{username,password,totp?}`，要求同源 `Origin`。按 `IP+username` 的 D1 窗口限制最多 10 次/15 分钟；这是基础限速，不替代 WAF/更强的全局防暴力控制。
- `GET /api/me`、`POST /api/logout`。
- `POST /api/totp/setup`：已启用 TOTP 时拒绝，不覆盖现有启用配置。
- `POST /api/totp/enable`：body `{code}`。
- `POST /api/totp/disable`：body `{password,code}`，同时要求密码和当前 TOTP。
- `GET /api/agents`：管理员 session 认证，返回 heartbeat metrics、certificates 与时间。
- `POST /api/agent/heartbeat`：不依赖 admin cookie，仅要求 `Authorization: Bearer AGENT_TOKEN`；body `{agent_id,metrics,certificates?}`，certificates 为顶层可选字段。
- `GET/POST /api/targets`、`DELETE /api/targets/:id`。
- `GET/POST /api/targets/:id/checks`、`PATCH/DELETE /api/checks/:id`；`interval_seconds` 支持 60 秒至 365 天。
- `GET /api/checks/:id/latest|history`。
- `POST /api/cron/monitor`：要求 `x-cron-key: BOOTSTRAP_KEY`；同时支持 Workers Cron `scheduled` handler。

## 安全与范围说明

密码使用 PBKDF2-HMAC-SHA-256（新建密码使用 100,000 iterations，以兼容 Cloudflare Workers 生产环境的上限）；这是运行时兼容折中，不能宣称满足当前密码存储强度标准。`passwordVerify` 按存储哈希中的 iteration 校验，保持既有 `pbkdf2$iterations$salt$hash` 格式兼容，不静默降级旧哈希。生产环境必须在外层配置 Cloudflare Access/MFA，并进行专业安全审计；不要仅依赖此 Worker 的密码保护。session 使用带过期时间的 HMAC-SHA-256 token。状态变更的 cookie 请求必须带与 `APP_ORIGIN` 完全匹配的 `Origin`；CORS 不回退到任意 origin。HTTP endpoint 只允许 HTTP/HTTPS、80/443、无 userinfo，并拒绝 URL 标准化后及常见数字表示的 IPv4/IPv6 literal、localhost；手动重定向每一跳都重新校验。

Cloudflare Workers 无通用 DNS 解析/固定出站 IP API，因此这里不能完全消除 DNS rebinding 或网络层 SSRF 风险：校验域名后，DNS 仍可能在连接时解析到私网地址；生产部署必须配合出站隔离、域名 allowlist 或 egress proxy，并进行外部审计。TCP 检查使用官方 `cloudflare:sockets` 的 `connect()`，等待 `socket.opened` 后判定成功，带超时并在 `finally` 关闭 socket；连接失败、超时、Cloudflare 禁止的目标/端口等都如实记为 down，不伪造 up。应用拒绝 localhost、IP literal、userinfo、常见私有主机名风险、端口 25 和非法端口；Cloudflare 平台自身对目标地址/端口的限制仍可能导致合法配置无法连接。证书到期信息由可选的服务器采集器探测并上报，Worker 保存而不是自行检查；到期自动告警尚未实现。状态变化通知为 best-effort，复杂告警去抖/重试队列留作 TODO。
