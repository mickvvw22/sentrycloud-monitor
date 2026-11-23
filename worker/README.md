# SentryCloud Monitor Worker

原创 Cloudflare Workers + D1 后端 MVP。**未经过外部安全审计，未达到生产就绪标准。**

## 配置

必须设置：

- `DB`：D1 binding。
- `SESSION_SECRET`、`BOOTSTRAP_KEY`、`AGENT_TOKEN`：各至少 32 字符的高熵随机 secret；缺失或过短时除 `/health` 外 fail-closed。
- `APP_ORIGIN`：唯一允许的前端 origin；不配置不会启用任意来源 CORS。

可选配置：

- `CERT_EXPIRY_ALERT_DAYS`：证书临期提醒阈值，默认 30 天；有效范围为 1–365 天。
- `NOTIFY_WEBHOOK_URL`、`TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID`：告警通知目的地。

新建数据库使用 `schema.sql` 初始化。已有旧版数据库：如果 `agent_heartbeats` 缺少 `certificates` 列，先运行一次 `migration-certificates.sql`；再运行一次 `migration-certificate-alerts.sql` 创建证书状态表。不要对已有 `certificates` 列的数据库重复执行旧列迁移。

## 端点

- `GET /health`：无需应用密钥，仅返回存活状态。
- `POST /api/bootstrap`：body `{key, username, password}`，仅空库；密码至少 12 字符，要求同源 `Origin`。
- `POST /api/login`：body `{username,password,totp?}`，要求同源 `Origin`。按 `IP+username` 的 D1 窗口限制最多 10 次/15 分钟；包括缺失或格式错误的口令，超限返回 HTTP 429。这是基础限速，不替代 WAF 或更强的全局防暴力控制。
- `GET /api/me`、`POST /api/logout`。
- `POST /api/totp/setup`：已启用 TOTP 时拒绝，不覆盖现有启用配置。
- `POST /api/totp/enable`：body `{code}`。
- `POST /api/totp/disable`：body `{password,code}`，同时要求密码和当前 TOTP。
- `GET /api/agents`：管理员 session 认证，返回 heartbeat metrics、certificates 与时间。
- `POST /api/agent/heartbeat`：不依赖 admin cookie，仅要求 `Authorization: Bearer AGENT_TOKEN`；body `{agent_id,metrics,certificates?}`。
- `GET/POST /api/targets`、`DELETE /api/targets/:id`：需要管理员 session。
- `GET/POST /api/targets/:id/checks`、`PATCH/DELETE /api/checks/:id`：需要管理员 session；`interval_seconds` 支持 60 秒至 365 天。
- `GET /api/checks/:id/latest|history`：需要管理员 session。
- `POST /api/cron/monitor`：要求管理员 session、同源 `Origin` 和 `x-cron-key: BOOTSTRAP_KEY`；同时支持 Workers Cron `scheduled` handler。

## 证书告警与安全范围

采集器上报可验证证书的 `expires_at` 后，Worker 会按 `CERT_EXPIRY_ALERT_DAYS` 计算 `ok`、`warning` 或 `expired` 状态；同一主机重复上报时按最早到期时间评估。初次发现临期/过期状态时告警；条件写入避免并发监控重复提醒；显式上报列表中消失的主机标记为 `missing`（不视为恢复），重新出现后重新评估。续期后回到安全窗口时发送恢复通知。证书探测失败或无效证书可能无法提供到期时间，因此不会伪造有效到期信息。Webhook 和 Telegram 通知均为尽力而为，没有重试队列。

密码使用 PBKDF2-HMAC-SHA-256（新建密码使用 100,000 iterations，以兼容 Cloudflare Workers 生产环境的上限）；这是运行时兼容折中，不能宣称满足当前密码存储强度标准。`passwordVerify` 按存储哈希中的 iteration 校验，保持既有 `pbkdf2$iterations$salt$hash` 格式兼容，不静默降级旧哈希。生产环境必须在外层配置 Cloudflare Access/MFA，并进行专业安全审计；不要仅依赖此 Worker 的密码保护。Session 使用带过期时间的 HMAC-SHA-256 token，当前没有服务端主动撤销机制。状态变更的 cookie 请求必须带与 `APP_ORIGIN` 完全匹配的 `Origin`；CORS 不回退到任意 origin。

HTTP endpoint 只允许 HTTP/HTTPS、80/443、无 userinfo，并拒绝 URL 标准化后及常见数字表示的 IPv4/IPv6 literal、localhost；手动重定向每一跳都重新校验。Cloudflare Workers 无通用 DNS 解析/固定出站 IP API，因此这里不能完全消除 DNS rebinding 或网络层 SSRF 风险：校验域名后，DNS 仍可能在连接时解析到私网地址。生产部署必须配合出站隔离、域名 allowlist 或 egress proxy，并进行外部审计。TCP 检查使用官方 `cloudflare:sockets` 的 `connect()`，等待 `socket.opened` 后判定成功，带超时并在 `finally` 关闭 socket；连接失败、超时、Cloudflare 禁止的目标/端口等都如实记为 down，不伪造 up。应用拒绝 localhost、IP literal、userinfo、常见私有主机名风险、端口 25 和非法端口；Cloudflare 平台自身对目标地址/端口的限制仍可能导致合法配置无法连接。

所有采集器当前共用一个 agent token；尚无逐机器令牌隔离。历史检测数据没有自动保留/清理策略，长期运行会持续占用 D1 存储与查询资源。定时触发、外部网络行为和生产通知尚未在真实 Cloudflare 环境验证。
