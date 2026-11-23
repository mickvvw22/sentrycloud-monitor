# SentryCloud Monitor Worker

原创 Cloudflare Workers + D1 控制面。**未经过外部安全审计，仍不是生产就绪软件。** Worker 管理用户、TOTP、目标/检查配置、任务租约、历史与告警；它不再直接访问监控目标的 HTTP、HTTPS 或 TCP 端口。

## 必需配置

- `DB`：D1 binding。
- `SESSION_SECRET`、`BOOTSTRAP_KEY`：各至少 32 字符的高熵随机 secret。
- `APP_ORIGIN`：唯一前端 origin；不配置不会启用任意来源 CORS。
- 可选：`CERT_EXPIRY_ALERT_DAYS`（默认 30，范围 1–365）、`NOTIFY_WEBHOOK_URL`、`TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID`。

不再需要全局 `AGENT_TOKEN`。每台 Linux 探测器由管理员单独注册，Worker 仅存令牌 SHA-256 摘要，可逐台撤销。探测器以 HTTPS 主动拉取任务，因此无需开放探测器入站端口，也不向探测器提供 Cloudflare API、D1 或通知渠道凭据。

新建数据库使用 `schema.sql`。已有数据库依次按原项目升级说明完成证书列/证书告警状态迁移后，再执行一次 `migration-probe-security.sql`，创建 `probes`、`probe_task_leases` 与 `certificate_probe_states`。先备份 D1；不要把迁移文件当作可重复全量重置操作。

## 认证与端点

- `GET /health`：无需应用密钥，只返回存活状态。
- `POST /api/bootstrap`：body `{key, username, password}`，仅空库；密码至少 12 字符，要求同源 `Origin`。
- `POST /api/login`：body `{username,password,totp?}`，要求同源 `Origin`；按 `IP+username` 限速最多 10 次/15 分钟。仍需要外层 Access/MFA 与更强防暴力保护。
- `GET /api/me`、`POST /api/logout`；管理员 cookie 为 Secure、HttpOnly、SameSite=Strict。
- `POST /api/totp/setup|enable|disable`：启用 TOTP 后不允许无验证覆盖密钥；待绑定期间重复请求会返回现有密钥，不会让页面刷新或部署更新使原绑定二维码失效；停用要求密码与当前 TOTP。
- `POST /api/probes`（管理员 session、同源 `Origin`）：body `{name}`。创建独立探测器并仅一次返回 `{id,name,token}`；token 不可查询回。
- `GET /api/probes`（管理员 session）：列出探测器名称、上线时间、撤销状态，不含令牌。
- `DELETE /api/probes/:id`（管理员 session、同源 `Origin`）：撤销该探测器令牌。
- `POST /api/agent/heartbeat`：探测器 bearer token 认证；探测器身份来自令牌，不接受请求体 `agent_id` 冒充其他机器。body `{agent_id,metrics,certificates}` 中的 `agent_id` 会被忽略，以已认证 ID 为准。
- `GET /api/probe/tasks?limit=10`：逐机 bearer 认证，最多返回 20 个到期检查及随机短期 `task_token`。任务由条件写入租约领取；已有有效租约不会重复发给其他探测器，超时后可重派。
- `POST /api/probe/results`：逐机 bearer 认证；body `{check_id,task_token,ok,latency_ms,error}`。仅当前探测器持有、未过期且未消费的租约可提交，结果由 Worker 时间戳记录，重放被拒绝。
- `GET /api/agents`：管理员查看心跳、主机指标和证书结果。
- `GET/POST /api/targets`、`DELETE /api/targets/:id`；`GET/POST /api/targets/:id/checks`、`PATCH/DELETE /api/checks/:id`；`GET /api/checks/:id/latest|history`：均需要管理员 session。
- `POST /api/cron/monitor`：要求管理员 session、同源 `Origin` 和 `x-cron-key: BOOTSTRAP_KEY`；仅扫描证书告警。Workers Cron 也只执行该证书扫描，不会自行探测 HTTP/TCP。

## 网络安全与探测职责

检查目标由管理员配置；Worker 校验 URL scheme、标准端口、userinfo、IP literal 和常见本地域名，但不执行任何针对目标的出站请求。独立 Python 探测器对每个 HTTP/HTTPS/TCP/证书连接重新解析 DNS；拒绝所有非公网/特殊地址，并固定套接字到已验证 IP，HTTP `Host`、TLS SNI 与证书校验仍使用域名。每个重试和 HTTP 重定向都重新解析并验证。HTTPS 用系统 CA 与主机名验证，证书验证失败以明确错误回传并可告警。

此设计降低 Worker SSRF 和共享凭证泄漏风险，但不是完整网络安全边界：探测器主机上的系统解析器、出站防火墙、目标端、Cloudflare、管理员账号与通知目的地都需单独审计。应使用专用低权限 Linux 账号、只读程序文件、受保护的配置文件与主机级出站限制；不要让不可信用户修改探测任务或探测器配置。TCP 允许除 25 外的有效端口，因此出站网络策略要按实际被授权的目标收紧。

证书有效期状态仍为 `ok`、`warning`、`expired`、`missing`；新表 `certificate_probe_states` 单独追踪 TLS 验证/网络/危险 DNS 等探测错误，并在状态变化时去重告警，重新成功时发送恢复通知。证书条目从列表消失只标记 `missing`，不会误报恢复。通知为尽力而为，没有重试队列。历史检查结果目前没有自动清理策略。

登录密码仍使用 PBKDF2-HMAC-SHA-256 100,000 次迭代以兼容运行时，低于推荐强度；Session 暂无服务端主动撤销。生产环境须先配置 Access/MFA、出站与入站网络限制、备份与留存策略，并完成独立安全审计。平台定时行为、实际目标连通性、证书告警和生产通知尚未在真实 Cloudflare 环境验证。
