# Linux 探测器

这是仅使用 Python 3 标准库的出站型 Linux 探测器：它读取本机 `/proc` 指标，通过 HTTPS 向 Worker 上报心跳、拉取到期任务，并将 HTTP/HTTPS/TCP 检查结果回传。**无需监听任何入站端口**；Worker 不再直接连接用户配置的监控目标。

## 注册独立探测器

以管理员登录监控面板后，向同源 `POST /api/probes` 发送 `{ "name": "probe-eu-1" }`。请求必须带当前管理员 session、与 `APP_ORIGIN` 完全一致的 `Origin` 和 `Content-Type: application/json`。成功响应包含新探测器 `id` 与随机 `token`：令牌仅在创建时返回，数据库只保存其 SHA-256 摘要。将 `id` 用作 `AGENT_ID`，将 `token` 存入仅探测器服务账号可读的环境文件。`GET /api/probes` 可查看名称、最近上线时间和撤销状态（不返回令牌）；`DELETE /api/probes/<id>` 立即撤销该机器凭证。每台机器注册一个探测器；令牌不共享，泄漏时只需撤销对应机器。

创建、复制令牌时不要把响应写入日志、命令历史或仓库。务必先妥善保存创建响应中的 token；随后无法从服务器取回，只能撤销后创建新探测器。

## 配置与运行

需要设置：

- `SENTRY_AGENT_URL`：完整心跳地址，例如 `https://monitor.example/api/agent/heartbeat`。
- `AGENT_ID`：注册响应里的唯一探测器 ID。
- `AGENT_TOKEN`：注册时返回的独立令牌，至少 32 个字符。旧变量 `SENTRY_AGENT_TOKEN` 仅作过渡读取名，不代表旧共享令牌仍可用。
- `SENTRY_AGENT_INTERVAL`：心跳、任务拉取间隔（秒，默认 60）。
- `SENTRY_AGENT_TIMEOUT`：控制 API 与单次证书探测超时（秒，默认 10）。
- `SENTRY_AGENT_CERT_HOSTS`：可选的逗号分隔公有域名列表，启用 TLS 证书检查。
- `SENTRY_AGENT_ALLOW_INSECURE_LOCAL`：只用于显式启用的 `127.0.0.1` 本地测试；生产必须使用 HTTPS。

运行 `python3 agent.py`。控制面请求禁止自动跟随重定向，避免把探测器 Bearer 令牌带到其他 URL。正常生产部署不应将令牌放在 shell 命令行参数里；建议写入 `/etc/sentrycloud-probe.env`，权限设为 `0600`，归专用服务账号所有。

### systemd 示例

创建专用低权限用户，并将项目代码放在只读目录。服务单元可按实际安装路径调整：

```ini
[Unit]
Description=SentryCloud outbound probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentry-probe
Group=sentry-probe
EnvironmentFile=/etc/sentrycloud-probe.env
WorkingDirectory=/opt/sentrycloud-monitor/agent
ExecStart=/usr/bin/python3 /opt/sentrycloud-monitor/agent/agent.py
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

按你的主机策略继续限制出站网络：至少允许到监控 Worker 的 HTTPS；目标探测仅允许你实际监控所需的公网上游地址和端口。agent 不需要入站放行。操作系统级 egress 防火墙是额外防线，不应代替本程序的 DNS 校验。

## 监控行为与安全边界

探测器轮询 Worker 的窄范围任务 API，并只提交与租约匹配的检查结果。任务按配置的检查间隔派发，租约超时后可重新派发；Worker 只记录检查结果并发送状态变化通知。HTTP/HTTPS 仅访问对应标准端口 80/443；TCP 可配置端口（拒绝 25），错误或超时只记为失败，不伪报成功。

每次连接前，agent 会重新查询完整 A/AAAA 结果集：任何非公网、特殊、保留、私网、回环、链路本地、共享/CGNAT（含 Tailscale 常用地址段）、组播、未指定或文档地址都会导致该次探测 fail-closed。DNS 返回的每个地址都要通过检查，随后套接字连接到经过检查的**数值 IP**，不再把域名交给系统解析器连接。每次连接重试、HTTP 重定向的下一跳和证书检查都会重新执行此策略；HTTPS 始终使用原主机名进行 Host、SNI、系统 CA 链与主机名验证。网络边界、防火墙和专业安全审计仍然重要；不要允许不可信人员修改探测器配置或执行服务的主机账号。

证书结果可能是有效的 `expires_at`，也可能是 `certificate_verification_failed`、`unsafe_dns_address`、`timeout` 等明确错误。错误结果不会被当作有效证书到期时间；Worker 会按主机去重发送首次失败/错误变化告警，并在恢复有效探测后发送恢复通知。到期提醒仍按 `CERT_EXPIRY_ALERT_DAYS` 的 1–365 天阈值工作。告警通知依旧是尽力而为，尚无重试队列。

心跳仍上报 CPU、内存、磁盘、累计网络流量及运行时间；第一次 CPU 采样显示未知。当前证书主机列表由部署配置提供，不接受 Worker 下发任意 DNS 名称作为新证书探测命令。

## 测试

在本目录运行：

```sh
python3 -m unittest discover -v
python3 -m py_compile agent.py cert_probe.py probe_security.py probe_checks.py
```

测试使用模拟网络与地址，不能代替对真实主机、防火墙、证书链和长期服务稳定性的检查。
