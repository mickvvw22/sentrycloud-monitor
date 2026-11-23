# Linux 服务器采集器

这是独立开发的 Python 3 标准库采集器，不执行远程命令。它读取 Linux `/proc` 和根文件系统的 CPU、内存、磁盘、累计网络流量及运行时间，使用 bearer token 将数据发送到 Worker。首次采样没有上一周期，CPU 使用率会显示为未知。

## 环境变量

- `SENTRY_AGENT_URL`：完整心跳地址，例如 `https://你的域名/api/agent/heartbeat`。
- `AGENT_ID`：该机器的唯一标识；多台机器请使用不同值。
- `AGENT_TOKEN`：与 Worker 配置一致的长随机令牌。旧名称 `SENTRY_AGENT_TOKEN` 仅作为兼容回退。
- `SENTRY_AGENT_INTERVAL`：采样和心跳间隔（秒，默认 60）。
- `SENTRY_AGENT_TIMEOUT`：请求与单次证书探测超时（秒，默认 10）。
- `SENTRY_AGENT_CERT_HOSTS`：可选的逗号分隔域名列表，默认不探测证书。
- `SENTRY_AGENT_ALLOW_INSECURE_LOCAL`：仅对显式的本机 HTTP 测试设置 `true`；正常使用必须使用 HTTPS。

设置上述环境变量后运行 `python3 agent.py`。不要将令牌写进命令历史、Git 仓库或公开日志；在系统服务中使用仅服务账号可读的环境文件。部署生产服务时使用最低权限、专用服务账号并设置适当的系统和网络隔离。

心跳使用 `Authorization: Bearer <AGENT_TOKEN>`，JSON 为 `{agent_id, metrics, certificates}`。当前 Worker 使用同一个 agent token 验证所有采集器；它并非逐机器隔离，令牌泄漏后必须轮换。无网络或服务错误时记录简短错误并在下一周期重试。

## 可选 TLS 证书探测

设置 `SENTRY_AGENT_CERT_HOSTS` 后，采集器对指定的主机 443 端口建立 TLS 连接，使用 SNI、系统 CA 和主机名验证，并读取证书 `notAfter`。成功返回 `hostname` 与 UTC `expires_at`；失败返回错误，不会伪造到期时间。Worker 可以保存这些数据，但证书到期告警尚未实现。失效证书可能导致 TLS 验证失败，此时不能读取其到期时间。

也可以独立运行：

```sh
python3 cert_probe.py --timeout 5 example.com
```

请只配置自己信任、确实需要检查的域名。采集器并不对 DNS 解析结果做公网强制校验，因此能修改该环境变量的人可能令其连接内网 443；请限制环境配置写权限并使用网络策略。域名探测和站点运行状态是不同信息。

## 离线测试

在本目录运行：

```sh
python3 -m unittest discover -v
python3 -m py_compile agent.py cert_probe.py
```

测试使用模拟文件和网络，不能代替对真实服务器、TLS 证书链和长期运行的验证。
