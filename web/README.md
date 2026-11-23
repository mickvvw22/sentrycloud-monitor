# SentryCloud Monitor Web 前端

## 已完成

- 从零实现自适应现代暗色监控面板，包含：概览、服务器、域名 / 站点、历史、设置。
- 登录界面支持 `username`、`password`、可选 TOTP，并使用后端要求的 `totp` 字段调用同源 REST API。
- 设置页先通过 `/api/me` 读取 `totp_enabled`；未启用时调用 `/api/totp/setup`，用本地随项目部署的 `vendor/qrcode.js` 在浏览器中生成 `otpauth://` 二维码，不把绑定 URI 发给二维码服务；手动密钥仅放在折叠的备用说明中。启用和关闭均通过表单提交，关闭同时提交 `password` 与 `code`。
- 目标页支持新建与删除目标：HTTP / HTTPS check 显式提交 `interval_seconds: 60`，TCP check 可填写 host / port 并提交 `{kind:"tcp",host,port,interval_seconds:60}`；没有数据时只显示空状态，不伪造在线或成功状态。
- 服务器页与概览页解析 `/api/agents` 返回的 `{agent_id,metrics(JSON string),certificates(JSON string array),received_at}`；指标读取 `cpu_used_percent`、`memory.used_percent`、`disk.used_percent`、`network.rx_bytes/tx_bytes`、`uptime_seconds`，证书展示到期时间、剩余天数或后端错误，空数组显示未配置且不宣称自动告警；历史页先读取每个 target 的 checks，再按同一 check 调用 `/api/checks/:id/latest|history`。
- API 调用集中在 `app.js` 的 `api` 适配对象中，所有 D1 列表响应均按 `{results:[...]}` 读取；不存在全局 `/api/checks/latest` 调用。
- 用户数据均经过 HTML 转义后再进入模板；交互使用原生 DOM、`textContent`、事件委托和 `encodeURIComponent`，避免直接注入未处理用户数据。
- 具备逐接口错误通知与连接状态（部分失败不会显示全部成功）、空状态、键盘可操作表单、ARIA 标签、移动端布局适配。

## 文件

- `index.html`：页面结构、登录界面、导航、目标表单与各业务页面。
- `styles.css`：暗色主题、响应式布局、指标卡、表格、状态标识、趋势图与对话框样式。
- `app.js`：API 适配、状态管理、渲染、登录 / 登出、目标 CRUD、TOTP 操作与错误处理。
- `vendor/qrcode.js`：MIT 许可的本地二维码编码库；`vendor/qrcode-LICENSE.txt` 保留许可文本。

## 校验

- 已执行：`node --check app.js`，并完成 API 路径、方法、字段和 D1 `{results:[...]}` 响应形状的 mock/契约检查。
- 结果：通过。
- 未部署、未创建 GitHub 仓库、未读取或复制其他项目源码。
