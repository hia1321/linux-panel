# Linux-Panel 模块化版本

## 目录结构

- `app.py`：启动入口、root 检查、启动提示。
- `linux_panel/__init__.py`：Flask 应用工厂、扩展初始化、蓝图注册。
- `linux_panel/core.py`：配置、日志、数据库、认证装饰器、共享系统工具和业务辅助函数。
- `linux_panel/routes/auth.py`：登录、登出、账号管理。
- `linux_panel/routes/pages.py`：主页面入口。
- `linux_panel/routes/files.py`：文件管理 API。
- `linux_panel/routes/cron.py`：计划任务 API。
- `linux_panel/routes/ssh.py`：SSH 服务与密钥管理 API。
- `linux_panel/routes/firewall.py`：UFW 防火墙 API。
- `linux_panel/routes/docker.py`：Docker 安装、配置、容器、镜像、网络及数据卷 API。
- `linux_panel/routes/dns.py`：阿里云 DNS 与腾讯云 DNSPod API。
- `linux_panel/routes/ssl.py`：证书上传、Let’s Encrypt 申请、HTTPS 启停与跳转设置 API。
- `linux_panel/ssl_service.py`：证书校验、私钥匹配、Certbot 调用、systemd HTTPS 服务及自动续期钩子。
- `linux_panel/routes/terminal.py`：Socket.IO Web 终端事件。
- `linux_panel/templates/`：独立 HTML 页面，不再嵌在 Python 字符串中。

## 部署方式

保持整个目录的文件结构上传到仓库根目录。原有 `install.sh` 仍然通过 `/opt/linux-panel/app.py` 启动，无须更改 systemd 的入口路径。依赖仍由 `requirements.txt` 安装到 `venv`。

本次拆分保留原有 HTTP API 路径、请求字段和响应格式；蓝图内部的 Flask endpoint 名称变成带模块前缀的名称，但面板页面使用的 URL 路径不变。

## SSL / HTTPS 管理

- 左侧「SSL 管理」采用分栏标签页，分为「证书信息」「申请证书」「上传证书」「HTTPS 设置」；支持上传 PEM 证书链和匹配的未加密 PEM 私钥，或一键通过 Certbot / Let’s Encrypt 申请证书；已保存的证书停用后也可以直接重新启用。
- HTTPS 使用独立的 `linux-panel-https.service` 服务，默认监听 TCP 443；原 HTTP 服务仍监听 `PANEL_PORT`（默认 33972），可用于停用 HTTPS 后恢复访问。
- 启用 SSL 后默认将 HTTP 请求跳转到证书域名的 HTTPS 地址；可在 SSL 管理页关闭该跳转。
- Let’s Encrypt 使用 HTTP-01 standalone 验证，需要域名解析到服务器、外网 TCP 80 可访问且该端口空闲。证书会由 Certbot 自动续期，续期成功后会重启 HTTPS 服务。
- 启用 HTTPS 前确认防火墙/云安全组放通所配置的 HTTPS TCP 端口（默认 443）。自定义上传的证书不会自动续期，需要在到期前重新上传。主面板响应禁用 HTML 缓存，更新前端后可避免继续加载旧版页面脚本。
- 用户上传的证书存放在 `data/ssl/custom/`，私钥权限为 `0600`，SSL 配置文件 `data/ssl.json` 权限为 `0600`。建议继续限制面板账号访问权限。
