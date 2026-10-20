# Linux-Panel 强制 HTTPS 部署说明

## 安装行为

- 安装时自动生成并启用自签名 TLS/HTTPS 证书，证书 SAN 尽可能包含本机网卡 IP 和主机名。
- 主服务 `linux-panel.service` 在默认 TCP 33972 端口接收 HTTP 和 HTTPS。
- HTTP 请求返回 `308`，跳转到相同主机、端口、路径和查询参数的 HTTPS URL；不替换成证书配置里的域名。
- TLS 字节流通过本机 TCP 代理转发到仅监听 `127.0.0.1` 的 Flask-SocketIO TLS 后端，支持普通 HTTPS、登录 Cookie 和 WSS/WebSocket。
- 不再创建/启用旧版 `linux-panel-https.service` 的 443 监听；TLS 后端的随机回环端口不对外开放。
- 升级时如果原有证书仍然有效，会保留该证书并将端口迁移到安装配置端口；如果不存在有效证书，则创建自签名证书。
- SSL 管理仍支持上传 PEM 证书和申请 Let’s Encrypt；申请 Let’s Encrypt 的 HTTP-01 验证需要外网可访问 TCP 80，但面板本身仍然只监听 HTTPS。
- HTTPS 是必需服务，SSL 管理中不能停用 HTTPS；可以上传新证书并单独启用。

## 访问

HTTPS 直接访问：`https://服务器IP:33972`。输入 `http://服务器IP:33972` 时会自动跳转到相同 IP 和端口的 HTTPS 地址。

自签名证书会被浏览器默认视为不受信任，因此第一次访问仍会显示安全警告。安装程序会尽可能将服务器 IP 写入证书 SAN 以避免额外的名称不匹配；要消除不受信任警告，需要在客户端信任该证书或换用受信任 CA 签发的证书。

## 防火墙

需要允许面板 HTTPS TCP 33972。若要从 SSL 管理申请 Let’s Encrypt 证书，还必须允许公网访问 TCP 80。

```bash
sudo ufw allow 33972/tcp
sudo ufw allow 80/tcp   # 仅在申请/续期使用 HTTP-01 时需要外部可达
```

## 服务管理

```bash
sudo linux-panel status
sudo linux-panel logs
sudo linux-panel restart
```

旧的 `linux-panel-https.service` 会在升级安装时停止并移除，避免继续占用 443。

## SSL 证书列表

- SSL 管理的“证书信息”页将证书改为列表显示，能枚举当前配置证书、待启用证书、`data/ssl/custom/` 下的上传证书、安装时生成的自签名证书，以及 `/etc/letsencrypt/live/` 下由 Certbot 管理的证书。
- 列表包含域名、来源、颁发者、到期时间、状态和操作；支持展开查看详情，并把有效的已保存证书切换为当前证书。
- 过期证书仍显示在列表中方便查看，但不能直接启用；激活前会再次验证证书有效期、私钥匹配和 TLS 加载。
- 新上传的证书版本会保留在列表中，不再在上传时自动清理旧版本。
- 列表 API 不返回证书或私钥的服务器文件路径，也不会返回私钥内容。


## 文件管理默认页与证书下载/删除

- 登录后访问 `/` 会跳转到 `/files`，避免 SPA 在根路径 `/` 初始化为未知栏目而显示空列表。
- SSL 证书列表提供“下载”按钮，下载公开证书链 `fullchain.pem`，不会导出私钥。
- “删除”会保护当前正在使用的证书；支持删除不在使用中的用户上传证书和面板自签名证书。非活动的 Let's Encrypt lineage 通过 `certbot delete` 删除，并在确认框提示可能影响共享该证书的其他站点。
- 证书删除前会校验证书 ID 与证书目录布局；不会允许通过请求参数指定任意服务器路径。
