#!/usr/bin/env python3
"""Linux-Panel entry point. Feature code is organized in the linux_panel package."""
import os
import ssl
import sys

from linux_panel import create_app
from linux_panel.core import (
    CRON_DIR, FILE_ROOT, HOST, LOG_FILE, PORT, TASK_DIR,
    socketio, sync_all_cron_files, ufw_available,
)
from linux_panel.ssl_service import load_ssl_config

app = create_app()


def require_root():
    """Require root, matching the original panel's operating model."""
    if os.geteuid() != 0:
        bar = "=" * 64
        print(f"\n{bar}")
        print("  ✗ 错误：linux-panel 只能以 root 身份运行")
        print(f"{bar}")
        print("  请使用以下方式之一启动：")
        print("    1) 安装为系统服务（推荐）：")
        print("         sudo bash install.sh")
        print("         sudo linux-panel start")
        print("    2) 临时以 root 运行：")
        print("         sudo python3 app.py")
        print(f"{bar}\n")
        sys.exit(1)


def check_ufw():
    if not ufw_available():
        print("⚠️  未检测到 ufw，防火墙功能不可用")
        print("   安装：sudo apt install -y ufw\n")


def check_cron_d():
    """Warn if /etc/cron.d is missing (cron jobs may not work)."""
    if not os.path.isdir(CRON_DIR):
        print(f"⚠️  未检测到 {CRON_DIR} 目录，计划任务可能无法工作")
        print("   安装 cron：sudo apt install -y cron && sudo systemctl enable --now cron\n")


if __name__ == "__main__":
    require_root()
    print("\n面板启动中…")
    check_ufw()
    check_cron_d()

    if os.environ.get("PANEL_SSL_SERVER") == "1":
        ssl_cfg = load_ssl_config()
        if not ssl_cfg.get("enabled"):
            print("✗ HTTPS 服务未启用证书配置。请先在面板的 SSL 管理中上传证书或申请 Let’s Encrypt 证书。")
            sys.exit(1)
        cert_path = ssl_cfg.get("cert_path") or ""
        key_path = ssl_cfg.get("key_path") or ""
        if not cert_path or not key_path or not os.path.isfile(cert_path) or not os.path.isfile(key_path):
            print("✗ HTTPS 证书文件不存在，请重新上传证书或重新申请。")
            sys.exit(1)
        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            https_port = int(ssl_cfg.get("port", 443))
        except Exception as exc:
            print(f"✗ HTTPS 证书加载失败：{exc}")
            sys.exit(1)
        print(f"🔒 https://<域名>:{https_port}" if https_port != 443 else "🔒 https://<域名>")
        print(f"📄 证书: {cert_path}")
        # Cron files are synchronized by the primary HTTP process to avoid two
        # listeners racing while writing the same system files.
        socketio.run(app, host=HOST, port=https_port, debug=False,
                     ssl_context=tls_context, allow_unsafe_werkzeug=True)
    else:
        try:
            sync_all_cron_files()
        except Exception as exc:
            print(f"⚠️  同步计划任务失败：{exc}")
        print(f"📡 http://{HOST}:{PORT}")
        print(f"📂 文件根目录: {FILE_ROOT}")
        print(f"📄 日志: {LOG_FILE}")
        print(f"⏰ 计划任务: {TASK_DIR}")
        socketio.run(app, host=HOST, port=PORT, debug=False,
                     allow_unsafe_werkzeug=True)
