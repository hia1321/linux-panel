#!/usr/bin/env python3
"""Linux-Panel entry point. Feature code is organized in the linux_panel package."""
import os
import ssl
import sys
import socket
import threading
import time

from linux_panel import create_app
from linux_panel.core import (
    CRON_DIR, FILE_ROOT, HOST, LOG_FILE, PORT, TASK_DIR,
    socketio, sync_all_cron_files, ufw_available,
)
from linux_panel.ssl_service import load_ssl_config
from linux_panel.protocol_mux import choose_loopback_port, create_listener, serve as serve_protocol_mux

# Even when launched manually (outside systemd), an installed configuration
# with an enabled certificate must run in TLS mode, never fall back to HTTP.
_initial_ssl_cfg = load_ssl_config()
if _initial_ssl_cfg.get("enabled"):
    os.environ["PANEL_SSL_SERVER"] = "1"
    os.environ["PANEL_FORCE_HTTPS"] = "1"

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
        print("         sudo env PANEL_SSL_SERVER=1 PANEL_FORCE_HTTPS=1 python3 app.py")
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

    # Scheduled task files must be synchronized before starting the TCP
    # multiplexer and its loopback-only TLS application backend.
    try:
        sync_all_cron_files()
    except Exception as exc:
        print(f"⚠️  同步任务文件失败：{exc}")

    if os.environ.get("PANEL_SSL_SERVER") == "1" or os.environ.get("PANEL_FORCE_HTTPS") == "1":
        ssl_cfg = load_ssl_config()
        if not ssl_cfg.get("enabled"):
            print("✗ HTTPS 强制模式没有可用证书。请运行 install.sh 生成自签名证书，或修复 SSL 管理中的证书配置。")
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
            https_port = int(ssl_cfg.get("port", 33972))
        except Exception as exc:
            print(f"✗ HTTPS 证书加载失败：{exc}")
            sys.exit(1)
        # Public TCP port speaks both HTTP and HTTPS. Plain HTTP is answered
        # with a same-host/same-port HTTPS redirect; TLS is passed through to a
        # private loopback-only Flask-SocketIO listener. This preserves WSS and
        # keeps 443 unused.
        public_listener = create_listener(HOST, https_port)
        backend_port = choose_loopback_port()
        backend_error = []

        def run_tls_backend():
            try:
                socketio.run(
                    app, host="127.0.0.1", port=backend_port, debug=False,
                    ssl_context=tls_context, allow_unsafe_werkzeug=True,
                    use_reloader=False,
                )
            except BaseException as exc:
                backend_error.append(exc)
                print(f"✗ HTTPS 后端启动失败：{exc}", flush=True)

        backend_thread = threading.Thread(target=run_tls_backend, name="panel-tls-backend", daemon=True)
        backend_thread.start()

        # Fail clearly instead of accepting public connections if the inner TLS
        # listener cannot bind. The local probe closes immediately and is only
        # used to test whether the TCP listener is ready.
        backend_ready = False
        probe_context = ssl.create_default_context()
        probe_context.check_hostname = False
        probe_context.verify_mode = ssl.CERT_NONE
        for _ in range(60):
            if backend_error or not backend_thread.is_alive():
                break
            try:
                raw_probe = socket.create_connection(("127.0.0.1", backend_port), timeout=0.3)
                with probe_context.wrap_socket(raw_probe, server_hostname="localhost"):
                    backend_ready = True
                    break
            except OSError:
                time.sleep(0.1)
        if not backend_ready:
            public_listener.close()
            print(f"✗ HTTPS 后端未能在 127.0.0.1:{backend_port} 启动。", flush=True)
            if backend_error:
                print(f"原因：{backend_error[-1]}", flush=True)
            sys.exit(1)

        print(f"🔒 HTTPS: https://<服务器IP>:{https_port}", flush=True)
        print(f"↪ HTTP: 同端口收到 HTTP 请求时跳转到相同主机的 HTTPS 地址", flush=True)
        print(f"📄 证书: {cert_path}", flush=True)
        print(f"🔧 TLS 后端仅监听 127.0.0.1:{backend_port}（不对外开放）", flush=True)
        serve_protocol_mux(public_listener, "127.0.0.1", backend_port)
    else:
        print("✗ Linux-Panel 当前版本强制使用 HTTPS，拒绝启动 HTTP 服务。请运行 install.sh 生成/配置证书，或设置有效的 TLS 启动环境。")
        sys.exit(1)
