"""SSL certificate management helpers for Linux-Panel.

Custom certificates live below DATA_DIR/ssl. Let's Encrypt certificates remain
managed by Certbot under /etc/letsencrypt so Certbot's renewal workflow stays intact.
"""
import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import uuid
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .config import DATA_DIR, PORT, log

SSL_CONFIG_PATH = os.path.join(DATA_DIR, "ssl.json")
SSL_DATA_DIR = os.path.join(DATA_DIR, "ssl")
CUSTOM_SSL_DIR = os.path.join(SSL_DATA_DIR, "custom")
HTTPS_SERVICE = "linux-panel-https.service"
DEFAULT_HTTPS_PORT = 443
MAX_CERT_FILE_SIZE = 2 * 1024 * 1024
MAX_KEY_FILE_SIZE = 2 * 1024 * 1024

os.makedirs(CUSTOM_SSL_DIR, mode=0o700, exist_ok=True)
try:
    os.chmod(SSL_DATA_DIR, 0o700)
    os.chmod(CUSTOM_SSL_DIR, 0o700)
except OSError:
    pass


def default_ssl_config():
    return {
        "enabled": False,
        "redirect_http": True,
        "port": DEFAULT_HTTPS_PORT,
        "source": "none",
        "domains": [],
        "cert_path": "",
        "key_path": "",
        "cert_name": "",
        "server_name": "",
        "updated_at": "",
    }


def load_ssl_config():
    cfg = default_ssl_config()
    try:
        with open(SSL_CONFIG_PATH, "r", encoding="utf-8") as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            cfg.update(stored)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError) as exc:
        log.error("读取 SSL 配置失败：%s", exc)
    try:
        cfg["port"] = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
    except (TypeError, ValueError):
        cfg["port"] = DEFAULT_HTTPS_PORT
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["redirect_http"] = bool(cfg.get("redirect_http", True))
    if not isinstance(cfg.get("domains"), list):
        cfg["domains"] = []
    return cfg


def save_ssl_config(cfg):
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    tmp_path = SSL_CONFIG_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, SSL_CONFIG_PATH)
    try:
        os.chmod(SSL_CONFIG_PATH, 0o600)
    except OSError:
        pass


def _read_upload(file_storage, label):
    if not file_storage or not getattr(file_storage, "filename", ""):
        raise ValueError(f"请选择{label}文件")
    data = file_storage.stream.read(MAX_CERT_FILE_SIZE + 1)
    if not data:
        raise ValueError(f"{label}文件为空")
    if len(data) > MAX_CERT_FILE_SIZE:
        raise ValueError(f"{label}文件不能超过 2 MiB")
    return data


def _cert_dates(cert):
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
    return not_before, not_after


def inspect_certificate(cert_bytes, key_bytes, check_current=True):
    """Validate PEM certificate/key pair and return display metadata."""
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as exc:
        raise ValueError("证书无法解析，请上传 PEM 格式证书；建议使用 fullchain.pem") from exc
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except TypeError as exc:
        raise ValueError("当前仅支持未加密的 PEM 私钥，请先导出为未加密私钥文件") from exc
    except Exception as exc:
        raise ValueError("私钥无法解析，请上传与证书配套的 PEM 私钥") from exc

    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_pub != key_pub:
        raise ValueError("证书与私钥不匹配")

    not_before, not_after = _cert_dates(cert)
    now = _dt.datetime.now(_dt.timezone.utc)
    if check_current and now < not_before:
        raise ValueError(f"证书尚未生效：{not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if check_current and now >= not_after:
        raise ValueError(f"证书已过期：{not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = sorted(set(san.get_values_for_type(x509.DNSName)))
    except x509.ExtensionNotFound:
        pass
    if not names:
        names = [attr.value for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    subject = cert.subject.rfc4514_string() or "(未知主题)"
    issuer = cert.issuer.rfc4514_string() or "(未知颁发者)"
    days_left = (not_after - now).days
    return {
        "subject": subject,
        "issuer": issuer,
        "domains": names,
        "not_before": not_before.isoformat(),
        "expires_at": not_after.isoformat(),
        "expires_at_display": not_after.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "days_left": days_left,
    }


def inspect_certificate_files(cert_path, key_path):
    with open(cert_path, "rb") as f:
        cert_bytes = f.read(MAX_CERT_FILE_SIZE + 1)
    with open(key_path, "rb") as f:
        key_bytes = f.read(MAX_KEY_FILE_SIZE + 1)
    if len(cert_bytes) > MAX_CERT_FILE_SIZE or len(key_bytes) > MAX_KEY_FILE_SIZE:
        raise ValueError("证书或私钥文件超过 2 MiB")
    info = inspect_certificate(cert_bytes, key_bytes)
    # Confirm OpenSSL can actually load the pair in server mode.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return info


def validate_https_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("HTTPS 端口必须是数字")
    if not 1 <= port <= 65535:
        raise ValueError("HTTPS 端口范围必须为 1–65535")
    return port


def normalize_domains(value):
    raw_items = re.split(r"[\s,;，；]+", (value or "").strip())
    domains = []
    for item in raw_items:
        if not item:
            continue
        if item.startswith("*."):
            raise ValueError("当前一键申请使用 HTTP-01 验证，不支持泛域名证书")
        name = item.rstrip(".").encode("idna").decode("ascii").lower()
        if len(name) > 253 or "." not in name:
            raise ValueError(f"域名格式不正确：{item}")
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise ValueError("Let’s Encrypt 域名申请不能填写 IP 地址，请填写解析到本服务器的域名")
        labels = name.split(".")
        if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise ValueError(f"域名格式不正确：{item}")
        if name not in domains:
            domains.append(name)
    if not domains:
        raise ValueError("请至少填写一个域名")
    if len(domains) > 20:
        raise ValueError("一次最多申请 20 个域名")
    return domains


def normalize_server_name(value, certificate_domains):
    """Validate the hostname used in links/HTTP redirects against certificate SANs."""
    value = (value or "").strip().rstrip(".")
    if not value:
        value = next((d for d in certificate_domains if not d.startswith("*.")), "")
        if not value:
            raise ValueError("该证书仅包含泛域名，请填写实际访问域名，例如 panel.example.com")
    try:
        host = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("HTTPS 访问域名格式不正确") from exc
    if len(host) > 253 or "." not in host:
        raise ValueError("HTTPS 访问域名格式不正确")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("HTTPS 访问域名请填写 DNS 域名，不要填写 IP 地址")
    labels = host.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ValueError("HTTPS 访问域名格式不正确")
    for pattern in certificate_domains:
        if pattern == host:
            return host
        if pattern.startswith("*.") and host.endswith(pattern[1:]) and host.count(".") == pattern.count("."):
            return host
    raise ValueError("填写的 HTTPS 访问域名不在证书的 SAN 域名列表中")


def valid_email(value):
    value = (value or "").strip()
    if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("请填写有效的邮箱地址，用于接收证书到期等通知")
    return value


def certbot_available():
    return shutil.which("certbot") is not None


def https_unit_available():
    return os.path.exists("/etc/systemd/system/linux-panel-https.service") or os.path.exists(
        "/lib/systemd/system/linux-panel-https.service"
    ) or os.path.exists("/usr/lib/systemd/system/linux-panel-https.service")


def service_state():
    if not shutil.which("systemctl"):
        return "unavailable"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", HTTPS_SERVICE],
            capture_output=True, text=True, timeout=5,
        )
        state_text = (result.stdout or result.stderr).strip()
        if result.returncode != 0 and ("could not be found" in state_text.lower() or "not loaded" in state_text.lower()):
            return "not-found"
        state = state_text.splitlines()
        return state[0] if state else "unknown"
    except Exception:
        return "unknown"


def _systemctl(args, timeout=30):
    if not shutil.which("systemctl"):
        return False, "未检测到 systemctl；请在安装为 systemd 服务的环境中使用 HTTPS 管理"
    try:
        result = subprocess.run(
            ["systemctl", *args], capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "systemctl 命令执行超时"
    except OSError as exc:
        return False, str(exc)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemctl 执行失败").strip()
        return False, detail[-2500:]
    return True, (result.stdout or "").strip()


def _schedule_service_action(action, delay=1.5):
    """Delay restarts/stops so an API response can reach an HTTPS browser first."""
    def run_action():
        ok, message = _systemctl(action, timeout=60)
        if not ok:
            log.error("延迟执行 systemctl %s 失败：%s", " ".join(action), message)
    timer = threading.Timer(delay, run_action)
    timer.daemon = True
    timer.start()


def _port_available(port):
    # The installed service binds PANEL_HOST=0.0.0.0, so check the IPv4 wildcard
    # specifically; an available IPv6-only socket must not mask an IPv4 conflict.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
        return True
    except OSError as exc:
        raise ValueError(f"HTTPS 端口 {port} 无法绑定，可能已被其他服务占用：{exc}") from exc
    finally:
        sock.close()


def _ensure_https_unit():
    if not https_unit_available():
        raise RuntimeError("未找到 linux-panel-https.service。请先用最新版 install.sh 更新安装，再启用 HTTPS")


def _write_renewal_hook():
    hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
    os.makedirs(hook_dir, mode=0o755, exist_ok=True)
    hook_path = os.path.join(hook_dir, "50-linux-panel-https")
    content = "#!/bin/sh\n# Restart only while SSL Management says HTTPS is enabled.\nif grep -Eq '\"enabled\"[[:space:]]*:[[:space:]]*true' /opt/linux-panel/data/ssl.json 2>/dev/null; then\n  /usr/bin/systemctl restart linux-panel-https.service >/dev/null 2>&1 || /bin/systemctl restart linux-panel-https.service >/dev/null 2>&1 || true\nfi\n"
    tmp = hook_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, 0o750)
    os.replace(tmp, hook_path)


def _enable_certbot_timer():
    # Debian/Ubuntu packages generally ship certbot.timer; do not fail issuance if
    # a distribution exposes its renewal timer under another name.
    ok, _ = _systemctl(["enable", "--now", "certbot.timer"], timeout=20)
    if not ok:
        log.warning("无法启用 certbot.timer；请检查当前系统的 Certbot 自动续期定时器")


def _ensure_certbot():
    if certbot_available():
        return
    if not shutil.which("apt-get"):
        raise RuntimeError("未检测到 Certbot，也未检测到 apt-get。请先安装 Certbot，再重新申请证书")
    # apt update can fail because an optional CD-ROM source is broken while the
    # requested packages remain installable, so proceed to install regardless.
    try:
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True, text=True, timeout=180)
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", "certbot"],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("安装 Certbot 超时，请检查软件源和网络") from exc
    if result.returncode != 0 or not certbot_available():
        detail = (result.stderr or result.stdout or "apt-get 安装 Certbot 失败").strip()
        raise RuntimeError("自动安装 Certbot 失败：" + detail[-2500:])


def commit_and_activate(new_cfg):
    """Persist configuration and make the dedicated HTTPS listener active."""
    _ensure_https_unit()
    old_cfg = load_ssl_config()
    port = validate_https_port(new_cfg.get("port", DEFAULT_HTTPS_PORT))
    if service_state() == "active":
        if port != int(old_cfg.get("port") or DEFAULT_HTTPS_PORT):
            _port_available(port)
    else:
        _port_available(port)

    new_cfg = dict(new_cfg)
    new_cfg["enabled"] = True
    new_cfg["port"] = port
    new_cfg["updated_at"] = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    save_ssl_config(new_cfg)

    if service_state() == "active":
        _schedule_service_action(["restart", HTTPS_SERVICE])
        return "证书配置已保存，HTTPS 服务将在约 2 秒后重启；页面可能短暂断开"

    ok, msg = _systemctl(["enable", "--now", HTTPS_SERVICE], timeout=45)
    if not ok or service_state() != "active":
        save_ssl_config(old_cfg)
        if old_cfg.get("enabled"):
            _systemctl(["restart", HTTPS_SERVICE], timeout=45)
        else:
            _systemctl(["disable", "--now", HTTPS_SERVICE], timeout=45)
        detail = msg or "服务没有进入 active 状态"
        raise RuntimeError("HTTPS 服务启动失败，已恢复旧配置。详情：" + detail)
    return "证书已保存，HTTPS 服务已启用"


def ssl_status():
    cfg = load_ssl_config()
    active = service_state() == "active"
    certificate = None
    cert_error = ""
    if cfg.get("cert_path") and cfg.get("key_path"):
        try:
            certificate = inspect_certificate_files(cfg["cert_path"], cfg["key_path"])
        except Exception as exc:
            cert_error = str(exc)
    domains = cfg.get("domains") or (certificate or {}).get("domains", [])
    first_domain = cfg.get("server_name") or next((d for d in domains if not d.startswith("*.")), "")
    port = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
    host = f"[{first_domain}]" if ":" in first_domain and not first_domain.startswith("[") else first_domain
    url = f"https://{host}" if host and port == 443 else (f"https://{host}:{port}" if host else "")
    return {
        "enabled": bool(cfg.get("enabled")),
        "active": active,
        "redirect_http": bool(cfg.get("redirect_http", True)),
        "port": port,
        "source": cfg.get("source") or "none",
        "domains": domains,
        "server_name": first_domain,
        "url": url,
        "certbot_available": certbot_available(),
        "https_unit_available": https_unit_available(),
        "http_port": PORT,
        "service_state": service_state(),
        "certificate": certificate,
        "certificate_error": cert_error,
        "cert_path": cfg.get("cert_path") or "",
        "key_path": cfg.get("key_path") or "",
    }


def save_uploaded_certificate(cert_bytes, key_bytes, port, server_name=""):
    initial_info = inspect_certificate(cert_bytes, key_bytes)
    server_name = normalize_server_name(server_name, initial_info["domains"])
    upload_id = _dt.datetime.now().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    version_dir = os.path.join(CUSTOM_SSL_DIR, upload_id)
    os.makedirs(version_dir, mode=0o700, exist_ok=False)
    cert_path = os.path.join(version_dir, "fullchain.pem")
    key_path = os.path.join(version_dir, "privkey.pem")
    try:
        for path, data, mode in ((cert_path, cert_bytes, 0o644), (key_path, key_bytes, 0o600)):
            fd, tmp_path = tempfile.mkstemp(prefix=".upload-", dir=version_dir)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp_path, mode)
                os.replace(tmp_path, path)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        info = inspect_certificate_files(cert_path, key_path)
        old = load_ssl_config()
        cfg = dict(old)
        cfg.update({
            "enabled": True,
            "redirect_http": bool(old.get("redirect_http", True)),
            "port": port,
            "source": "upload",
            "domains": info["domains"],
            "server_name": server_name,
            "cert_path": cert_path,
            "key_path": key_path,
            "cert_name": "",
        })
        message = commit_and_activate(cfg)
        _prune_old_uploads(keep=3)
        return info, message
    except Exception:
        shutil.rmtree(version_dir, ignore_errors=True)
        raise


def _prune_old_uploads(keep=3):
    try:
        current = load_ssl_config().get("cert_path", "")
        current_dir = os.path.dirname(current)
        dirs = []
        for entry in os.scandir(CUSTOM_SSL_DIR):
            if entry.is_dir(follow_symlinks=False):
                try:
                    dirs.append((entry.stat(follow_symlinks=False).st_mtime, entry.path))
                except OSError:
                    pass
        dirs.sort(reverse=True)
        retained = {path for _, path in dirs[:keep]}
        if current_dir:
            retained.add(os.path.realpath(current_dir))
        for _, path in dirs:
            if os.path.realpath(path) not in retained:
                shutil.rmtree(path, ignore_errors=True)
    except OSError as exc:
        log.warning("清理旧 SSL 上传文件失败：%s", exc)


def issue_letsencrypt(domain_value, email_value, port):
    domains = normalize_domains(domain_value)
    email = valid_email(email_value)
    port = validate_https_port(port)
    _ensure_https_unit()
    if service_state() != "active":
        _port_available(port)
    elif port != int(load_ssl_config().get("port") or DEFAULT_HTTPS_PORT):
        _port_available(port)

    _ensure_certbot()
    domain_slug = re.sub(r"[^a-z0-9-]+", "-", domains[0]).strip("-")[:75]
    import hashlib
    domain_set_hash = hashlib.sha256("\n".join(domains).encode("utf-8")).hexdigest()[:8]
    cert_name = f"linux-panel-{domain_slug}-{domain_set_hash}"
    cmd = [
        "certbot", "certonly", "--standalone", "--non-interactive",
        "--agree-tos", "--keep-until-expiring", "--email", email,
        "--cert-name", cert_name,
    ]
    for domain in domains:
        cmd.extend(["-d", domain])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Let’s Encrypt 申请超时。请检查域名解析、80 端口连通性及服务器网络") from exc
    except OSError as exc:
        raise RuntimeError(f"无法执行 Certbot：{exc}") from exc
    output = "\n".join(s for s in (result.stdout, result.stderr) if s).strip()
    if result.returncode != 0:
        raise RuntimeError("证书申请失败。请确认域名已解析到本机、外网可访问 TCP 80，且 80 端口没有被其他服务占用。Certbot 信息：\n" + output[-3500:])

    cert_path = f"/etc/letsencrypt/live/{cert_name}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{cert_name}/privkey.pem"
    try:
        info = inspect_certificate_files(cert_path, key_path)
    except Exception as exc:
        raise RuntimeError(f"Certbot 返回成功，但无法验证生成的证书：{exc}\n{output[-1500:]}") from exc

    _write_renewal_hook()
    _enable_certbot_timer()
    old = load_ssl_config()
    cfg = dict(old)
    cfg.update({
        "enabled": True,
        "redirect_http": bool(old.get("redirect_http", True)),
        "port": port,
        "source": "letsencrypt",
        "domains": domains,
        "server_name": domains[0],
        "cert_path": cert_path,
        "key_path": key_path,
        "cert_name": cert_name,
    })
    message = commit_and_activate(cfg)
    return info, message, output[-3000:]


def disable_https():
    cfg = load_ssl_config()
    cfg["enabled"] = False
    save_ssl_config(cfg)
    if service_state() == "active":
        _schedule_service_action(["disable", "--now", HTTPS_SERVICE])
        return "HTTPS 已停用，监听服务将在约 2 秒后停止；HTTP 面板将恢复可用"
    ok, msg = _systemctl(["disable", "--now", HTTPS_SERVICE], timeout=30)
    if not ok and "not found" not in msg.lower():
        log.warning("停用 HTTPS 服务时收到提示：%s", msg)
    return "HTTPS 已停用"


def set_http_redirect(enabled):
    cfg = load_ssl_config()
    cfg["redirect_http"] = bool(enabled)
    save_ssl_config(cfg)
    return "HTTP 自动跳转 HTTPS 已开启" if enabled else "HTTP 自动跳转 HTTPS 已关闭"


def redirect_target_for_request(request):
    cfg = load_ssl_config()
    if not cfg.get("enabled") or not cfg.get("redirect_http"):
        return None
    # If the TLS listener crashed or is stopped, keep HTTP reachable so an
    # administrator can disable HTTPS or inspect the failure from the UI.
    if service_state() != "active":
        return None
    # The HTTP process only calls this helper. The dedicated TLS process must not redirect.
    try:
        host = urlsplit("//" + request.host).hostname or ""
    except Exception:
        host = ""
    if not host:
        return None
    domains = cfg.get("domains") or []
    allowed_host = cfg.get("server_name") or next((d for d in domains if not d.startswith("*.")), "")
    if not allowed_host:
        return None
    try:
        host_ip = ipaddress.ip_address(host)
        host = allowed_host
    except ValueError:
        host_l = host.lower().rstrip(".")
        valid_host = host_l in domains or host_l == allowed_host
        if not valid_host:
            valid_host = any(
                d.startswith("*.") and host_l.endswith(d[1:]) and host_l.count(".") == d.count(".")
                for d in domains
            )
        if not valid_host:
            host = allowed_host
        else:
            host = host_l
    if ":" in host:
        host = f"[{host}]"
    port = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
    netloc = host if port == 443 else f"{host}:{port}"
    return "https://" + netloc + request.full_path.rstrip("?")


__all__ = [name for name in globals() if not name.startswith("__")]
