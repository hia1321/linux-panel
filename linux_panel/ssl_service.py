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
HTTPS_SERVICE = "linux-panel.service"
DEFAULT_HTTPS_PORT = 33972
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
        "pending_cert_path": "",
        "pending_key_path": "",
        "pending_cert_name": "",
        "pending_source": "",
        "pending_domains": [],
        "pending_server_name": "",
        "pending_port": DEFAULT_HTTPS_PORT,
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
    # Same-port HTTP -> HTTPS redirection is mandatory in the installed
    # deployment and is handled by protocol_mux, not this setting file.
    cfg["redirect_http"] = True
    if not isinstance(cfg.get("domains"), list):
        cfg["domains"] = []
    if not isinstance(cfg.get("pending_domains"), list):
        cfg["pending_domains"] = []
    try:
        cfg["pending_port"] = validate_https_port(cfg.get("pending_port") or cfg["port"])
    except (NameError, TypeError, ValueError):
        cfg["pending_port"] = cfg["port"]
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


def bootstrap_self_signed_certificate(port=DEFAULT_HTTPS_PORT):
    """Ensure the panel has a valid certificate and enabled HTTPS config.

    Existing valid certificates are preserved during upgrades; a self-signed
    certificate is generated on fresh installs or when the active pair is
    missing/invalid. The SAN includes detected interface IPs so LAN-IP access
    does not also produce a hostname-mismatch warning (the self-signed trust
    warning remains until the certificate is trusted by the browser).
    """
    port = validate_https_port(port)
    cfg = load_ssl_config()
    current_cert = cfg.get("cert_path") or ""
    current_key = cfg.get("key_path") or ""
    if current_cert and current_key and os.path.isfile(current_cert) and os.path.isfile(current_key):
        try:
            info = inspect_certificate_files(current_cert, current_key)
        except Exception as exc:
            log.warning("现有 HTTPS 证书无法使用，将生成自签名证书：%s", exc)
        else:
            cfg["enabled"] = True
            cfg["port"] = port
            cfg["pending_port"] = port
            cfg["redirect_http"] = True
            cfg["updated_at"] = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
            save_ssl_config(cfg)
            if cfg.get("source") == "letsencrypt":
                # Upgrade the old deploy hook, which used to restart the removed
                # standalone HTTPS unit on port 443.
                _write_renewal_hook()
                _enable_certbot_timer()
            return info, "已保留现有有效证书，并将 HTTPS 端口设置为 %s" % port

    self_signed_dir = os.path.join(SSL_DATA_DIR, "self-signed")
    os.makedirs(self_signed_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(SSL_DATA_DIR, 0o700)
        os.chmod(self_signed_dir, 0o700)
    except OSError:
        pass
    cert_path = os.path.join(self_signed_dir, "fullchain.pem")
    key_path = os.path.join(self_signed_dir, "privkey.pem")

    dns_names = ["localhost"]
    try:
        hostname = socket.gethostname().strip().rstrip(".").lower()
        fqdn = socket.getfqdn().strip().rstrip(".").lower()
        for candidate in (hostname, fqdn):
            if candidate and len(candidate) <= 253 and re.fullmatch(r"[a-z0-9.-]+", candidate) and candidate not in dns_names:
                dns_names.append(candidate)
    except OSError:
        pass

    ip_names = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None):
            try:
                ip_names.add(ipaddress.ip_address(result[4][0].split("%", 1)[0]))
            except (ValueError, IndexError):
                pass
    except OSError:
        pass
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        for item in out.stdout.split():
            try:
                ip_names.add(ipaddress.ip_address(item.split("%", 1)[0]))
            except ValueError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    now = _dt.datetime.now(_dt.timezone.utc)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Linux-Panel"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Linux-Panel Self-Signed"),
    ])
    san_entries = [x509.DNSName(name) for name in dns_names]
    san_entries.extend(x509.IPAddress(address) for address in sorted(ip_names, key=lambda x: (x.version, int(x))))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_data = certificate.public_bytes(serialization.Encoding.PEM)
    for path, data, mode in ((key_path, key_data, 0o600), (cert_path, cert_data, 0o644)):
        fd, tmp_path = tempfile.mkstemp(prefix=".bootstrap-", dir=self_signed_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    info = inspect_certificate_files(cert_path, key_path)
    # Preserve any uploaded-but-not-yet-enabled certificate fields, but make
    # the generated certificate the active default so HTTPS always starts.
    cfg.update({
        "enabled": True,
        "redirect_http": True,
        "port": port,
        "source": "self_signed",
        "domains": info["domains"],
        "server_name": "",
        "cert_path": cert_path,
        "key_path": key_path,
        "cert_name": "Linux-Panel self-signed certificate",
        "pending_port": port,
        "updated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
    })
    save_ssl_config(cfg)
    return info, "已生成并启用自签名 HTTPS 证书，监听端口 %s" % port


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


def inspect_certificate_files(cert_path, key_path, check_current=True):
    with open(cert_path, "rb") as f:
        cert_bytes = f.read(MAX_CERT_FILE_SIZE + 1)
    with open(key_path, "rb") as f:
        key_bytes = f.read(MAX_KEY_FILE_SIZE + 1)
    if len(cert_bytes) > MAX_CERT_FILE_SIZE or len(key_bytes) > MAX_KEY_FILE_SIZE:
        raise ValueError("证书或私钥文件超过 2 MiB")
    info = inspect_certificate(cert_bytes, key_bytes, check_current=check_current)
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
    # The panel itself is the HTTPS listener in force-HTTPS mode.
    return os.path.exists("/etc/systemd/system/linux-panel.service") or os.path.exists(
        "/lib/systemd/system/linux-panel.service"
    ) or os.path.exists("/usr/lib/systemd/system/linux-panel.service")


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
        raise RuntimeError("未找到 linux-panel.service。请先运行最新版 install.sh 配置 HTTPS 服务")


def _write_renewal_hook():
    hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
    os.makedirs(hook_dir, mode=0o755, exist_ok=True)
    # Remove the pre-migration hook that restarted the obsolete port-443 unit.
    legacy_hook = os.path.join(hook_dir, "50-linux-panel-https")
    try:
        if os.path.exists(legacy_hook):
            os.remove(legacy_hook)
    except OSError:
        pass
    hook_path = os.path.join(hook_dir, "50-linux-panel")
    content = "#!/bin/sh\n# Restart the HTTPS-only panel after Certbot deploys a renewed certificate.\nif grep -Eq '\"enabled\"[[:space:]]*:[[:space:]]*true' /opt/linux-panel/data/ssl.json 2>/dev/null; then\n  /usr/bin/systemctl restart linux-panel.service >/dev/null 2>&1 || /bin/systemctl restart linux-panel.service >/dev/null 2>&1 || true\nfi\n"
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
    """Persist the certificate settings and restart the HTTPS-only panel listener."""
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
        return "证书配置已保存，HTTPS 面板将在约 2 秒后重启；页面可能短暂断开"

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
    pending_certificate = None
    pending_cert_error = ""
    if cfg.get("pending_cert_path") and cfg.get("pending_key_path"):
        try:
            pending_certificate = inspect_certificate_files(cfg["pending_cert_path"], cfg["pending_key_path"])
        except Exception as exc:
            pending_cert_error = str(exc)
    domains = cfg.get("domains") or (certificate or {}).get("domains", [])
    first_domain = cfg.get("server_name") or next((d for d in domains if not d.startswith("*.")), "")
    port = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
    host = f"[{first_domain}]" if ":" in first_domain and not first_domain.startswith("[") else first_domain
    url = f"https://{host}:{port}" if host else ""
    return {
        "enabled": bool(cfg.get("enabled")),
        "active": active,
        # The TCP protocol multiplexer always redirects plaintext HTTP on the
        # public panel port. This is not a user-disableable feature.
        "redirect_http": True,
        "port": port,
        "source": cfg.get("source") or "none",
        "domains": domains,
        "server_name": first_domain,
        "url": url,
        "certbot_available": certbot_available(),
        "https_unit_available": https_unit_available(),
        "http_port": port,
        "service_state": service_state(),
        "certificate": certificate,
        "certificate_error": cert_error,
        "cert_path": cfg.get("cert_path") or "",
        "key_path": cfg.get("key_path") or "",
        "pending_certificate": pending_certificate,
        "pending_certificate_error": pending_cert_error,
        "pending_source": cfg.get("pending_source") or "",
        "pending_server_name": cfg.get("pending_server_name") or "",
        "pending_port": int(cfg.get("pending_port") or port),
        "pending_cert_path": cfg.get("pending_cert_path") or "",
        "certificates": list_ssl_certificates(),
    }


def _cert_pair_identity(cert_path, key_path):
    """Stable identity for a certificate/key pair without exposing its path to UI."""
    import hashlib
    cert_real = os.path.realpath(cert_path)
    key_real = os.path.realpath(key_path)
    return hashlib.sha256((cert_real + "\0" + key_real).encode("utf-8")).hexdigest()[:24]


def _same_cert_pair(cert_a, key_a, cert_b, key_b):
    if not cert_a or not key_a or not cert_b or not key_b:
        return False
    return (os.path.realpath(cert_a) == os.path.realpath(cert_b)
            and os.path.realpath(key_a) == os.path.realpath(key_b))


def _path_is_under(path, root):
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except (OSError, ValueError):
        return False


def _certificate_source_for_path(cert_path, cfg, is_active=False, is_pending=False):
    if is_pending and cfg.get("pending_source"):
        return cfg.get("pending_source")
    if is_active and cfg.get("source"):
        return cfg.get("source")
    # Certbot stores managed lineages under /etc/letsencrypt/live/<name>.
    if _path_is_under(cert_path, "/etc/letsencrypt/live"):
        return "letsencrypt"
    if _path_is_under(cert_path, CUSTOM_SSL_DIR):
        return "upload"
    if _path_is_under(cert_path, os.path.join(SSL_DATA_DIR, "self-signed")):
        return "self_signed"
    return "other"


def list_ssl_certificates(include_paths=False):
    """Inventory active, pending, uploaded, self-signed, and Certbot certificates.

    The browser receives metadata only. Private keys and certificate filesystem
    paths remain server-side. Expired certificates are retained in the list so
    administrators can identify them and switch to another stored certificate.
    """
    cfg = load_ssl_config()
    active_cert, active_key = cfg.get("cert_path") or "", cfg.get("key_path") or ""
    pending_cert, pending_key = cfg.get("pending_cert_path") or "", cfg.get("pending_key_path") or ""
    candidates = {}

    def add(cert_path, key_path, hint=""):
        cert_path = os.path.abspath(cert_path or "")
        key_path = os.path.abspath(key_path or "")
        if not cert_path or not key_path or not os.path.isfile(cert_path) or not os.path.isfile(key_path):
            return
        identity = _cert_pair_identity(cert_path, key_path)
        if identity not in candidates:
            candidates[identity] = {"id": identity, "cert_path": cert_path,
                                    "key_path": key_path, "hint": hint}

    # Insert configured pairs first so the canonical configured/live paths win
    # if a managed certificate appears more than once via symlinks.
    add(active_cert, active_key, "active")
    add(pending_cert, pending_key, "pending")

    self_dir = os.path.join(SSL_DATA_DIR, "self-signed")
    add(os.path.join(self_dir, "fullchain.pem"), os.path.join(self_dir, "privkey.pem"), "self_signed")

    try:
        entries = sorted(os.scandir(CUSTOM_SSL_DIR), key=lambda ent: ent.name.lower())
    except OSError:
        entries = []
    for ent in entries:
        if not ent.is_dir(follow_symlinks=False):
            continue
        add(os.path.join(ent.path, "fullchain.pem"), os.path.join(ent.path, "privkey.pem"), "upload")

    le_root = "/etc/letsencrypt/live"
    try:
        le_entries = sorted(os.scandir(le_root), key=lambda ent: ent.name.lower())
    except OSError:
        le_entries = []
    for ent in le_entries:
        if not ent.is_dir(follow_symlinks=True):
            continue
        add(os.path.join(ent.path, "fullchain.pem"), os.path.join(ent.path, "privkey.pem"), "letsencrypt")

    now = _dt.datetime.now(_dt.timezone.utc)
    records = []
    for identity, item in candidates.items():
        cert_path, key_path = item["cert_path"], item["key_path"]
        is_active = _same_cert_pair(cert_path, key_path, active_cert, active_key)
        is_pending = _same_cert_pair(cert_path, key_path, pending_cert, pending_key)
        source = _certificate_source_for_path(cert_path, cfg, is_active, is_pending)
        try:
            info = inspect_certificate_files(cert_path, key_path, check_current=False)
        except Exception as exc:
            # A bad/expired pair should not make the entire inventory disappear.
            records.append({
                "id": identity, "_cert_path": cert_path, "_key_path": key_path,
                "domains": [], "subject": "证书无法读取",
                "issuer": "—", "source": source,
                "source_label": {"letsencrypt": "Let's Encrypt", "upload": "用户上传",
                                 "self_signed": "自签名", "other": "其他证书"}.get(source, source),
                "expires_at": "", "expires_at_display": "—", "days_left": None,
                "not_before": "", "is_active": is_active, "is_pending": is_pending,
                "status": "error", "status_label": "读取失败", "validity": "error", "error": str(exc),
                "name": os.path.basename(os.path.dirname(cert_path)),
            })
            continue

        try:
            not_before = _dt.datetime.fromisoformat(info["not_before"])
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=_dt.timezone.utc)
        except (KeyError, TypeError, ValueError):
            not_before = now
        try:
            not_after = _dt.datetime.fromisoformat(info["expires_at"])
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=_dt.timezone.utc)
        except (KeyError, TypeError, ValueError):
            not_after = now

        if now < not_before:
            validity, validity_label = "not_yet_valid", "尚未生效"
        elif now >= not_after:
            validity, validity_label = "expired", "已过期"
        else:
            validity, validity_label = "valid", "有效"

        if is_pending and validity != "valid":
            status, status_label = validity, "待启用（%s）" % validity_label
        elif is_pending:
            status, status_label = "pending", "待启用"
        elif is_active:
            if validity != "valid":
                status, status_label = validity, "当前配置（%s）" % validity_label
            elif cfg.get("enabled") and service_state() == "active":
                status, status_label = "active", "当前使用"
            else:
                status, status_label = "configured", "当前配置"
        else:
            status, status_label = validity, validity_label

        if source == "letsencrypt":
            name = os.path.basename(os.path.dirname(cert_path))
        elif source in ("upload", "self_signed"):
            name = os.path.basename(os.path.dirname(cert_path))
        else:
            name = cfg.get("cert_name") if is_active else os.path.basename(os.path.dirname(cert_path))

        preferred_domain = (cfg.get("pending_server_name") if is_pending else cfg.get("server_name") if is_active else "") or ""
        if not preferred_domain:
            preferred_domain = next((d for d in info.get("domains", []) if not d.startswith("*.")), "")

        records.append({
            "id": identity,
            "_cert_path": cert_path,
            "_key_path": key_path,
            "domains": info.get("domains", []),
            "subject": info.get("subject", "—"),
            "issuer": info.get("issuer", "—"),
            "source": source,
            "source_label": {"letsencrypt": "Let's Encrypt", "upload": "用户上传",
                             "self_signed": "自签名", "other": "其他证书"}.get(source, source),
            "expires_at": info.get("expires_at", ""),
            "expires_at_display": info.get("expires_at_display", "—"),
            "days_left": info.get("days_left"),
            "not_before": info.get("not_before", ""),
            "is_active": is_active,
            "is_pending": is_pending,
            "status": status,
            "status_label": status_label,
            "validity": validity,
            "error": "",
            "name": name or preferred_domain or "证书",
            "server_name": preferred_domain,
        })

    # Put the current and staged certificates first, then soonest-expiring
    # records. Expired certificates remain visible at the bottom.
    def sort_key(record):
        priority = 0 if record.get("is_active") else 1 if record.get("is_pending") else 2
        days = record.get("days_left")
        if isinstance(days, int) and days >= 0:
            validity_order, expiry_order = 0, days
        elif isinstance(days, int):
            validity_order, expiry_order = 1, abs(days)
        else:
            validity_order, expiry_order = 2, 10**9
        return (priority, validity_order, expiry_order, str(record.get("name", "")).lower())
    records.sort(key=sort_key)
    if include_paths:
        return records
    # Do not expose server filesystem paths in the public API response.
    return [{key: value for key, value in record.items() if not key.startswith("_")}
            for record in records]



def _find_stored_certificate(certificate_id):
    """Return an inventoried certificate record by its opaque ID."""
    certificate_id = str(certificate_id or "").strip()
    if not re.fullmatch(r"[a-f0-9]{24}", certificate_id):
        raise ValueError("证书标识无效，请刷新证书列表后重试")
    item = next((entry for entry in list_ssl_certificates(include_paths=True)
                 if entry.get("id") == certificate_id), None)
    if not item:
        raise ValueError("找不到这张证书，可能已删除；请刷新证书列表")
    return item


def _certificate_download_pair_details(certificate_id):
    """Resolve and validate a listed certificate/key pair for an authenticated export."""
    item = _find_stored_certificate(certificate_id)
    cert_path = os.path.abspath(item.get("_cert_path") or "")
    key_path = os.path.abspath(item.get("_key_path") or "")
    if not cert_path or not os.path.isfile(cert_path):
        raise ValueError("证书文件不存在")
    if not key_path or not os.path.isfile(key_path):
        raise ValueError("对应的私钥文件不存在")

    allowed_roots = (
        os.path.realpath(SSL_DATA_DIR),
        os.path.realpath("/etc/letsencrypt"),
    )
    cfg = load_ssl_config()
    configured_pairs = (
        (cfg.get("cert_path"), cfg.get("key_path")),
        (cfg.get("pending_cert_path"), cfg.get("pending_key_path")),
    )
    is_configured_pair = any(
        cert and key and _same_cert_pair(cert_path, key_path, cert, key)
        for cert, key in configured_pairs
    )
    for path, label in ((cert_path, "证书"), (key_path, "私钥")):
        real_path = os.path.realpath(path)
        in_allowed_root = any(_path_is_under(real_path, root) for root in allowed_roots)
        if not in_allowed_root and not is_configured_pair:
            raise ValueError(f"{label}路径不在允许导出的证书目录中")

    # Validate key match and TLS loadability, but allow old/expired certificates
    # to be downloaded for backup or migration.
    inspect_certificate_files(cert_path, key_path, check_current=False)
    label = str(item.get("name") or "certificate")
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._-") or "certificate"
    return cert_path, key_path, label


def certificate_download_details(certificate_id):
    """Return the public full-chain path and a safe filename."""
    cert_path, _key_path, label = _certificate_download_pair_details(certificate_id)
    return cert_path, f"{label}-fullchain.pem"


def certificate_download_bundle(certificate_id):
    """Build a ZIP containing only fullchain.pem and privkey.key.

    The private key is sensitive and is exported only through the authenticated
    SSL-management route after explicit user confirmation in the UI.
    """
    import io
    import stat
    import zipfile

    cert_path, key_path, label = _certificate_download_pair_details(certificate_id)
    with open(cert_path, "rb") as f:
        cert_bytes = f.read(MAX_CERT_FILE_SIZE + 1)
    with open(key_path, "rb") as f:
        key_bytes = f.read(MAX_KEY_FILE_SIZE + 1)
    if len(cert_bytes) > MAX_CERT_FILE_SIZE or len(key_bytes) > MAX_KEY_FILE_SIZE:
        raise ValueError("证书或私钥文件超过 2 MiB，拒绝打包下载")

    cert_blocks = re.findall(
        br"-----BEGIN CERTIFICATE-----\s*.*?\s*-----END CERTIFICATE-----",
        cert_bytes, flags=re.S,
    )
    if not cert_blocks:
        raise ValueError("证书文件中未找到 PEM CERTIFICATE 区块")
    try:
        # Validate that the private key is readable and in PEM format before export.
        serialization.load_pem_private_key(key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("无法读取私钥；目前仅支持未加密 PEM 私钥导出") from exc

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # fullchain.pem contains the leaf certificate and any intermediate chain.
        zf.writestr("fullchain.pem", cert_bytes)
        # Keep restrictive Unix permissions in the archive metadata.
        private_info = zipfile.ZipInfo("privkey.key")
        private_info.compress_type = zipfile.ZIP_DEFLATED
        private_info.external_attr = (stat.S_IFREG | 0o600) << 16
        zf.writestr(private_info, key_bytes)
    return archive.getvalue(), f"{label}-certificate.zip"


def delete_stored_certificate(certificate_id):
    """Delete a certificate that is not in active use by the panel.

    Uploaded and inactive bootstrap self-signed pairs are removed from the
    panel's SSL data directory. Inactive Certbot lineages are deleted through
    Certbot itself so its renewal metadata remains consistent. A certificate
    currently used by this panel is never deleted.
    """
    item = _find_stored_certificate(certificate_id)
    cert_path = os.path.abspath(item.get("_cert_path") or "")
    key_path = os.path.abspath(item.get("_key_path") or "")
    cfg = load_ssl_config()

    if _same_cert_pair(cert_path, key_path, cfg.get("cert_path"), cfg.get("key_path")):
        raise ValueError("不能删除当前正在使用的证书，请先启用其他证书")

    is_pending = _same_cert_pair(
        cert_path, key_path, cfg.get("pending_cert_path"), cfg.get("pending_key_path")
    )
    source = item.get("source") or "other"

    if source in ("upload", "self_signed"):
        cert_real = os.path.realpath(cert_path)
        key_real = os.path.realpath(key_path)
        cert_dir = os.path.dirname(cert_real)
        if (os.path.basename(cert_real) != "fullchain.pem"
                or os.path.basename(key_real) != "privkey.pem"
                or cert_dir != os.path.dirname(key_real)
                or not os.path.isfile(cert_real) or not os.path.isfile(key_real)):
            raise ValueError("证书目录结构不符合预期，已拒绝删除")

        if source == "upload":
            allowed_parent = os.path.realpath(CUSTOM_SSL_DIR)
            # Every upload is stored in its own direct child version directory.
            if (os.path.dirname(cert_dir) != allowed_parent
                    or not _path_is_under(cert_dir, allowed_parent)):
                raise ValueError("上传证书路径不在允许删除的目录中")
        else:
            allowed_self_signed = os.path.realpath(os.path.join(SSL_DATA_DIR, "self-signed"))
            if cert_dir != allowed_self_signed:
                raise ValueError("自签名证书路径不符合预期，已拒绝删除")

        if is_pending:
            cfg.update({
                "pending_cert_path": "", "pending_key_path": "", "pending_cert_name": "",
                "pending_source": "", "pending_domains": [], "pending_server_name": "",
                "pending_port": int(cfg.get("port") or DEFAULT_HTTPS_PORT),
            })
            save_ssl_config(cfg)

        if source == "upload":
            shutil.rmtree(cert_dir)
        else:
            # Delete only the two expected files; leave the directory in place
            # so a future installer run can safely regenerate this fallback.
            os.remove(cert_real)
            os.remove(key_real)
        return "已删除证书%s" % ("（待启用记录已清除）" if is_pending else "")

    if source == "letsencrypt":
        live_root = os.path.realpath("/etc/letsencrypt/live")
        cert_parent = os.path.abspath(os.path.dirname(cert_path))
        lineage = os.path.basename(cert_parent)
        if (os.path.basename(cert_path) != "fullchain.pem"
                or os.path.basename(key_path) != "privkey.pem"
                or os.path.dirname(key_path) != cert_parent
                or os.path.dirname(cert_parent) != "/etc/letsencrypt/live"
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", lineage)):
            raise ValueError("Certbot 证书路径不符合预期，已拒绝删除")
        if not shutil.which("certbot"):
            raise RuntimeError("未找到 certbot，无法安全删除托管证书")
        try:
            result = subprocess.run(
                ["certbot", "delete", "--cert-name", lineage, "--non-interactive"],
                capture_output=True, text=True, timeout=180,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Certbot 删除证书超时，请检查 Certbot 状态") from exc
        if result.returncode != 0:
            details = (result.stderr or result.stdout or "Certbot 删除失败").strip()
            raise RuntimeError(details[-2000:])
        return f"已通过 Certbot 删除证书 {lineage}。若其他站点也使用它，请检查相关服务配置。"

    raise ValueError("此证书来源不支持删除")


def activate_stored_certificate(certificate_id):
    """Activate a certificate selected from list_ssl_certificates()."""
    certificate_id = str(certificate_id or "").strip()
    if not re.fullmatch(r"[a-f0-9]{24}", certificate_id):
        raise ValueError("证书标识无效，请刷新证书列表后重试")
    item = next((entry for entry in list_ssl_certificates(include_paths=True)
                 if entry["id"] == certificate_id), None)
    if not item:
        raise ValueError("找不到此证书，可能已被删除；请刷新证书列表")
    if item.get("error"):
        raise ValueError("此证书无法读取，不能启用：" + item["error"])
    cfg = load_ssl_config()
    cert_path, key_path = item["_cert_path"], item["_key_path"]
    # Always re-validate expiry, private key match, and OpenSSL loadability before activation.
    info = inspect_certificate_files(cert_path, key_path)
    source = item.get("source") or "other"
    cfg.update({
        "enabled": True,
        "redirect_http": True,
        "source": source,
        "domains": info.get("domains", []),
        "server_name": item.get("server_name") or next((d for d in info.get("domains", []) if not d.startswith("*.")), ""),
        "cert_path": cert_path,
        "key_path": key_path,
        "cert_name": item.get("name", ""),
        "pending_cert_path": "",
        "pending_key_path": "",
        "pending_cert_name": "",
        "pending_source": "",
        "pending_domains": [],
        "pending_server_name": "",
        "pending_port": int(cfg.get("port") or DEFAULT_HTTPS_PORT),
    })
    message = commit_and_activate(cfg)
    return message


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
            # Staging only: don't change the active certificate or restart HTTPS.
            "pending_source": "upload",
            "pending_domains": info["domains"],
            "pending_server_name": server_name,
            "pending_cert_path": cert_path,
            "pending_key_path": key_path,
            "pending_cert_name": "",
            "pending_port": port,
            "updated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        })
        save_ssl_config(cfg)
        # Keep previous uploaded certificate versions: the SSL page presents a
        # certificate inventory and lets the administrator switch between them.
        return info, "证书已上传并验证，尚未启用 HTTPS。请确认信息后点击“启用证书”"
    except Exception:
        shutil.rmtree(version_dir, ignore_errors=True)
        raise


def _prune_old_uploads(keep=3):
    try:
        cfg = load_ssl_config()
        current = cfg.get("cert_path", "")
        current_dir = os.path.dirname(current)
        pending = cfg.get("pending_cert_path", "")
        pending_dir = os.path.dirname(pending) if pending else ""
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
        if pending_dir:
            retained.add(os.path.realpath(pending_dir))
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
        "redirect_http": True,
        "port": port,
        "source": "letsencrypt",
        "domains": domains,
        "server_name": domains[0],
        "cert_path": cert_path,
        "key_path": key_path,
        "cert_name": cert_name,
        "pending_cert_path": "",
        "pending_key_path": "",
        "pending_cert_name": "",
        "pending_source": "",
        "pending_domains": [],
        "pending_server_name": "",
        "pending_port": port,
    })
    message = commit_and_activate(cfg)
    return info, message, output[-3000:]


def disable_https():
    # The installer runs the panel only with TLS. Stopping HTTPS would leave no
    # management endpoint, so certificate changes are supported but disabling
    # HTTPS is deliberately not supported.
    raise ValueError("此版本强制使用 HTTPS，不能停用 HTTPS 服务。请更换或重新申请证书。")


def set_http_redirect(enabled):
    """Keep same-port HTTP-to-HTTPS redirects permanently enabled."""
    cfg = load_ssl_config()
    cfg["redirect_http"] = True
    save_ssl_config(cfg)
    if not enabled:
        return "安全策略：HTTP→HTTPS 跳转不可关闭，已保持启用"
    return "同端口 HTTP→HTTPS 跳转已启用"


def redirect_target_for_request(request):
    # Legacy compatibility helper. The installed single-port multiplexer now
    # performs redirects before Flask, so this function is not used there.
    if os.environ.get("PANEL_FORCE_HTTPS") == "1":
        return None
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
        ipaddress.ip_address(host)
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
    else:
        # Never rewrite literal-IP HTTP requests to a certificate domain.
        # A domain certificate doesn't apply to IP URLs, and LAN admins may
        # intentionally use the HTTP listener for recovery/local access.
        return None
    if ":" in host:
        host = f"[{host}]"
    port = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
    netloc = f"{host}:{port}"
    return "https://" + netloc + request.full_path.rstrip("?")


__all__ = [name for name in globals() if not name.startswith("__")]
