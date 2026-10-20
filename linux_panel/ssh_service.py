import base64
import hashlib
import os
import shutil
import socket as pysocket
import subprocess
import tempfile
SSHD_CONFIG = "/etc/ssh/sshd_config"
AUTHORIZED_KEYS = os.path.expanduser("~/.ssh/authorized_keys")

# ============================================================================
# SSH 密钥
# ============================================================================
def fingerprint_from_pubkey(pub):
    parts = (pub or "").strip().split()
    if len(parts) < 2: return ""
    try: blob = base64.b64decode(parts[1])
    except: return ""
    d = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(d).decode().rstrip("=")

def load_private_key(text, pp=None):
    from cryptography.hazmat.primitives.serialization import (
        load_ssh_private_key, load_pem_private_key)
    text = text.strip().encode()
    try: return load_ssh_private_key(text, password=pp.encode() if pp else None)
    except Exception:
        try: return load_pem_private_key(text, password=pp.encode() if pp else None)
        except Exception as e: raise RuntimeError(f"无法解析私钥：{e}")

def pub_from_priv(pkey):
    from cryptography.hazmat.primitives import serialization
    return pkey.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH).decode()

def key_type_of(pkey):
    name = pkey.__class__.__name__.lower()
    if "ed25519" in name: return "ed25519"
    if "rsa" in name: return "rsa"
    if "ecdsa" in name: return "ecdsa"
    return "unknown"

def generate_ssh_key(key_type, bits, comment, passphrase):
    key_type = key_type.lower()
    if key_type not in ("ed25519", "rsa", "ecdsa"):
        raise RuntimeError("不支持的密钥类型")
    with tempfile.TemporaryDirectory() as tmp:
        kp = os.path.join(tmp, "id")
        args = ["ssh-keygen", "-t", key_type, "-f", kp, "-N", passphrase or "", "-q"]
        if key_type in ("rsa", "ecdsa") and bits: args += ["-b", str(bits)]
        args += ["-C", comment or f"panel@{pysocket.gethostname()}"]
        try: r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except FileNotFoundError: raise RuntimeError("未找到 ssh-keygen")
        if r.returncode != 0: raise RuntimeError(r.stderr.strip() or "ssh-keygen 失败")
        priv = open(kp, "r", encoding="utf-8").read()
        pub = open(kp + ".pub", "r", encoding="utf-8").read().strip()
    return priv, pub


# ============================================================================
# sshd_config
# ============================================================================

def read_sshd_config():
    if not os.path.exists(SSHD_CONFIG):
        return {"port": "22", "password_auth": "yes", "pubkey_auth": "yes",
                "root_login": "yes", "error": "找不到 sshd_config"}
    cfg = {"port": "22", "password_auth": "yes", "pubkey_auth": "yes", "root_login": "yes"}
    with open(SSHD_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            low = s.lower()
            for k in ("port", "passwordauthentication",
                      "pubkeyauthentication", "permitrootlogin"):
                if low.startswith(k + " "):
                    parts = s.split(None, 1)
                    if len(parts) == 2:
                        v = parts[1].strip().lower()
                        if k == "port": cfg["port"] = v
                        elif k == "passwordauthentication": cfg["password_auth"] = v
                        elif k == "pubkeyauthentication": cfg["pubkey_auth"] = v
                        elif k == "permitrootlogin": cfg["root_login"] = v
    return cfg

def update_sshd_config(port, password_auth, pubkey_auth, root_login=None):
    if not os.path.exists(SSHD_CONFIG): raise RuntimeError("找不到 sshd_config")
    try:
        pn = int(port)
        if not (1 <= pn <= 65535): raise ValueError
    except (ValueError, TypeError): raise RuntimeError("端口非法")
    if password_auth not in ("yes", "no"): raise RuntimeError("密码登录值非法")
    if pubkey_auth not in ("yes", "no"): raise RuntimeError("密钥登录值非法")
    with open(SSHD_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    new_lines = []
    flags = {"port": False, "password": False, "pubkey": False, "root": False}
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            new_lines.append(line); continue
        low = s.lower()
        if low.startswith("port "):
            new_lines.append(f"Port {pn}\n"); flags["port"] = True
        elif low.startswith("passwordauthentication "):
            new_lines.append(f"PasswordAuthentication {password_auth}\n"); flags["password"] = True
        elif low.startswith("pubkeyauthentication "):
            new_lines.append(f"PubkeyAuthentication {pubkey_auth}\n"); flags["pubkey"] = True
        elif low.startswith("permitrootlogin ") and root_login:
            new_lines.append(f"PermitRootLogin {root_login}\n"); flags["root"] = True
        else:
            new_lines.append(line)
    if not flags["port"]: new_lines.append(f"\nPort {pn}\n")
    if not flags["password"]: new_lines.append(f"PasswordAuthentication {password_auth}\n")
    if not flags["pubkey"]: new_lines.append(f"PubkeyAuthentication {pubkey_auth}\n")
    if root_login and not flags["root"]:
        new_lines.append(f"PermitRootLogin {root_login}\n")
    shutil.copy2(SSHD_CONFIG, SSHD_CONFIG + ".bak")
    with open(SSHD_CONFIG, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    chk = subprocess.run(["sshd", "-t"], capture_output=True, text=True)
    if chk.returncode != 0:
        shutil.copy2(SSHD_CONFIG + ".bak", SSHD_CONFIG)
        raise RuntimeError(f"配置校验失败：{chk.stderr.strip()}")
    return True

def restart_ssh():
    for cmd in (["systemctl", "restart", "ssh"],
                ["systemctl", "restart", "sshd"],
                ["service", "ssh", "restart"],
                ["service", "sshd", "restart"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.returncode == 0: return True
        except Exception: continue
    raise RuntimeError("重启 SSH 服务失败")

def ssh_service_status():
    for svc in ("ssh", "sshd"):
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                               capture_output=True, text=True, timeout=5)
            st = r.stdout.strip()
            if st in ("active", "inactive", "failed"): return st
        except Exception: pass
    return "unknown"

def read_authorized_keys():
    if not os.path.exists(AUTHORIZED_KEYS): return []
    out = []
    with open(AUTHORIZED_KEYS, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            s = line.strip()
            if not s or s.startswith("#"): continue
            parts = s.split(None, 2)
            if len(parts) < 2: continue
            out.append({
                "index": i, "key_type": parts[0],
                "comment": parts[2] if len(parts) > 2 else "",
                "fingerprint": fingerprint_from_pubkey(s), "raw": s,
            })
    return out

def add_authorized_key(pub_key):
    pub_key = (pub_key or "").strip()
    if not pub_key.startswith(("ssh-", "ecdsa-")):
        raise RuntimeError("公钥格式不正确")
    d = os.path.dirname(AUTHORIZED_KEYS)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try: os.chmod(d, 0o700)
    except OSError: pass
    existing = set()
    if os.path.exists(AUTHORIZED_KEYS):
        with open(AUTHORIZED_KEYS) as f:
            for line in f:
                s = line.strip()
                if s: existing.add(s)
    if pub_key in existing: return False
    content = ""
    if os.path.exists(AUTHORIZED_KEYS):
        with open(AUTHORIZED_KEYS) as f: content = f.read()
    with open(AUTHORIZED_KEYS, "a") as f:
        if content and not content.endswith("\n"): f.write("\n")
        f.write(pub_key + "\n")
    try: os.chmod(AUTHORIZED_KEYS, 0o600)
    except OSError: pass
    return True

def remove_authorized_key(index):
    if not os.path.exists(AUTHORIZED_KEYS): return False
    with open(AUTHORIZED_KEYS) as f: lines = f.readlines()
    if index < 0 or index >= len(lines): return False
    del lines[index]
    with open(AUTHORIZED_KEYS, "w") as f: f.writelines(lines)
    return True

def ssh_login_stats():
    success, failed = 0, 0
    try:
        r = subprocess.run(["journalctl", "-u", "ssh", "--since", "today", "--no-pager"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "Accepted " in line: success += 1
                elif "Failed " in line or "Invalid user" in line: failed += 1
    except Exception:
        try:
            r = subprocess.run(["grep", "-E", "(Accepted|Failed) ", "/var/log/auth.log"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "Accepted " in line: success += 1
                elif "Failed " in line: failed += 1
        except Exception: pass
    return {"success": success, "failed": failed}

__all__ = [name for name in globals() if not name.startswith("__")]
