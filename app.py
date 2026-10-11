import base64, errno, fcntl, hashlib, hmac, io, logging, os, pty, re, secrets
import select, shutil, signal, socket as pysocket, sqlite3, stat, struct
import subprocess, tarfile, tempfile, termios, threading, time, zipfile
import sys
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler

from cryptography.fernet import Fernet
from flask import (Flask, jsonify, redirect, render_template_string,
                   request, send_file, session, url_for)
from flask_socketio import SocketIO, emit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH  = os.path.join(DATA_DIR, "panel.db")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")
LOG_FILE = os.path.join(DATA_DIR, "panel.log")

FILE_ROOT = os.path.realpath(os.environ.get("PANEL_FILE_ROOT", "/"))
HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("PANEL_PORT", "33972"))

MAX_EDIT_SIZE   = 5 * 1024 * 1024
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024 * 1024

_h = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
_h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log = logging.getLogger("panel"); log.addHandler(_h); log.setLevel(logging.INFO)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


def _load_fernet():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f: k = f.read().strip()
    else:
        k = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f: f.write(k)
        try: os.chmod(KEY_FILE, 0o600)
        except OSError: pass
    return Fernet(k)

fernet = _load_fernet()


# ============================================================================
# 数据库
# ============================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def db_one(sql, args=()):
    c = get_db()
    try:
        r = c.execute(sql, args).fetchone()
        return dict(r) if r else None
    finally: c.close()

def db_all(sql, args=()):
    c = get_db()
    try: return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally: c.close()

def db_exec(sql, args=()):
    c = get_db()
    try:
        cur = c.execute(sql, args); c.commit(); return cur.lastrowid
    finally: c.close()

def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"

def verify_password(pw, stored):
    try: _, salt, digest = stored.split("$")
    except ValueError: return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120_000)
    return hmac.compare_digest(dk.hex(), digest)

def init_db():
    c = get_db()
    try:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ssh_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, key_type TEXT NOT NULL, bits INTEGER,
                private_key_enc BLOB NOT NULL, public_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL, comment TEXT,
                passphrase_enc BLOB, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_notes (
                path TEXT PRIMARY KEY,
                note TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        c.commit()
        if c.execute("SELECT COUNT(*) AS x FROM users").fetchone()["x"] == 0:
            pw = os.environ.get("PANEL_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
            c.execute("INSERT INTO users(username,password,created_at) VALUES(?,?,?)",
                      ("hia1321", hash_password(pw), datetime.now().isoformat(timespec="seconds")))
            c.commit()
            bar = "=" * 64
            print(f"\n{bar}\n面板已初始化")
            print(f"  访问 : http://<服务器IP>:{PORT}")
            print(f"  用户 : hia1321")
            print(f"  密  码 : {pw}")
            print(f"  日志 : {LOG_FILE}")
            print(f"  ⚠️  请登录后立即修改密码\n{bar}\n")
    finally: c.close()

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify(code=401, msg="未登录")
            return redirect(url_for("login_page"))
        return f(*a, **kw)
    return w


class PathError(Exception):
    pass

def resolve(rel, must_exist=False):
    rel = (rel or "").strip().replace("\\", "/").lstrip("/")
    full = FILE_ROOT if not rel or rel == "." else \
        os.path.realpath(os.path.join(FILE_ROOT, rel))
    prefix = FILE_ROOT if FILE_ROOT.endswith(os.sep) else FILE_ROOT + os.sep
    if full != FILE_ROOT and not full.startswith(prefix):
        raise PathError("路径越界")
    if must_exist and not os.path.lexists(full):
        raise PathError("路径不存在")
    return full

def api_guard(f):
    @wraps(f)
    def w(*a, **kw):
        try: return f(*a, **kw)
        except PathError as e: return jsonify(code=400, msg=str(e))
        except PermissionError as e: return jsonify(code=403, msg=f"权限不足：{e}")
        except FileNotFoundError: return jsonify(code=404, msg="文件不存在")
        except IsADirectoryError: return jsonify(code=400, msg="目标是目录")
        except OSError as e:
            if e.errno == errno.ENOSPC:
                return jsonify(code=507, msg="磁盘空间不足")
            return jsonify(code=500, msg=f"系统错误：{e.strerror or e}")
    return w

def uid_name(uid):
    import pwd
    try: return pwd.getpwuid(uid).pw_name
    except: return str(uid)

def gid_name(gid):
    import grp
    try: return grp.getgrgid(gid).gr_name
    except: return str(gid)

def check_name(name):
    name = (name or "").strip()
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise PathError("非法名称")
    return name

def check_port(port):
    port = (port or "").strip()
    if not re.match(r"^\d+(?::\d+)?(?:,\d+(?::\d+)?)*$", port):
        raise PathError("端口格式不正确")
    for p in re.findall(r"\d+", port):
        if not (1 <= int(p) <= 65535):
            raise PathError(f"端口 {p} 超出范围")
    return port


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
SSHD_CONFIG = "/etc/ssh/sshd_config"
AUTHORIZED_KEYS = os.path.expanduser("~/.ssh/authorized_keys")

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


# ============================================================================
# ufw
# ============================================================================
def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired: return -1, "", "命令超时"
    except FileNotFoundError: return -1, "", f"命令不存在：{args[0]}"

def ufw_available():
    return run_cmd(["which", "ufw"])[0] == 0

def _parse_ufw_rules():
    code, out, _ = run_cmd(["ufw", "status", "numbered"])
    if code != 0: return []
    rules = []
    for line in out.splitlines():
        m = re.match(r"^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.*?)\s*$", line)
        if not m: continue
        num, to, action, _d, src = m.groups()
        to_clean = re.sub(r"\s*\(v6\)\s*$", "", to).strip()
        pm = re.match(r"^(\d+(?:[:,\d]*)?)(?:/(\w+))?(?:\s|$)", to_clean)
        if not pm: continue
        port, proto = pm.group(1), (pm.group(2) or "any")
        source = "" if src.strip() in ("Anywhere", "Anywhere (v6)") else src.strip()
        rules.append({"num": int(num), "port": port, "proto": proto.lower(),
                      "action": action.lower(), "source": source})
    return rules

def ufw_status():
    code, out, err = run_cmd(["ufw", "status", "verbose"])
    if code != 0:
        return {"installed": ufw_available(), "active": False, "rules": [],
                "error": err.strip() or "无法获取 ufw 状态"}
    active = bool(re.search(r"^Status:\s*active", out, re.M))
    all_rules = _parse_ufw_rules()
    step1 = {}
    for r in all_rules:
        key = (r["port"], r["proto"], r["action"], r["source"])
        if key not in step1:
            step1[key] = dict(r); step1[key]["nums"] = [r["num"]]
        else: step1[key]["nums"].append(r["num"])
    step2 = {}
    for r in step1.values():
        key = (r["port"], r["action"], r["source"])
        if key not in step2:
            step2[key] = {"port": r["port"], "action": r["action"],
                          "source": r["source"], "protos": {r["proto"]},
                          "nums": list(r["nums"])}
        else:
            step2[key]["protos"].add(r["proto"])
            step2[key]["nums"].extend(r["nums"])
    rules = []
    for v in step2.values():
        protos = v["protos"]
        if "any" in protos or ("tcp" in protos and "udp" in protos): dp = "any"
        elif "tcp" in protos: dp = "tcp"
        elif "udp" in protos: dp = "udp"
        else: dp = "any"
        rules.append({"port": v["port"], "proto": dp, "action": v["action"],
                      "source": v["source"], "nums": sorted(set(v["nums"]))})
    rules.sort(key=lambda r: (int(re.match(r"\d+", r["port"]).group()) if re.match(r"\d+", r["port"]) else 0, r["proto"]))
    return {"installed": True, "active": active, "rules": rules}

def ufw_add(port, proto, source):
    port = check_port(port)
    proto = (proto or "any").lower()
    source = (source or "").strip()
    if source and not re.match(r"^[\d\./:a-fA-F]+$", source):
        return False, "来源地址格式不正确"
    st = ufw_status()
    existing = [r for r in st.get("rules", [])
                if r["port"] == port and r["source"] == source and r["action"] == "allow"]
    protos_existing = set(r["proto"] for r in existing)
    for r in existing:
        if r["proto"] == "any":
            return False, f"端口 {port} 已放行（ANY），无需重复添加"
        if r["proto"] == proto:
            return False, f"端口 {port} 已放行（{proto.upper()}），无需重复添加"
    upgrade = False
    if proto == "any" and protos_existing: upgrade = True
    elif proto == "tcp" and "udp" in protos_existing: upgrade = True
    elif proto == "udp" and "tcp" in protos_existing: upgrade = True
    if upgrade:
        nums_del = []
        for r in existing: nums_del.extend(r["nums"])
        for n in sorted(set(nums_del), reverse=True):
            run_cmd(["ufw", "--force", "delete", str(n)])
        if source: args = ["ufw", "allow", "from", source, "to", "any", "port", port]
        else: args = ["ufw", "allow", port]
        code, out, err = run_cmd(args)
        if code != 0: return False, (err.strip() or out.strip() or "ufw 执行失败")
        return True, f"端口 {port} 已合并升级为 ANY"
    if proto == "any":
        args = ["ufw", "allow", port] if not source else \
            ["ufw", "allow", "from", source, "to", "any", "port", port]
    else:
        args = ["ufw", "allow", f"{port}/{proto}"] if not source else \
            ["ufw", "allow", "from", source, "to", "any", "port", port, "proto", proto]
    code, out, err = run_cmd(args)
    if code != 0: return False, (err.strip() or out.strip() or "ufw 执行失败")
    return True, out.strip()

def ufw_delete_nums(nums):
    for n in sorted(set(int(n) for n in nums), reverse=True):
        code, out, err = run_cmd(["ufw", "--force", "delete", str(n)])
        if code != 0: return False, (err.strip() or f"删除规则 #{n} 失败")
    return True, "已删除"

def ufw_switch(enable):
    cmd = ["ufw", "--force", "enable" if enable else "disable"]
    code, out, err = run_cmd(cmd)
    if code != 0: return False, (err.strip() or out.strip() or "操作失败")
    return True, "ok"


# ============================================================================
# Flask
# ============================================================================
app = Flask(__name__)
app.secret_key = fernet._signing_key
app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  JSON_AS_ASCII=False)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*",
                    max_http_buffer_size=64*1024*1024, ping_timeout=60, ping_interval=25)
init_db()


# ============================================================================
# 认证
# ============================================================================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("user"): return redirect(url_for("index"))
        return render_template_string(LOGIN_HTML)
    d = request.get_json(silent=True) or request.form
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if not u or not p: return jsonify(code=400, msg="请输入用户名和密码")
    time.sleep(0.2)
    row = db_one("SELECT * FROM users WHERE username=?", (u,))
    if not row or not verify_password(p, row["password"]):
        return jsonify(code=400, msg="用户名或密码错误")
    session.permanent = True
    session["user"] = u
    return jsonify(code=0)

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear(); return jsonify(code=0)

@app.route("/api/account", methods=["GET", "POST"])
@login_required
def api_account():
    if request.method == "GET":
        return jsonify(code=0, data={"username": session.get("user", "")})
    d = request.get_json() or {}
    old_p = d.get("old_password", "")
    new_p = d.get("new_password", "")
    new_u = (d.get("new_username") or "").strip()
    row = db_one("SELECT * FROM users WHERE username=?", (session["user"],))
    if not row: return jsonify(code=400, msg="用户不存在")
    if not verify_password(old_p, row["password"]):
        return jsonify(code=400, msg="当前密码错误")
    changed = []; need_relogin = False
    if new_u and new_u != session["user"]:
        if not re.match(r"^[\w\-\.]{2,32}$", new_u):
            return jsonify(code=400, msg="用户名需 2-32 位，允许字母数字 - _ .")
        if db_one("SELECT id FROM users WHERE username=?", (new_u,)):
            return jsonify(code=400, msg="用户名已存在")
        db_exec("UPDATE users SET username=? WHERE id=?", (new_u, row["id"]))
        session["user"] = new_u; changed.append("用户名")
    if new_p:
        if len(new_p) < 6: return jsonify(code=400, msg="新密码至少 6 位")
        db_exec("UPDATE users SET password=? WHERE id=?", (hash_password(new_p), row["id"]))
        changed.append("密码"); need_relogin = True
    if not changed: return jsonify(code=400, msg="没有修改任何内容")
    if need_relogin: session.clear()
    return jsonify(code=0, msg="已修改：" + "、".join(changed), need_relogin=need_relogin)


# ============================================================================
# 文件管理
# ============================================================================
@app.route("/")
@login_required
def index():
    return render_template_string(INDEX_HTML)

@app.route("/api/files")
@login_required
@api_guard
def api_files():
    rel = request.args.get("path", "")
    full = resolve(rel, must_exist=True)
    if not os.path.isdir(full): return jsonify(code=400, msg="不是目录")
    try: names = os.listdir(full)
    except PermissionError: return jsonify(code=403, msg="没有权限读取")
    notes = {r["path"]: r["note"] for r in db_all("SELECT path, note FROM file_notes")}
    entries = []
    for name in names:
        p = os.path.join(full, name)
        try: lst = os.lstat(p)
        except OSError: continue
        is_link = stat.S_ISLNK(lst.st_mode)
        try: st = os.stat(p) if is_link else lst
        except OSError: st = lst
        is_dir = stat.S_ISDIR(st.st_mode)
        rel_path = (rel.rstrip("/") + "/" + name).lstrip("/") if rel else name
        entries.append({
            "name": name, "path": rel_path,
            "dir": is_dir, "link": is_link,
            "size": 0 if is_dir else st.st_size,
            "mtime": st.st_mtime,
            "mode": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
            "uid": st.st_uid, "gid": st.st_gid,
            "owner": uid_name(st.st_uid), "group": gid_name(st.st_gid),
            "note": notes.get(rel_path, ""),
        })
    # 前端会再排序，后端默认按 (目录优先, 名称)
    entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    try:
        du = shutil.disk_usage(full)
        disk = {"total": du.total, "used": du.used, "free": du.free}
    except OSError: disk = None
    return jsonify(code=0, data={"path": rel.strip("/"), "entries": entries, "disk": disk})

@app.route("/api/files/mkdir", methods=["POST"])
@login_required
@api_guard
def api_mkdir():
    d = request.get_json() or {}
    parent = resolve(d.get("path", ""), must_exist=True)
    name = check_name(d.get("name"))
    target = os.path.join(parent, name)
    if os.path.exists(target): return jsonify(code=400, msg="已存在")
    os.makedirs(target, mode=0o755); return jsonify(code=0)

@app.route("/api/files/touch", methods=["POST"])
@login_required
@api_guard
def api_touch():
    d = request.get_json() or {}
    parent = resolve(d.get("path", ""), must_exist=True)
    name = check_name(d.get("name"))
    target = os.path.join(parent, name)
    if os.path.exists(target): return jsonify(code=400, msg="已存在")
    open(target, "w").close(); os.chmod(target, 0o644)
    return jsonify(code=0)

@app.route("/api/files/delete", methods=["POST"])
@login_required
@api_guard
def api_delete():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    if not paths: return jsonify(code=400, msg="未选择文件")
    errors = []
    for rel in paths:
        full = resolve(rel)
        if full == FILE_ROOT: errors.append("不能删根目录"); continue
        if not os.path.lexists(full): continue
        try:
            if os.path.isdir(full) and not os.path.islink(full): shutil.rmtree(full)
            else: os.remove(full)
            db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
        except OSError as e: errors.append(f"{os.path.basename(full)}: {e.strerror or e}")
    if errors: return jsonify(code=500, msg="部分失败：" + "; ".join(errors[:3]))
    return jsonify(code=0)

@app.route("/api/files/rename", methods=["POST"])
@login_required
@api_guard
def api_rename():
    d = request.get_json() or {}
    src = resolve(d.get("path", ""), must_exist=True)
    old_rel = d.get("path", "").strip("/")
    name = check_name(d.get("name"))
    dst = os.path.join(os.path.dirname(src), name)
    if os.path.lexists(dst) and os.path.realpath(dst) != os.path.realpath(src):
        return jsonify(code=400, msg="目标已存在")
    os.rename(src, dst)
    new_rel = os.path.join(os.path.dirname(old_rel), name).replace(os.sep, "/").lstrip("/")
    db_exec("UPDATE file_notes SET path=? WHERE path=?", (new_rel, old_rel))
    return jsonify(code=0)

@app.route("/api/files/copy", methods=["POST"])
@login_required
@api_guard
def api_copy():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    target_dir = resolve(d.get("target", ""), must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    errors, success = [], 0
    for rel in paths:
        src = resolve(rel, must_exist=True)
        name = os.path.basename(src)
        dst = os.path.join(target_dir, name)
        base, ext = os.path.splitext(name); i = 1
        while os.path.exists(dst):
            dst = os.path.join(target_dir, f"{base}_副本{i}{ext}"); i += 1
        try:
            if os.path.isdir(src) and not os.path.islink(src): shutil.copytree(src, dst)
            else: shutil.copy2(src, dst, follow_symlinks=False)
            success += 1
        except OSError as e: errors.append(f"{name}: {e.strerror or e}")
    if errors and not success: return jsonify(code=500, msg="复制失败：" + "; ".join(errors[:3]))
    return jsonify(code=0, msg=f"已复制 {success} 项")

@app.route("/api/files/move", methods=["POST"])
@login_required
@api_guard
def api_move():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    target_dir = resolve(d.get("target", ""), must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    errors, success = [], 0
    for rel in paths:
        src = resolve(rel, must_exist=True)
        name = os.path.basename(src)
        dst = os.path.join(target_dir, name)
        if os.path.realpath(src) == os.path.realpath(dst): continue
        if os.path.exists(dst):
            base, ext = os.path.splitext(name); i = 1
            while os.path.exists(dst):
                dst = os.path.join(target_dir, f"{base}_副本{i}{ext}"); i += 1
        try:
            shutil.move(src, dst); success += 1
            db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
        except OSError as e: errors.append(f"{name}: {e.strerror or e}")
    if errors and not success: return jsonify(code=500, msg="移动失败：" + "; ".join(errors[:3]))
    return jsonify(code=0, msg=f"已移动 {success} 项")

@app.route("/api/files/chmod", methods=["POST"])
@login_required
@api_guard
def api_chmod():
    d = request.get_json() or {}
    paths = d.get("paths") or ([d["path"]] if d.get("path") else [])
    mode_str = (d.get("mode") or "").strip()
    recursive = bool(d.get("recursive"))
    if not re.match(r"^[0-7]{3,4}$", mode_str):
        return jsonify(code=400, msg="权限必须是 3~4 位八进制")
    mode = int(mode_str, 8)
    for rel in paths:
        full = resolve(rel, must_exist=True)
        os.chmod(full, mode)
        if recursive and os.path.isdir(full) and not os.path.islink(full):
            for root, dirs, files in os.walk(full):
                for n in dirs + files:
                    try: os.chmod(os.path.join(root, n), mode)
                    except OSError: pass
    return jsonify(code=0)

@app.route("/api/files/chown", methods=["POST"])
@login_required
@api_guard
def api_chown():
    d = request.get_json() or {}
    paths = d.get("paths") or ([d["path"]] if d.get("path") else [])
    owner = (d.get("owner") or "").strip()
    group = (d.get("group") or "").strip()
    recursive = bool(d.get("recursive"))
    import pwd, grp
    uid = -1; gid = -1
    if owner:
        try: uid = pwd.getpwnam(owner).pw_uid
        except KeyError: return jsonify(code=400, msg=f"用户 {owner} 不存在")
    if group:
        try: gid = grp.getgrnam(group).gr_gid
        except KeyError: return jsonify(code=400, msg=f"组 {group} 不存在")
    for rel in paths:
        full = resolve(rel, must_exist=True)
        os.chown(full, uid, gid)
        if recursive and os.path.isdir(full) and not os.path.islink(full):
            for root, dirs, files in os.walk(full):
                for n in dirs + files:
                    try: os.chown(os.path.join(root, n), uid, gid)
                    except OSError: pass
    return jsonify(code=0)

@app.route("/api/files/stat")
@login_required
@api_guard
def api_stat():
    full = resolve(request.args.get("path", ""), must_exist=True)
    st = os.lstat(full)
    rel = request.args.get("path", "").strip("/")
    note = db_one("SELECT note FROM file_notes WHERE path=?", (rel,))
    return jsonify(code=0, data={
        "name": os.path.basename(full), "path": full, "rel": rel,
        "size": st.st_size, "is_dir": stat.S_ISDIR(st.st_mode),
        "is_link": stat.S_ISLNK(st.st_mode),
        "mode": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
        "uid": st.st_uid, "gid": st.st_gid,
        "owner": uid_name(st.st_uid), "group": gid_name(st.st_gid),
        "mtime": st.st_mtime, "atime": st.st_atime, "ctime": st.st_ctime,
        "note": note["note"] if note else "",
    })

@app.route("/api/files/hash")
@login_required
@api_guard
def api_hash():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if not os.path.isfile(full):
        return jsonify(code=400, msg="不是文件")
    algos = request.args.get("algos", "md5,sha1,sha256").split(",")
    algos = [a for a in algos if a in ("md5", "sha1", "sha256")]
    if not algos: algos = ["md5", "sha1", "sha256"]
    size = os.path.getsize(full)
    if size > 2 * 1024 * 1024 * 1024: algos = ["sha256"]
    hashers = {a: hashlib.new(a) for a in algos}
    try:
        with open(full, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                for h in hashers.values(): h.update(chunk)
    except OSError as e:
        return jsonify(code=500, msg=f"读取失败：{e.strerror or e}")
    result = {a: hashers[a].hexdigest() for a in algos}
    return jsonify(code=0, data={"hashes": result, "size": size})

@app.route("/api/files/note", methods=["POST"])
@login_required
def api_note():
    d = request.get_json() or {}
    rel = (d.get("path") or "").strip("/")
    note = (d.get("note") or "").strip()
    if not rel: return jsonify(code=400, msg="缺少路径")
    try: resolve(rel, must_exist=True)
    except PathError as e: return jsonify(code=400, msg=str(e))
    if note:
        now = datetime.now().isoformat(timespec="seconds")
        c = get_db()
        try:
            c.execute("""INSERT INTO file_notes(path, note, updated_at) VALUES(?,?,?)
                         ON CONFLICT(path) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at""",
                      (rel, note, now))
            c.commit()
        finally: c.close()
    else:
        db_exec("DELETE FROM file_notes WHERE path=?", (rel,))
    return jsonify(code=0, msg="已保存")

@app.route("/api/system/users_groups")
@login_required
def api_users_groups():
    import pwd, grp
    users, groups = [], []
    try:
        for p in pwd.getpwall(): users.append({"name": p.pw_name, "uid": p.pw_uid})
        users.sort(key=lambda x: x["uid"])
    except Exception: pass
    try:
        for g in grp.getgrall(): groups.append({"name": g.gr_name, "gid": g.gr_gid})
        groups.sort(key=lambda x: x["gid"])
    except Exception: pass
    return jsonify(code=0, data={"users": users, "groups": groups})

@app.route("/api/files/read")
@login_required
@api_guard
def api_read():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if not os.path.isfile(full): return jsonify(code=400, msg="不是文件")
    size = os.path.getsize(full)
    truncated = size > MAX_EDIT_SIZE
    try:
        with open(full, "r", encoding="utf-8") as f: content = f.read(MAX_EDIT_SIZE)
        enc = "utf-8"
    except UnicodeDecodeError:
        with open(full, "rb") as f: raw = f.read(MAX_EDIT_SIZE)
        content = raw.decode("latin-1"); enc = "latin-1"
    return jsonify(code=0, data={"content": content, "size": size, "encoding": enc, "truncated": truncated})

@app.route("/api/files/write", methods=["POST"])
@login_required
@api_guard
def api_write():
    d = request.get_json() or {}
    full = resolve(d.get("path", ""))
    with open(full, "w", encoding="utf-8") as f: f.write(d.get("content", ""))
    return jsonify(code=0)

CHUNK_SIZE = 4 * 1024 * 1024

@app.route("/api/files/upload_stream", methods=["POST"])
@login_required
def api_upload_stream():
    rel = request.args.get("path", "")
    name = request.args.get("name", "")
    try: parent = resolve(rel, must_exist=True)
    except PathError as e: return jsonify(code=400, msg=str(e))
    if not os.path.isdir(parent): return jsonify(code=400, msg="目标不是目录")
    try: name = check_name(name)
    except PathError as e: return jsonify(code=400, msg=str(e))
    target = os.path.join(parent, name)
    try: content_length = int(request.content_length or 0)
    except (TypeError, ValueError): content_length = 0
    try:
        du = shutil.disk_usage(parent); free = du.free
    except OSError: free = None
    if content_length and free is not None and content_length > free:
        return jsonify(code=507,
                       msg=f"磁盘空间不足：需要 {content_length//1024//1024} MB，"
                           f"剩余 {free//1024//1024} MB")
    written = 0
    try:
        with open(target, "wb") as f:
            stream = request.stream
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk: break
                f.write(chunk); written += len(chunk)
        try: os.chmod(target, 0o644)
        except OSError: pass
        return jsonify(code=0, msg=f"上传成功（{human_size(written)}）", size=written)
    except OSError as e:
        try:
            if os.path.exists(target): os.remove(target)
        except OSError: pass
        if e.errno == errno.ENOSPC:
            return jsonify(code=507, msg=f"磁盘空间不足，已上传 {human_size(written)} 后中断")
        if e.errno == errno.EACCES:
            return jsonify(code=403, msg="权限不足，无法写入目标目录")
        if e.errno == errno.EROFS:
            return jsonify(code=400, msg="目标目录所在的文件系统为只读")
        return jsonify(code=500, msg=f"写入失败：{e.strerror or e}")
    except Exception as e:
        try:
            if os.path.exists(target): os.remove(target)
        except OSError: pass
        return jsonify(code=500, msg=f"上传异常：{e}")

def human_size(n):
    if n is None: return "-"
    if n < 1024: return f"{n} B"
    units = ["KB", "MB", "GB", "TB", "PB"]; i = -1
    while n >= 1024 and i < len(units) - 1:
        n /= 1024; i += 1
    return f"{n:.2f} {units[i]}"

@app.route("/api/files/upload", methods=["POST"])
@login_required
def api_upload():
    try:
        rel = request.form.get("path", "")
        parent = resolve(rel, must_exist=True)
        if not os.path.isdir(parent): return jsonify(code=400, msg="目标不是目录")
        files = request.files.getlist("files")
        if not files: return jsonify(code=400, msg="没有文件")
        saved, failed = [], []
        for f in files:
            name = os.path.basename(f.filename or "").strip()
            if not name: continue
            try: check_name(name)
            except PathError: failed.append(f"{name}: 非法名"); continue
            try:
                f.save(os.path.join(parent, name)); saved.append(name)
            except OSError as e:
                if e.errno == errno.ENOSPC: failed.append(f"{name}: 磁盘空间不足")
                else: failed.append(f"{name}: {e.strerror or e}")
        if failed and not saved: return jsonify(code=500, msg="全部失败：" + "; ".join(failed[:3]))
        msg = f"成功 {len(saved)}"
        if failed: msg += f"，失败 {len(failed)}：" + "; ".join(failed[:3])
        return jsonify(code=0 if not failed else 200, msg=msg)
    except PathError as e: return jsonify(code=400, msg=str(e))
    except OSError as e:
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足")
        return jsonify(code=500, msg=str(e))

@app.route("/api/files/download")
@login_required
@api_guard
def api_download():
    full = resolve(request.args.get("path", ""), must_exist=True)
    if os.path.isdir(full):
        buf = io.BytesIO()
        base = os.path.basename(full.rstrip("/")) or "root"
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try: zf.write(fp, os.path.relpath(fp, os.path.dirname(full)))
                    except OSError: pass
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"{base}.zip")
    return send_file(full, as_attachment=True, download_name=os.path.basename(full))

@app.route("/api/files/compress", methods=["POST"])
@login_required
@api_guard
def api_compress():
    d = request.get_json() or {}
    paths = d.get("paths") or []
    fmt = (d.get("format") or "zip").lower()
    archive_name = (d.get("archive_name") or "").strip()
    target_rel = d.get("target", "")
    if not paths: return jsonify(code=400, msg="未选择文件")
    target_dir = resolve(target_rel, must_exist=True)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    if fmt == "zip": ext = ".zip"
    elif fmt in ("tar.gz", "tgz"): fmt = "tar.gz"; ext = ".tar.gz"
    elif fmt in ("tar.bz2", "tbz2"): fmt = "tar.bz2"; ext = ".tar.bz2"
    elif fmt == "tar": ext = ".tar"
    else: return jsonify(code=400, msg="不支持的压缩格式")
    if not archive_name:
        base = os.path.basename(paths[0].rstrip("/")) or "archive"
        archive_name = base + ext
    else:
        if not archive_name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
            archive_name += ext
        try: check_name(archive_name)
        except PathError as e: return jsonify(code=400, msg=str(e))
    archive_path = os.path.join(target_dir, archive_name)
    if os.path.lexists(archive_path):
        return jsonify(code=400, msg=f"压缩包 {archive_name} 已存在")
    try:
        if fmt == "zip":
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for rel in paths:
                    full = resolve(rel, must_exist=True)
                    if os.path.isdir(full) and not os.path.islink(full):
                        parent = os.path.dirname(full)
                        for root, dirs, files in os.walk(full):
                            arc_dir = os.path.relpath(root, parent)
                            if arc_dir and arc_dir != ".":
                                try: zf.write(root, arc_dir)
                                except OSError: pass
                            for fn in files:
                                fp = os.path.join(root, fn)
                                try: zf.write(fp, os.path.relpath(fp, parent))
                                except OSError: pass
                    else:
                        zf.write(full, os.path.basename(full))
        else:
            mode = "w:gz" if fmt == "tar.gz" else ("w:bz2" if fmt == "tar.bz2" else "w")
            with tarfile.open(archive_path, mode) as tf:
                for rel in paths:
                    full = resolve(rel, must_exist=True)
                    tf.add(full, arcname=os.path.basename(full))
    except OSError as e:
        try:
            if os.path.exists(archive_path): os.remove(archive_path)
        except OSError: pass
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足，压缩中断")
        return jsonify(code=500, msg=f"压缩失败：{e.strerror or e}")
    except Exception as e:
        try:
            if os.path.exists(archive_path): os.remove(archive_path)
        except OSError: pass
        return jsonify(code=500, msg=f"压缩失败：{e}")
    try: size = os.path.getsize(archive_path)
    except OSError: size = 0
    return jsonify(code=0, msg=f"已生成 {archive_name}（{human_size(size)}）", name=archive_name)

@app.route("/api/files/extract", methods=["POST"])
@login_required
@api_guard
def api_extract():
    d = request.get_json() or {}
    path = d.get("path", "")
    target_rel = d.get("target", "")
    full = resolve(path, must_exist=True)
    if not os.path.isfile(full): return jsonify(code=400, msg="不是文件")
    if target_rel: target_dir = resolve(target_rel, must_exist=True)
    else: target_dir = os.path.dirname(full)
    if not os.path.isdir(target_dir): return jsonify(code=400, msg="目标不是目录")
    name = os.path.basename(full).lower()
    real_target = os.path.realpath(target_dir)
    def safe_join(member_name):
        target_path = os.path.realpath(os.path.join(real_target, member_name))
        if target_path != real_target and not target_path.startswith(real_target + os.sep):
            return None
        return target_path
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(full, "r") as zf:
                for member in zf.namelist():
                    if safe_join(member) is None:
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member}")
                zf.extractall(real_target)
        elif name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
            with tarfile.open(full, "r:*") as tf:
                for member in tf.getmembers():
                    if safe_join(member.name) is None:
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member.name}")
                    if os.path.isabs(member.name) or ".." in member.name.split("/"):
                        return jsonify(code=400, msg=f"压缩包含有非法路径：{member.name}")
                tf.extractall(real_target)
        else:
            return jsonify(code=400, msg="不支持的压缩格式（支持 .zip / .tar / .tar.gz / .tar.bz2 / .tar.xz）")
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        return jsonify(code=500, msg=f"解压失败：{e}")
    except OSError as e:
        if e.errno == errno.ENOSPC: return jsonify(code=507, msg="磁盘空间不足，解压中断")
        return jsonify(code=500, msg=f"解压失败：{e.strerror or e}")
    except Exception as e:
        return jsonify(code=500, msg=f"解压失败：{e}")
    return jsonify(code=0, msg="解压完成")


# ============================================================================
# SSH 服务 / 密钥
# ============================================================================
@app.route("/api/ssh/service", methods=["GET"])
@login_required
def api_ssh_service():
    return jsonify(code=0, data={
        "config": read_sshd_config(),
        "status": ssh_service_status(),
        "stats": ssh_login_stats(),
        "authorized_keys": read_authorized_keys(),
    })

@app.route("/api/ssh/service", methods=["POST"])
@login_required
def api_ssh_service_save():
    d = request.get_json() or {}
    try:
        update_sshd_config(
            port=str(d.get("port", "22")),
            password_auth=d.get("password_auth", "yes"),
            pubkey_auth=d.get("pubkey_auth", "yes"),
            root_login=d.get("root_login"))
        restart_ssh()
        return jsonify(code=0, msg="配置已保存并重启 SSH 服务")
    except Exception as e:
        return jsonify(code=500, msg=str(e))

@app.route("/api/ssh/authorized_keys/add", methods=["POST"])
@login_required
def api_authorized_add():
    d = request.get_json() or {}
    pub = (d.get("public_key") or "").strip()
    try:
        added = add_authorized_key(pub)
        return jsonify(code=0, msg="已添加" if added else "该密钥已存在")
    except Exception as e:
        return jsonify(code=500, msg=str(e))

@app.route("/api/ssh/authorized_keys/remove", methods=["POST"])
@login_required
def api_authorized_remove():
    d = request.get_json() or {}
    idx = int(d.get("index", -1))
    ok = remove_authorized_key(idx)
    return jsonify(code=0 if ok else 500, msg="已删除" if ok else "删除失败")

@app.route("/api/ssh/keys", methods=["GET"])
@login_required
def api_keys_list():
    rows = db_all("""SELECT id, name, key_type, bits, public_key,
                            fingerprint, comment, created_at
                     FROM ssh_keys ORDER BY id DESC""")
    return jsonify(code=0, data=rows)

@app.route("/api/ssh/keys/generate", methods=["POST"])
@login_required
def api_keys_gen():
    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    kt = (d.get("key_type") or "ed25519").lower()
    bits = int(d.get("bits") or 0)
    comment = (d.get("comment") or "").strip()
    pp = d.get("passphrase") or ""
    if not name: return jsonify(code=400, msg="请填写名称")
    if kt == "ed25519": bits = 0
    elif kt == "rsa" and bits not in (2048, 3072, 4096): bits = 4096
    elif kt == "ecdsa" and bits not in (256, 384, 521): bits = 256
    try:
        priv, pub = generate_ssh_key(kt, bits, comment, pp)
    except Exception as e:
        return jsonify(code=500, msg=str(e))
    fp = fingerprint_from_pubkey(pub)
    db_exec("""INSERT INTO ssh_keys
               (name, key_type, bits, private_key_enc, public_key,
                fingerprint, comment, passphrase_enc, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (name, kt, bits or None, fernet.encrypt(priv.encode()), pub, fp,
             comment, fernet.encrypt(pp.encode()) if pp else None,
             datetime.now().isoformat(timespec="seconds")))
    return jsonify(code=0, msg="密钥已生成")

@app.route("/api/ssh/keys/import", methods=["POST"])
@login_required
def api_keys_import():
    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    priv = (d.get("private_key") or "").strip()
    pp = d.get("passphrase") or ""
    if not name: return jsonify(code=400, msg="请填写名称")
    if not priv: return jsonify(code=400, msg="请粘贴私钥")
    try:
        pkey = load_private_key(priv, pp); pub = pub_from_priv(pkey)
    except Exception as e:
        return jsonify(code=400, msg=f"私钥无效：{e}")
    fp = fingerprint_from_pubkey(pub)
    kt = key_type_of(pkey)
    bits = getattr(pkey, "key_size", 0) or 0
    db_exec("""INSERT INTO ssh_keys
               (name, key_type, bits, private_key_enc, public_key,
                fingerprint, comment, passphrase_enc, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (name, kt, bits or None, fernet.encrypt(priv.encode()), pub, fp,
             "imported", fernet.encrypt(pp.encode()) if pp else None,
             datetime.now().isoformat(timespec="seconds")))
    return jsonify(code=0, msg="已导入")

@app.route("/api/ssh/keys/<int:kid>", methods=["DELETE"])
@login_required
def api_keys_del(kid):
    if not db_one("SELECT id FROM ssh_keys WHERE id=?", (kid,)):
        return jsonify(code=404, msg="密钥不存在")
    db_exec("DELETE FROM ssh_keys WHERE id=?", (kid,))
    return jsonify(code=0)

@app.route("/api/ssh/keys/<int:kid>/private")
@login_required
def api_keys_download(kid):
    row = db_one("SELECT * FROM ssh_keys WHERE id=?", (kid,))
    if not row: return jsonify(code=404, msg="不存在"), 404
    try: priv = fernet.decrypt(row["private_key_enc"]).decode()
    except Exception as e: return jsonify(code=500, msg=f"解密失败：{e}"), 500
    buf = io.BytesIO(priv.encode())
    fname = re.sub(r"[^\w\-.]", "_", row["name"]) or f"key_{kid}"
    return send_file(buf, mimetype="application/x-pem-file",
                     as_attachment=True, download_name=f"{fname}.pem")

@app.route("/api/ssh/keys/<int:kid>/authorize", methods=["POST"])
@login_required
def api_keys_authorize(kid):
    row = db_one("SELECT * FROM ssh_keys WHERE id=?", (kid,))
    if not row: return jsonify(code=404, msg="密钥不存在")
    try:
        added = add_authorized_key(row["public_key"])
        return jsonify(code=0, msg="已添加到本机" if added else "该密钥已在 authorized_keys")
    except Exception as e:
        return jsonify(code=500, msg=str(e))


# ============================================================================
# 防火墙
# ============================================================================
@app.route("/api/firewall", methods=["GET"])
@login_required
def api_fw_status():
    if not ufw_available():
        return jsonify(code=0, data={"backend": "none", "backend_label": "未检测到 ufw",
                                     "active": False, "rules": [],
                                     "hint": "请执行：sudo apt install -y ufw"})
    st = ufw_status()
    return jsonify(code=0, data={
        "backend": "ufw", "backend_label": "UFW (Uncomplicated Firewall)",
        "active": st.get("active", False), "rules": st.get("rules", []),
        "hint": "" if st.get("active") else "防火墙未启用。放行规则已保存，但需启用后才会生效。"})

@app.route("/api/firewall/switch", methods=["POST"])
@login_required
def api_fw_switch():
    if not ufw_available(): return jsonify(code=500, msg="未安装 ufw")
    d = request.get_json() or {}
    ok, msg = ufw_switch(bool(d.get("enable")))
    if ok: return jsonify(code=0, msg="已开启" if d.get("enable") else "已关闭")
    return jsonify(code=500, msg=msg)

@app.route("/api/firewall/add", methods=["POST"])
@login_required
def api_fw_add():
    if not ufw_available(): return jsonify(code=500, msg="未安装 ufw")
    d = request.get_json() or {}
    try: ok, msg = ufw_add(d.get("port", ""), d.get("proto", "tcp"), d.get("source", ""))
    except PathError as e: return jsonify(code=400, msg=str(e))
    if not ok: return jsonify(code=500, msg=msg)
    return jsonify(code=0, msg=msg or "放行成功")

@app.route("/api/firewall/delete", methods=["POST"])
@login_required
def api_fw_del():
    if not ufw_available(): return jsonify(code=500, msg="未安装 ufw")
    d = request.get_json() or {}
    nums = d.get("nums")
    if nums: ok, msg = ufw_delete_nums(nums)
    else:
        port = str(d.get("port", "")); proto = (d.get("proto") or "any").lower()
        source = d.get("source", "")
        st = ufw_status(); nums_to_del = []
        for r in st.get("rules", []):
            if r["port"] != port: continue
            if source and r["source"] != source: continue
            if proto == "any": nums_to_del.extend(r["nums"])
            elif r["proto"] == proto or r["proto"] == "any": nums_to_del.extend(r["nums"])
        if not nums_to_del: return jsonify(code=500, msg="未找到匹配规则")
        ok, msg = ufw_delete_nums(nums_to_del)
    return jsonify(code=0 if ok else 500, msg=("已删除" if ok else msg))


# ============================================================================
# Web 终端
# ============================================================================
local_terms = {}; local_lock = threading.Lock()

def _close_local(sid):
    with local_lock: s = local_terms.pop(sid, None)
    if not s: return
    s["alive"] = False
    try: os.kill(s["pid"], signal.SIGTERM)
    except Exception: pass
    try: os.close(s["fd"])
    except Exception: pass

@socketio.on("local_open")
def on_local_open(data):
    sid = request.sid
    if not session.get("user"):
        emit("local_error", {"msg": "未登录"}); return
    _close_local(sid)
    cols = int(data.get("cols", 120)); rows = int(data.get("rows", 30))
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.environ["TERM"] = "xterm-256color"
            os.environ["LANG"] = "C.UTF-8"; os.environ["LC_ALL"] = "C.UTF-8"
            home = os.environ.get("HOME", "/root")
            os.chdir(home if os.path.isdir(home) else "/")
            os.execv("/bin/bash", ["/bin/bash", "-l"])
        except Exception: os._exit(1)
    try: fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception: pass
    with local_lock: local_terms[sid] = {"pid": pid, "fd": fd, "alive": True}
    emit("local_connected", {"cols": cols, "rows": rows})
    def reader():
        s = local_terms.get(sid)
        if not s: return
        fd = s["fd"]
        while s.get("alive"):
            try:
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    chunk = os.read(fd, 65536)
                    if not chunk: break
                    socketio.emit("local_output", {"d": base64.b64encode(chunk).decode()}, to=sid)
            except OSError: break
        socketio.emit("local_close", {}, to=sid); _close_local(sid)
    socketio.start_background_task(reader)

@socketio.on("local_input")
def on_local_input(data):
    s = local_terms.get(request.sid)
    if not s or not s.get("alive"): return
    try: os.write(s["fd"], data.get("d", "").encode("utf-8", "ignore"))
    except OSError: pass

@socketio.on("local_resize")
def on_local_resize(data):
    s = local_terms.get(request.sid)
    if not s or not s.get("alive"): return
    try:
        cols = max(20, int(data.get("cols", 80))); rows = max(5, int(data.get("rows", 24)))
        fcntl.ioctl(s["fd"], termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception: pass

@socketio.on("disconnect")
def on_disconnect():
    _close_local(request.sid)


# ============================================================================
# HTML - 登录页
# ============================================================================
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录面板</title>
<script>
try {
  const t = localStorage.getItem('panel-theme') || 'dark';
  if (t === 'light') document.documentElement.classList.add('light');
} catch(e){}
</script>
<style>
:root{--bg:#0e1116;--panel:#151a21;--border:#262e3a;--text:#e6eaf2;
  --muted:#8b95a7;--accent:#3b82f6;--accent-h:#2f6fdd;--danger:#ef4444;
  --glow:rgba(59,130,246,.35);--shadow:rgba(0,0,0,.55)}
html.light{
  --bg:#f5efe0;--panel:#fbf7ec;--border:#d5c8a9;--text:#3a3225;
  --muted:#8a7e68;--accent:#2563eb;--accent-h:#1d4ed8;--danger:#dc2626;
  --glow:rgba(37,99,235,.2);--shadow:rgba(90,80,50,.15)}
*{box-sizing:border-box}
svg{fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);
  font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
  font-size:14px;display:flex;align-items:center;justify-content:center;
  transition:background .35s,color .35s}
body::before{
  content:"";position:fixed;inset:0;z-index:-1;
  background:radial-gradient(circle at 30% 20%,#16202e 0%,#0b0e13 60%);
  transition:opacity .35s}
html.light body::before{
  background:radial-gradient(circle at 30% 20%,#fdfaef 0%,#f5efe0 60%)}
.box{width:360px;padding:36px 32px;background:var(--panel);border:1px solid var(--border);
  border-radius:14px;box-shadow:0 20px 60px var(--shadow);text-align:center;
  animation:boxIn .4s ease-out}
@keyframes boxIn{from{opacity:0;transform:translateY(20px) scale(.96)}to{opacity:1;transform:none}}
.logo{font-size:44px;line-height:1;margin-bottom:8px}
.logo svg{width:44px;height:44px;color:var(--accent)}
h1{margin:0 0 4px;font-size:20px;font-weight:600}
.sub{margin:0 0 26px;color:var(--muted);font-size:12px}
label{display:block;text-align:left;margin-bottom:14px}
label span{display:block;margin-bottom:6px;font-size:12px;color:var(--muted)}
input{width:100%;padding:9px 11px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-size:13px;outline:none;font-family:inherit;
  transition:border-color .15s,box-shadow .15s,background .35s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
button{width:100%;padding:10px;background:var(--accent);color:#fff;border:none;border-radius:6px;
  font-size:14px;cursor:pointer;margin-top:4px;font-family:inherit;
  transition:background .15s,transform .1s,box-shadow .15s}
button:hover:not(:disabled){background:var(--accent-h);box-shadow:0 4px 12px var(--glow)}
button:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{min-height:18px;margin-top:14px;font-size:12px;color:var(--muted)}
.msg.err{color:var(--danger)}
</style>
</head>
<body>
<form class="box" id="f">
  <div class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/></svg></div>
  <h1>linux工具面板</h1>
  <p class="sub">文件管理 · SSH 管理 · Web 终端 · 防火墙</p>
  <label><span>用户名</span><input id="u" autocomplete="username" required autofocus></label>
  <label><span>密码</span><input id="p" type="password" autocomplete="current-password" required></label>
  <button type="submit">登 录</button>
  <div class="msg" id="m"></div>
</form>
<script>
const f=document.getElementById('f'),m=document.getElementById('m');
f.addEventListener('submit',async e=>{
  e.preventDefault();m.className='msg';m.textContent='';
  const btn=f.querySelector('button');btn.disabled=true;btn.textContent='登录中…';
  try{
    const r=await fetch('/login',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.value,password:p.value})});
    const d=await r.json();
    if(d.code===0)location.href='/';
    else{m.className='msg err';m.textContent=d.msg||'登录失败';}
  }catch(err){m.className='msg err';m.textContent='网络错误: '+err.message;}
  finally{btn.disabled=false;btn.textContent='登 录';}
});
</script>
</body>
</html>"""


# ============================================================================
# HTML - 主界面
# ============================================================================
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>linux工具面板</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
<script>
try {
  const t = localStorage.getItem('panel-theme') || 'dark';
  if (t === 'light') document.documentElement.classList.add('light');
} catch(e){}
</script>
<style>
:root{
  --bg:#0e1116; --panel:#151a21; --panel-2:#1b2129; --panel-3:#222933;
  --border:#262e3a; --border-2:#1c222b; --text:#e6eaf2; --muted:#8b95a7;
  --accent:#3b82f6; --accent-h:#2f6fdd;
  --danger:#ef4444; --danger-h:#d63c3c;
  --ok:#22c55e; --warn:#f59e0b;
  --glow:rgba(59,130,246,.35);
  --row-hover:#1b2129; --row-selected:#1b2a3d;
  --shadow:rgba(0,0,0,.45);
  --radius:8px;
}
html.light{
  --bg:#f5efe0; --panel:#fbf7ec; --panel-2:#f0e8d4; --panel-3:#e8ddc4;
  --border:#d5c8a9; --border-2:#ebe1cb; --text:#3a3225; --muted:#8a7e68;
  --accent:#2563eb; --accent-h:#1d4ed8;
  --danger:#dc2626; --danger-h:#b91c1c;
  --ok:#16a34a; --warn:#d97706;
  --glow:rgba(37,99,235,.2);
  --row-hover:#f5ecd7; --row-selected:#dbeafe;
  --shadow:rgba(90,80,50,.15);
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);
  font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-size:14px;-webkit-font-smoothing:antialiased;overflow:hidden;
  transition:background .35s,color .35s}
svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.8;
  stroke-linecap:round;stroke-linejoin:round}
button{font-family:inherit}
input[type=number]::-webkit-outer-spin-button,
input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
input[type=number]{-moz-appearance:textfield;appearance:textfield}

.app{display:flex;height:100vh;overflow:hidden}
.sidebar{width:216px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--border);
  display:flex;flex-direction:column;transition:background .35s,border-color .35s}
.brand{display:flex;align-items:center;gap:10px;padding:18px 18px 16px;font-weight:600;font-size:15px;
  border-bottom:1px solid var(--border)}
.brand .logo{font-size:20px;display:flex;align-items:center;justify-content:center}
.brand .logo svg{width:22px;height:22px;color:var(--accent)}
.nav{flex:1;padding:12px 10px;display:flex;flex-direction:column;gap:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--radius);
  color:var(--muted);cursor:pointer;user-select:none;
  transition:background .2s,color .2s,transform .1s}
.nav-item:hover{background:var(--panel-2);color:var(--text);transform:translateX(2px)}
.nav-item:active{transform:translateX(0) scale(.98)}
.nav-item.active{background:var(--accent);color:#fff;box-shadow:0 4px 12px var(--glow)}
.sidebar-foot{padding:12px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px}
.user{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;cursor:pointer;
  background:var(--panel-2);transition:background .15s,transform .1s;user-select:none}
.user:hover{background:var(--panel-3);transform:translateY(-1px)}
.user:active{transform:translateY(0)}
.avatar{width:32px;height:32px;border-radius:50%;background:var(--accent);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;
  box-shadow:0 2px 8px var(--glow)}
.uname{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-weight:500;color:var(--text)}
.theme-toggle{display:flex;align-items:center;justify-content:center;gap:8px;padding:8px 12px;
  background:var(--panel-2);border:1px solid var(--border);border-radius:8px;
  cursor:pointer;user-select:none;transition:background .2s,border-color .2s,transform .1s}
.theme-toggle:hover{background:var(--panel-3);transform:translateY(-1px)}
.theme-toggle:active{transform:translateY(0)}
.theme-toggle svg{width:14px;height:14px;transition:transform .35s}
.theme-toggle .lbl{font-size:12px;color:var(--muted);transition:color .2s}
.theme-toggle .sun{color:var(--warn)}
.theme-toggle .moon{color:#7c8ef5}
.theme-toggle:hover .lbl{color:var(--text)}

.main{flex:1;min-width:0;display:flex;flex-direction:column;overflow:hidden;position:relative}
.view{display:none;flex-direction:column;height:100%;min-height:0;padding:14px}
.view.active{display:flex;animation:viewIn .35s cubic-bezier(.2,.8,.3,1)}
@keyframes viewIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:7px 13px;
  background:var(--panel-3);color:var(--text);border:1px solid var(--border);border-radius:6px;
  font-size:13px;cursor:pointer;white-space:nowrap;
  transition:background .15s,border-color .15s,opacity .15s,transform .1s,box-shadow .15s}
.btn:hover:not(:disabled){background:var(--panel-2);transform:translateY(-1px);
  box-shadow:0 2px 8px var(--shadow)}
.btn:active:not(:disabled){transform:translateY(0)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover:not(:disabled){background:var(--accent-h);box-shadow:0 4px 12px var(--glow)}
.btn.danger{background:transparent;border-color:rgba(239,68,68,.35);color:var(--danger)}
.btn.danger:hover:not(:disabled){background:rgba(239,68,68,.1)}
.btn.ok{background:transparent;border-color:rgba(34,197,94,.35);color:var(--ok)}
.btn.ok:hover:not(:disabled){background:rgba(34,197,94,.1)}
.btn.tiny{padding:4px 9px;font-size:12px}

input[type=text],input[type=password],input[type=number],select,textarea{
  padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;
  color:var(--text);font-size:13px;font-family:inherit;outline:none;
  transition:border-color .15s,box-shadow .15s,background .35s;width:100%}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
input::placeholder,textarea::placeholder{color:var(--muted);opacity:.7}
select{cursor:pointer}
.spacer{flex:1}
.hint{font-size:12px;color:var(--muted);margin:6px 0 0}

.toolbar{display:flex;align-items:center;gap:8px;padding-bottom:12px;flex-wrap:wrap}
.disk-info{font-size:12px;color:var(--muted);margin-right:10px}
.disk-info b{color:var(--ok)}

/* 面包屑 + 搜索框同一行；路径始终单行显示 */
.browser-bar{display:flex;gap:8px;align-items:center;margin-bottom:10px;min-width:0}
.browser-bar .breadcrumb{flex:1 1 0;min-width:0;margin-bottom:0}
.breadcrumb{display:flex;align-items:center;flex-wrap:nowrap;gap:2px;padding:6px 10px;
  min-width:0;overflow:hidden;white-space:nowrap;
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);font-size:13px;cursor:text;min-height:38px;
  transition:border-color .15s,background .35s}
.breadcrumb:hover{border-color:var(--muted)}
.breadcrumb .bc-part{display:inline-block;flex:0 0 auto;max-width:160px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;vertical-align:middle;cursor:pointer;
  padding:4px 8px;border-radius:4px;color:var(--text);text-decoration:none;
  transition:background .15s,color .15s}
.breadcrumb .bc-root{max-width:none}
.breadcrumb .bc-part:hover{background:var(--panel-3);color:var(--accent)}
.breadcrumb .bc-node{display:inline-flex;align-items:center;flex:0 0 auto;gap:2px}
.breadcrumb .sep{flex:0 0 auto;color:var(--muted);padding:0 1px;user-select:none}
.breadcrumb .bc-ellipsis-node{display:none}
.breadcrumb .bc-ellipsis{min-width:24px;text-align:center;cursor:pointer;color:var(--muted)}
.breadcrumb .bc-ellipsis:hover{color:var(--accent)}
.breadcrumb .bc-fill{flex:1 1 auto;min-width:0;min-height:24px}
.breadcrumb .bc-input{flex:1 1 0;padding:2px 8px;background:transparent;border:none;
  color:var(--text);font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;
  outline:none;box-shadow:none;width:100%;min-width:0}
/* 使用更高优先级，避免全局 input[type=text] 的 width:100% 撑满整行 */
.browser-bar input.search-box{width:240px;min-width:240px;max-width:240px;flex:0 0 240px;
  padding:9px 12px 9px 34px;background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%238b95a7' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='11' cy='11' r='8'/><path d='m21 21-4.35-4.35'/></svg>");
  background-repeat:no-repeat;background-position:10px center;
  transition:border-color .15s,box-shadow .15s,background-color .35s}
.browser-bar input.search-box:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}

/* 表格 */
.table-wrap{flex:1;min-height:0;overflow:auto;background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);position:relative;transition:background .2s,border-color .2s,box-shadow .2s}
#file-table-wrap.drag-over{border-color:var(--accent);box-shadow:inset 0 0 0 2px var(--accent)}
#file-table-wrap.drag-over::after{content:"释放以上传文件或文件夹\A";position:absolute;inset:0;z-index:10;display:flex;align-items:center;justify-content:center;
  background:rgba(59,130,246,.12);border:2px dashed var(--accent);border-radius:var(--radius);
  color:var(--accent);font-size:16px;font-weight:600;text-align:center;white-space:pre;line-height:2;pointer-events:none;backdrop-filter:blur(1px)}
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table thead th{position:sticky;top:0;z-index:2;background:var(--panel-2);
  font-weight:500;color:var(--muted);padding:10px 12px;border-bottom:1px solid var(--border);
  white-space:nowrap;transition:background .2s,color .2s;text-align:center}
.data-table thead th:nth-child(2){text-align:left}
.data-table thead th.sortable{cursor:pointer;user-select:none}
.data-table thead th.sortable:hover{background:var(--panel-3);color:var(--text)}
.data-table thead th .sort-arrow{display:inline-block;margin-left:6px;
  font-size:9px;line-height:1;opacity:.35;
  transition:opacity .15s,color .15s,transform .2s}
.data-table thead th.sorted .sort-arrow{opacity:1;color:var(--accent)}
.data-table tbody td{padding:8px 12px;border-bottom:1px solid var(--border-2);vertical-align:middle;
  transition:background .15s,color .35s;text-align:center}
.data-table tbody td:nth-child(2){text-align:left}
.data-table tbody tr:last-child td{border-bottom:none}
.data-table tbody tr:hover{background:var(--row-hover)}
.data-table tbody tr.selected{background:var(--row-selected)}
.data-table tbody tr{cursor:default}
.w-check{width:40px}.w-size{width:90px}.w-mode{width:80px}.w-owner{width:130px}
.w-time{width:160px}.w-port{width:70px}.w-note{width:180px}
.name-cell{display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.name-cell .icon{width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--muted)}
.name-cell .icon .ui-icon{width:17px;height:17px}
.name-cell .icon .icon-folder{color:var(--accent)}
.name-cell .icon .icon-archive{color:#d6a24b}
.name-cell .icon .icon-image{color:#8b9cf5}
.name-cell .icon .icon-film{color:#cf8be8}
.name-cell .icon .icon-music{color:#e58bb5}
.name-cell .icon .icon-file-code{color:#56b6c2}
.name-cell .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.name-cell .link-mark{color:var(--warn);font-size:11px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#5b9bff}
html.light code{color:#1d4ed8}
.empty{padding:40px;text-align:center;color:var(--muted);font-size:13px}
input[type=checkbox]{width:15px;height:15px;accent-color:var(--accent);cursor:pointer;margin:0}

.note-cell{display:inline-block;padding:3px 8px;border-radius:4px;cursor:text;
  min-width:70px;min-height:20px;line-height:1.4;font-size:12px;color:var(--text);
  transition:background .15s;text-align:center;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;max-width:160px}
.note-cell:hover{background:var(--panel-3)}
.note-cell input{width:100%;padding:3px 6px;font-size:12px;min-width:140px}

.ctx-menu{position:fixed;z-index:150;background:var(--panel);border:1px solid var(--border);
  border-radius:8px;box-shadow:0 12px 40px var(--shadow);padding:6px;min-width:200px;
  font-size:13px;display:none;transition:background .35s,border-color .35s}
.ctx-menu.show{display:block;animation:ctxIn .12s ease-out}
@keyframes ctxIn{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}
.ctx-menu .item{padding:7px 12px;border-radius:4px;cursor:pointer;display:flex;align-items:center;
  gap:10px;color:var(--text);user-select:none;transition:background .1s}
.ctx-menu .item:hover{background:var(--accent);color:#fff}
.ctx-menu .sep{height:1px;background:var(--border);margin:4px 0}
.ctx-menu .ico{width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center;opacity:.85;flex-shrink:0}
.ctx-menu .ico svg{width:16px;height:16px}
.confirm-icon{display:flex;align-items:center;justify-content:center;width:28px;height:28px;color:var(--warn);flex-shrink:0}
.confirm-icon svg{width:26px;height:26px}

.subtabs{display:flex;gap:4px;margin-bottom:12px;border-bottom:1px solid var(--border)}
.subtab{padding:9px 18px;background:transparent;border:none;border-bottom:2px solid transparent;
  color:var(--muted);cursor:pointer;font-size:13px;transition:color .2s,border-color .2s}
.subtab:hover{color:var(--text)}
.subtab.active{color:var(--accent);border-bottom-color:var(--accent)}
.subpanel{display:none;flex-direction:column;flex:1;min-height:0;overflow-y:auto}
.subpanel.active{display:flex;animation:viewIn .3s ease-out}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;margin-bottom:14px;transition:background .35s,border-color .35s}
.card h3{margin:0 0 14px;font-size:14px;font-weight:600;display:flex;align-items:center;gap:8px}
.card h3 .badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:400}
.badge.on{background:rgba(34,197,94,.15);color:var(--ok);border:1px solid rgba(34,197,94,.35)}
.badge.off{background:rgba(239,68,68,.15);color:var(--danger);border:1px solid rgba(239,68,68,.35)}
.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.form-grid.one{grid-template-columns:1fr}
.form-item{display:flex;flex-direction:column;gap:6px}
.form-item > label{font-size:12px;color:var(--muted)}
.root-row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
.root-row .form-item{flex:1;min-width:280px}
.root-row .btn{flex-shrink:0;height:36px;padding:0 20px}
.switch-row{display:flex;align-items:center;gap:10px;padding:10px 0}
.switch-row .label{font-size:13px}
.switch-row .desc{font-size:12px;color:var(--muted);margin-left:auto}
.switch{position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;
  background:var(--panel-3);border-radius:24px;transition:.3s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;
  background:#fff;border-radius:50%;transition:.3s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.switch input:checked + .slider{background:var(--accent)}
.switch input:checked + .slider:before{transform:translateX(20px)}
.stats-box{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.stat{padding:14px 16px;background:var(--panel-2);border:1px solid var(--border);border-radius:8px;
  transition:transform .2s,box-shadow .2s,background .35s}
.stat:hover{transform:translateY(-2px);box-shadow:0 4px 16px var(--shadow)}
.stat .num{font-size:22px;font-weight:600;margin-bottom:4px}
.stat .num.ok{color:var(--ok)}
.stat .num.err{color:var(--danger)}
.stat .lbl{font-size:12px;color:var(--muted)}
.ak-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.ak-item{padding:10px 12px;background:var(--panel-2);border:1px solid var(--border);
  border-radius:6px;display:flex;align-items:center;gap:10px;font-size:12px;
  transition:background .35s,border-color .35s}
.ak-item .fp{font-family:ui-monospace,monospace;color:#5b9bff;flex:1;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
html.light .ak-item .fp{color:#1d4ed8}
.ak-item .cmt{color:var(--muted);font-size:11px}

.term-head{display:flex;align-items:center;gap:10px;padding:8px 14px;margin-bottom:8px;
  background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;
  transition:background .35s,border-color .35s}
.term-dot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex-shrink:0;
  transition:background .3s,box-shadow .3s}
.term-dot.on{background:var(--ok);box-shadow:0 0 8px var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 8px var(--ok)}50%{box-shadow:0 0 16px var(--ok)}}
.term-dot.err{background:var(--danger)}
.term-hint{font-size:12px;color:var(--muted)}
.terminal-wrap{flex:1;min-height:0;background:#12161c;border:1px solid var(--border);
  border-radius:var(--radius);padding:8px;overflow:hidden}
#terminal{width:100%;height:100%}

.fw-bar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.fw-chip{display:flex;align-items:center;gap:10px;padding:8px 14px;background:var(--panel);
  border:1px solid var(--border);border-radius:var(--radius);font-size:13px;
  transition:background .35s,border-color .35s}
.fw-chip span{color:var(--muted);font-size:12px}
.fw-chip b{color:var(--accent);font-weight:600}
.fw-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.fw-form input[type=text]{width:220px}
.fw-form select{width:120px}

.modal{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.5);display:flex;align-items:center;
  justify-content:center;padding:24px;backdrop-filter:blur(4px);animation:fadeIn .2s ease-out}
.modal[hidden]{display:none}
/* 确认框必须始终覆盖账号设置等其他弹窗（例如“退出登录”确认）。 */
.modal#confirm-modal{z-index:160}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes modalIn{from{opacity:0;transform:scale(.94) translateY(10px)}to{opacity:1;transform:none}}
.modal-box{background:var(--panel);border:1px solid var(--border);border-radius:10px;
  box-shadow:0 24px 70px var(--shadow);display:flex;flex-direction:column;max-height:100%;width:100%;
  animation:modalIn .25s cubic-bezier(.2,.8,.3,1)}
.editor-box{max-width:1000px;height:80vh}
.prompt-box{max-width:440px}
.confirm-box{max-width:440px}
.form-box{max-width:600px;max-height:92vh}
.modal-head{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;
  border-bottom:1px solid var(--border);font-size:14px;font-weight:600;flex-shrink:0}
.modal-foot{display:flex;align-items:center;gap:8px;padding:12px 18px;
  border-top:1px solid var(--border);flex-shrink:0}
.form-body{padding:18px;overflow-y:auto;display:flex;flex-direction:column;gap:14px}
.form-row{display:flex;flex-direction:column;gap:6px}
.form-row > label{font-size:12px;color:var(--muted)}
.form-row.two-col{flex-direction:row;gap:12px}
.form-row.two-col > div{flex:1;display:flex;flex-direction:column;gap:6px}
.form-row.two-col > div > label{font-size:12px;color:var(--muted)}
.radio-group{display:flex;gap:18px;flex-wrap:wrap}
.radio{display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;color:var(--text)}
.radio input{accent-color:var(--accent);width:14px;height:14px}
.prompt-body{padding:16px;display:flex;flex-direction:column;gap:10px}
.confirm-body{padding:22px 18px;display:flex;gap:14px;align-items:flex-start}
.confirm-icon{font-size:24px;line-height:1;flex-shrink:0}
.confirm-text{flex:1;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
#editor-area{flex:1;min-height:0;width:100%;border:none;border-radius:0;padding:14px 16px;resize:none;
  outline:none;font-family:ui-monospace,Menlo,Consolas,"Courier New",monospace;font-size:13px;
  line-height:1.6;background:#0b0e13;color:#d7dce5;tab-size:4}
.test-result{padding:0 18px 14px;font-size:12px;min-height:0}
.test-result.ok{color:var(--ok)}
.test-result.err{color:var(--danger)}
.perm-tabs{display:flex;gap:6px;padding:0 18px;border-bottom:1px solid var(--border)}
.perm-tab{padding:8px 16px;background:transparent;border:none;border-bottom:2px solid transparent;
  color:var(--muted);cursor:pointer;font-size:13px}
.perm-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.perm-body{padding:18px;display:flex;flex-direction:column;gap:14px}
.perm-trio{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.perm-group{border:1px solid var(--border);border-radius:8px;padding:14px;background:var(--panel-2)}
.perm-group .title{font-size:12px;color:var(--muted);margin-bottom:10px;text-align:center;
  border-bottom:1px dashed var(--border);padding-bottom:6px}
.perm-check{display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px;cursor:pointer}
.perm-check input{accent-color:var(--accent);width:14px;height:14px}
.perm-bottom{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.perm-bottom input[type=text]{width:80px;text-align:center}
.perm-bottom select{width:140px}

.prop-table{width:100%;border-collapse:collapse;font-size:13px}
.prop-table td{padding:8px 12px;border-bottom:1px solid var(--border)}
.prop-table td:first-child{color:var(--muted);width:110px}
.prop-table td:last-child{word-break:break-all;font-family:ui-monospace,Menlo,Consolas,monospace;
  font-size:12px}
.hash-row{background:var(--panel-2)}
.hash-line{display:flex;align-items:center;gap:8px;margin:4px 0}
.hash-line .k{color:var(--muted);width:60px;flex-shrink:0}
.hash-line .v{color:var(--ok);cursor:pointer;user-select:all;word-break:break-all;flex:1}
.hash-line .v:hover{text-decoration:underline}

.compress-opts{display:flex;gap:8px;flex-wrap:wrap}
.compress-opts label{display:flex;align-items:center;gap:6px;padding:8px 14px;
  border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:13px;
  transition:all .15s;background:var(--panel-2)}
.compress-opts label:hover{border-color:var(--accent)}
.compress-opts input{accent-color:var(--accent)}
.compress-opts label:has(input:checked){border-color:var(--accent);background:var(--panel-3);
  box-shadow:0 0 0 3px var(--glow)}

.toast-wrap{position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:200;
  display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none}
.toast{padding:12px 20px;background:var(--panel);border:1px solid var(--border);
  border-left:3px solid var(--accent);border-radius:8px;font-size:13px;min-width:280px;max-width:480px;
  box-shadow:0 12px 40px var(--shadow);animation:toastIn .25s cubic-bezier(.2,.8,.3,1);
  pointer-events:auto;transition:background .35s,border-color .35s}
.toast.ok{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--danger)}
.toast.warn{border-left-color:var(--warn)}
.toast .title{font-weight:600;margin-bottom:4px;overflow-wrap:anywhere}
.toast .prog{margin-top:8px;height:6px;background:var(--panel-2);border-radius:3px;overflow:hidden}
.toast .prog .bar{height:100%;background:var(--accent);width:0;transition:width .2s}
.toast .pct{font-size:11px;color:var(--muted);margin-top:4px;display:flex;justify-content:space-between}
@keyframes toastIn{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:translateY(0)}}

::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--panel-3);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@media (max-width:900px){
  .sidebar{width:62px}
  .brand span:last-child,.nav-item span,.uname,.theme-toggle .lbl{display:none}
  .brand{justify-content:center;padding:16px 8px}
  .nav-item{justify-content:center}
  .sidebar-foot{padding:8px}
  .user{justify-content:center;padding:6px}
  .theme-toggle{justify-content:center;padding:8px}
  .w-owner,.w-mode,.w-time,.w-note{display:none}
  .form-grid{grid-template-columns:1fr}
  .root-row{flex-direction:column;align-items:stretch}
  .root-row .form-item{min-width:auto}
  .browser-bar{flex-wrap:wrap;gap:8px}
  .browser-bar .breadcrumb{flex:1 1 100%;min-width:0}
  .browser-bar input.search-box{width:100%;min-width:0;max-width:none;flex:1 1 100%}
}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand"><span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/></svg></span><span>hia1321</span></div>
    <nav class="nav">
      <a class="nav-item active" data-view="files">
        <svg viewBox="0 0 24 24"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z"/></svg>
        <span>文件管理</span>
      </a>
      <a class="nav-item" data-view="ssh">
        <svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>
        <span>SSH 管理</span>
      </a>
      <a class="nav-item" data-view="terminal">
        <svg viewBox="0 0 24 24"><path d="M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm3 5l3 3-3 3M12 15h5"/></svg>
        <span>Web 终端</span>
      </a>
      <a class="nav-item" data-view="firewall">
        <svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9.9C7.4 20.4 4 17 4 12V6l8-3z"/></svg>
        <span>防火墙</span>
      </a>
    </nav>
    <div class="sidebar-foot">
      <div class="user" id="user-box" title="点击打开账号设置">
        <span class="avatar">{{ (session.get('user','?')[:1] or '?')|upper }}</span>
        <span class="uname">{{ session.get('user','?') }}</span>
      </div>
      <div class="theme-toggle" id="theme-toggle" title="切换明暗模式">
        <svg class="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
        <span class="lbl" id="theme-lbl">暗色</span>
        <svg class="moon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </div>
    </div>
  </aside>

  <main class="main">
    <section class="view active" id="view-files">
      <div class="toolbar">
        <button class="btn primary" id="btn-upload" style="display:none;">
          <svg viewBox="0 0 24 24"><path d="M12 16V4m0 0L8 8m4-4l4 4M4 18h16"/></svg>上传
        </button>
        <span class="spacer"></span>
        <span class="disk-info" id="disk-info"></span>
        <button class="btn danger" id="btn-batch-del" style="display:none;">删除选中</button>
      </div>
      <div class="browser-bar">
        <div class="breadcrumb" id="breadcrumb"></div>
        <input type="text" class="search-box" id="search-box" placeholder="搜索文件名…" spellcheck="false">
      </div>
      <div class="table-wrap" id="file-table-wrap" title="可将文件或文件夹拖入此区域上传">
        <table class="data-table">
          <thead><tr>
            <th class="w-check"><input type="checkbox" id="check-all"></th>
            <th class="sortable" data-sort="name">名称<span class="sort-arrow">⇅</span></th>
            <th class="w-note sortable" data-sort="note">备注<span class="sort-arrow">⇅</span></th>
            <th class="w-size sortable" data-sort="size">大小<span class="sort-arrow">⇅</span></th>
            <th class="w-mode sortable" data-sort="mode">权限<span class="sort-arrow">⇅</span></th>
            <th class="w-owner sortable" data-sort="owner">所有者<span class="sort-arrow">⇅</span></th>
            <th class="w-time sortable" data-sort="mtime">修改时间<span class="sort-arrow">⇅</span></th>
          </tr></thead>
          <tbody id="file-list"></tbody>
        </table>
        <div class="empty" id="file-empty" hidden>该目录为空</div>
      </div>
    </section>

    <section class="view" id="view-ssh">
      <div class="subtabs">
        <button class="subtab active" data-tab="service">SSH 服务</button>
        <button class="subtab" data-tab="key">密钥管理</button>
      </div>

      <div class="subpanel active" id="panel-service">
        <div class="card">
          <h3>SSH 服务 <span class="badge" id="ss-badge">检测中…</span></h3>
          <div class="stats-box">
            <div class="stat"><div class="num ok" id="ss-success">0</div><div class="lbl">今日 SSH 成功登录</div></div>
            <div class="stat"><div class="num err" id="ss-failed">0</div><div class="lbl">今日 SSH 失败尝试</div></div>
          </div>
        </div>

        <div class="card">
          <h3>SSH 基础设置</h3>
          <div class="switch-row">
            <label class="switch"><input type="checkbox" id="ss-password"><span class="slider"></span></label>
            <span class="label">SSH 密码登录</span>
            <span class="desc">允许使用密码进行 SSH 登录</span>
          </div>
          <div class="switch-row">
            <label class="switch"><input type="checkbox" id="ss-pubkey"><span class="slider"></span></label>
            <span class="label">SSH 密钥登录</span>
            <span class="desc">允许使用密钥进行 SSH 登录</span>
          </div>
          <div class="form-grid one" style="margin-top:14px">
            <div class="form-item">
              <label>SSH 端口</label>
              <input type="number" id="ss-port" value="22" min="1" max="65535">
              <p class="hint">当前 SSH 服务使用的端口，默认为 22</p>
            </div>
          </div>
          <div style="margin-top:16px">
            <button class="btn primary" id="ss-save">保存</button>
          </div>
        </div>

        <div class="card">
          <h3>Root 设置</h3>
          <div class="root-row">
            <div class="form-item">
              <label>Root 密码登录方式</label>
              <select id="ss-root">
                <option value="yes">yes - 允许密码 + 密钥登录</option>
                <option value="without-password">without-password - 只能密钥登录</option>
                <option value="no">no - 禁止 Root 登录</option>
                <option value="prohibit-password">prohibit-password - 禁止密码登录</option>
              </select>
            </div>
            <button class="btn primary" id="ss-root-save">保存 Root 设置</button>
          </div>
          <p class="hint" style="margin-top:8px">建议选择 without-password 或 prohibit-password 提高安全性</p>
        </div>

        <div class="card">
          <h3>已授权的公钥 (authorized_keys)
            <button class="btn tiny" id="ss-ak-refresh" style="margin-left:auto">刷新</button>
          </h3>
          <div class="ak-list" id="ss-ak-list"></div>
          <p class="hint">此处公钥可用来登录本机的 SSH。在"密钥管理"里生成的密钥点"添加到本机"即可加入。</p>
        </div>
      </div>

      <div class="subpanel" id="panel-key">
        <div class="toolbar">
          <button class="btn primary" id="btn-gen-key">+ 生成密钥</button>
          <button class="btn" id="btn-import-key">导入密钥</button>
          <button class="btn" id="btn-refresh-key">刷新</button>
          <span class="spacer"></span>
          <span class="hint">推荐 Ed25519（更安全、密钥更短）</span>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr>
              <th>名称</th><th>类型</th><th>指纹 (SHA256)</th>
              <th>注释</th><th class="w-time">创建时间</th>
              <th style="width:340px">操作</th>
            </tr></thead>
            <tbody id="key-list"></tbody>
          </table>
          <div class="empty" id="key-empty" hidden>暂无密钥</div>
        </div>
      </div>
    </section>

    <section class="view" id="view-terminal">
      <div class="term-head">
        <span class="term-dot" id="term-dot"></span>
        <span id="term-title">正在启动本机终端…</span>
        <span class="spacer"></span>
        <button class="btn tiny" id="btn-term-new">新开终端</button>
      </div>
      <div class="terminal-wrap"><div id="terminal"></div></div>
    </section>

    <section class="view" id="view-firewall">
      <div class="fw-bar">
        <div class="fw-chip"><span>后端</span><b id="fw-backend">检测中…</b></div>
        <div class="fw-chip">
          <span>防火墙</span>
          <label class="switch" title="点击启用/关闭防火墙">
            <input type="checkbox" id="fw-switch"><span class="slider"></span>
          </label>
          <b id="fw-switch-label" style="min-width:52px">未启用</b>
        </div>
        <span class="spacer"></span>
        <button class="btn" id="btn-fw-refresh">刷新规则</button>
      </div>

      <div class="card">
        <h3>放行端口</h3>
        <form class="fw-form" id="fw-form">
          <input type="text" id="fw-port" placeholder="端口，如 8080 或 8000:9000" required>
          <select id="fw-proto">
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="any">TCP+UDP</option>
          </select>
          <input type="text" id="fw-source" placeholder="来源 IP（可选，留空 = 所有）">
          <button class="btn primary" type="submit">放 行</button>
        </form>
        <p class="hint" id="fw-hint"></p>
      </div>

      <div class="card">
        <h3>已有规则 <span class="hint" style="margin-left:8px;font-weight:400"></span></h3>
        <div class="table-wrap" style="max-height:420px">
          <table class="data-table">
            <thead><tr>
              <th>端口</th><th>协议</th><th>动作</th><th>来源</th>
              <th style="width:120px">操作</th>
            </tr></thead>
            <tbody id="fw-list"></tbody>
          </table>
          <div class="empty" id="fw-empty" hidden>暂无规则</div>
        </div>
      </div>
    </section>
  </main>
</div>

<div class="ctx-menu" id="ctx-menu">
  <div class="item" data-act="open"><span class="ico" data-icon="folder-open"></span>打开</div>
  <div class="item" data-act="edit"><span class="ico" data-icon="pencil"></span>编辑</div>
  <div class="item" data-act="download"><span class="ico" data-icon="download"></span>下载</div>
  <div class="sep"></div>
  <div class="item" data-act="copy"><span class="ico" data-icon="copy"></span>复制</div>
  <div class="item" data-act="cut"><span class="ico" data-icon="scissors"></span>剪切</div>
  <div class="item" data-act="paste"><span class="ico" data-icon="clipboard"></span>粘贴</div>
  <div class="sep"></div>
  <div class="item" data-act="compress"><span class="ico" data-icon="archive"></span>压缩</div>
  <div class="item" data-act="extract"><span class="ico" data-icon="package-open"></span>解压到当前目录</div>
  <div class="sep"></div>
  <div class="item" data-act="rename"><span class="ico" data-icon="tag"></span>重命名</div>
  <div class="item" data-act="chmod"><span class="ico" data-icon="lock"></span>权限</div>
  <div class="item" data-act="chown"><span class="ico" data-icon="user-round"></span>所有者</div>
  <div class="item" data-act="prop"><span class="ico" data-icon="info"></span>属性</div>
  <div class="sep"></div>
  <div class="item" data-act="newfile"><span class="ico" data-icon="file-text"></span>新建文件</div>
  <div class="item" data-act="newdir"><span class="ico" data-icon="folder-plus"></span>新建文件夹</div>
  <div class="item" data-act="upload"><span class="ico" data-icon="upload"></span>上传到此处</div>
  <div class="item" data-act="refresh"><span class="ico" data-icon="refresh-cw"></span>刷新</div>
  <div class="sep"></div>
  <div class="item" data-act="delete" style="color:#f87171"><span class="ico" data-icon="trash-2"></span>删除</div>
</div>

<div class="modal" id="confirm-modal" hidden>
  <div class="modal-box confirm-box">
    <div class="modal-head"><span id="confirm-title">确认</span></div>
    <div class="confirm-body">
      <div class="confirm-icon" id="confirm-icon" data-icon="alert-triangle"></div>
      <div class="confirm-text" id="confirm-text"></div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" id="confirm-cancel">取消</button>
      <button class="btn primary" id="confirm-ok">确定</button>
    </div>
  </div>
</div>

<div class="modal" id="account-modal" hidden>
  <div class="modal-box prompt-box" style="max-width:480px">
    <div class="modal-head"><span>账号设置</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row"><label>用户名</label>
        <input type="text" id="ac-user" placeholder="admin"></div>
      <div class="form-row"><label>当前密码 <span style="color:#ef4444">*</span></label>
        <input type="password" id="ac-oldpass" placeholder="修改时需要验证" autocomplete="current-password"></div>
      <div class="form-row"><label>新密码（留空表示不修改）</label>
        <input type="password" id="ac-newpass" placeholder="至少 6 位" autocomplete="new-password"></div>
      <p class="hint" id="ac-hint"></p>
    </div>
    <div class="modal-foot">
      <button class="btn danger" id="ac-logout" style="margin-right:auto">退出登录</button>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="ac-save">保存</button>
    </div>
  </div>
</div>

<div class="modal" id="compress-modal" hidden>
  <div class="modal-box prompt-box" style="max-width:520px">
    <div class="modal-head"><span>压缩</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row">
        <label>压缩格式</label>
        <div class="compress-opts">
          <label><input type="radio" name="cf-fmt" value="zip" checked><span>ZIP (.zip)</span></label>
          <label><input type="radio" name="cf-fmt" value="tar.gz"><span>TAR.GZ</span></label>
          <label><input type="radio" name="cf-fmt" value="tar.bz2"><span>TAR.BZ2</span></label>
          <label><input type="radio" name="cf-fmt" value="tar"><span>TAR</span></label>
        </div>
      </div>
      <div class="form-row">
        <label>压缩包名称</label>
        <input type="text" id="cf-archive-name" placeholder="留空自动使用第一项名称">
        <p class="hint">保存位置：当前目录（<span id="cf-curpath">/</span>）</p>
      </div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="cf-do-compress">压 缩</button>
    </div>
  </div>
</div>

<div class="modal" id="key-gen-modal" hidden>
  <div class="modal-box form-box" style="max-width:540px">
    <div class="modal-head"><span>生成 SSH 密钥</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row"><label>密钥名称 <span style="color:#ef4444">*</span></label>
        <input type="text" id="kg-name" placeholder="如：生产服务器密钥"></div>
      <div class="form-row two-col">
        <div><label>密钥类型</label>
          <select id="kg-type">
            <option value="ed25519" selected>Ed25519（推荐）</option>
            <option value="rsa">RSA</option>
            <option value="ecdsa">ECDSA</option>
          </select></div>
        <div id="kg-bits-wrap"><label>长度 / 曲线</label>
          <select id="kg-bits"></select></div>
      </div>
      <div class="form-row"><label>注释 (Comment)</label>
        <input type="text" id="kg-comment" placeholder="留空自动生成"></div>
      <div class="form-row"><label>密钥口令 (Passphrase)</label>
        <input type="password" id="kg-pass" placeholder="可选，留空则无口令" autocomplete="new-password"></div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="kg-save">生成</button>
    </div>
  </div>
</div>

<div class="modal" id="key-import-modal" hidden>
  <div class="modal-box form-box" style="max-width:620px">
    <div class="modal-head"><span>导入 SSH 私钥</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row"><label>密钥名称 <span style="color:#ef4444">*</span></label>
        <input type="text" id="ki-name" placeholder="如：原有服务器密钥"></div>
      <div class="form-row"><label>私钥内容 <span style="color:#ef4444">*</span></label>
        <textarea id="ki-content" rows="10" style="width:100%;font-family:ui-monospace,monospace;font-size:12px"></textarea></div>
      <div class="form-row"><label>密钥口令 (Passphrase)</label>
        <input type="password" id="ki-pass" placeholder="如果私钥有加密口令则填写"></div>
      <div class="test-result" id="ki-result"></div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="ki-save">导入</button>
    </div>
  </div>
</div>

<div class="modal" id="key-view-modal" hidden>
  <div class="modal-box form-box" style="max-width:680px">
    <div class="modal-head"><span id="kv-title">密钥详情</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row">
        <label>公钥（可复制到服务器 ~/.ssh/authorized_keys）</label>
        <textarea id="kv-pub" readonly style="width:100%;height:100px;font-family:ui-monospace,monospace;font-size:12px;resize:vertical"></textarea>
      </div>
      <p class="hint" id="kv-fingerprint"></p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" id="kv-copy-pub">复制公钥</button>
        <button class="btn ok" id="kv-add-local">添加到本机</button>
        <button class="btn danger" id="kv-download-priv">下载私钥</button>
      </div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>关闭</button>
    </div>
  </div>
</div>

<div class="modal" id="perm-modal" hidden>
  <div class="modal-box form-box" style="max-width:680px">
    <div class="modal-head"><span id="perm-title">文件权限</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="perm-tabs"><button class="perm-tab active">权限</button></div>
    <div class="perm-body">
      <div class="perm-trio">
        <div class="perm-group">
          <div class="title">所有者</div>
          <label class="perm-check"><input type="checkbox" data-role="u" data-bit="4"> 读取</label>
          <label class="perm-check"><input type="checkbox" data-role="u" data-bit="2"> 写入</label>
          <label class="perm-check"><input type="checkbox" data-role="u" data-bit="1"> 执行</label>
        </div>
        <div class="perm-group">
          <div class="title">用户组</div>
          <label class="perm-check"><input type="checkbox" data-role="g" data-bit="4"> 读取</label>
          <label class="perm-check"><input type="checkbox" data-role="g" data-bit="2"> 写入</label>
          <label class="perm-check"><input type="checkbox" data-role="g" data-bit="1"> 执行</label>
        </div>
        <div class="perm-group">
          <div class="title">公共</div>
          <label class="perm-check"><input type="checkbox" data-role="o" data-bit="4"> 读取</label>
          <label class="perm-check"><input type="checkbox" data-role="o" data-bit="2"> 写入</label>
          <label class="perm-check"><input type="checkbox" data-role="o" data-bit="1"> 执行</label>
        </div>
      </div>
      <div class="perm-bottom">
        <input type="text" id="perm-mode" value="755" maxlength="4">
        <span class="hint" style="margin:0">权限，所有者</span>
        <select id="perm-owner"></select>
        <select id="perm-group"></select>
        <label class="perm-check" style="margin-left:auto">
          <input type="checkbox" id="perm-recursive"> 应用到子目录
        </label>
      </div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="perm-apply">应用</button>
    </div>
  </div>
</div>

<div class="modal" id="prop-modal" hidden>
  <div class="modal-box form-box" style="max-width:640px">
    <div class="modal-head"><span>文件属性</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body" style="padding:0">
      <table class="prop-table" id="prop-table"></table>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>关闭</button>
    </div>
  </div>
</div>

<div class="modal" id="editor-modal" hidden>
  <div class="modal-box editor-box">
    <div class="modal-head"><span id="editor-title">编辑文件</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <textarea id="editor-area" spellcheck="false"></textarea>
    <div class="modal-foot">
      <span class="hint" id="editor-hint"></span>
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="editor-save">保存 (Ctrl+S)</button>
    </div>
  </div>
</div>

<div class="modal" id="prompt-modal" hidden>
  <div class="modal-box prompt-box">
    <div class="modal-head"><span id="prompt-title">输入</span></div>
    <div class="prompt-body">
      <input type="text" id="prompt-input">
      <p class="hint" id="prompt-hint"></p>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" id="prompt-cancel">取消</button>
      <button class="btn primary" id="prompt-ok">确定</button>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toast-wrap"></div>
<input type="file" id="file-input" multiple hidden>

<script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.7.5/dist/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from((r || document).querySelectorAll(s));

// 本地 SVG 线性图标：不依赖外部图标字体/CDN。
const ICON_PATHS = {
  terminal: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  folder: '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z"/>',
  'folder-open': '<path d="M3 7V5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v2M2.5 12h19l-2 7a2 2 0 0 1-2 1H5a2 2 0 0 1-2-2z"/>',
  'folder-plus': '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z"/><path d="M12 10v6M9 13h6"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  'file-text': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>',
  'file-code': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M10 13l-2 2 2 2M14 17l2-2-2-2"/>',
  archive: '<path d="M3 4h18v4H3zM5 8v12h14V8M10 12h4M10 16h4"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
  film: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 4v16M17 4v16M3 8h4M3 16h4M17 8h4M17 16h4"/>',
  music: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.6.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.6-.9l-1.7.6-1.4-2.4 1.4-1.1a7 7 0 0 1 0-1.9l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.6-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.6.9l1.7-.6 1.4 2.4-1.4 1.1a7 7 0 0 1 0 1.8z" transform="translate(-1 -1) scale(1.08)"/>',
  pencil: '<path d="m16 4 4 4M4 20l4-.8L19 8a2.1 2.1 0 0 0-3-3L5 16z"/>',
  download: '<path d="M12 3v12m0 0 4-4m-4 4-4-4M4 17v3h16v-3"/>',
  upload: '<path d="M12 16V4m0 0L8 8m4-4 4 4M4 18v2h16v-2"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  scissors: '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="m8.2 8.2 12 12M8.2 15.8 20 4"/>',
  clipboard: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6"/>',
  'package-open': '<path d="m12 3 9 5-9 5-9-5 9-5zM3 8v8l9 5 9-5V8M12 13v8"/>',
  tag: '<path d="M20 13 11 22 2 13V4h9z"/><circle cx="7" cy="8" r="1"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  'user-round': '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/>',
  'refresh-cw': '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.5 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.5-3"/>',
  'trash-2': '<path d="M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15M10 10v7M14 10v7"/>',
  'alert-triangle': '<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  'log-out': '<path d="M10 17l5-5-5-5M15 12H3M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
  'key-round': '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L21 8"/>',
  'shield-check': '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/><path d="m9 12 2 2 4-4"/>',
  flame: '<path d="M12 22c4.4 0 7-3 7-7 0-3-1.7-5.2-4-7-.1 2-1 3-2 3-1-4-3-6-5-8 0 4-1 6-3 9-3 6 1 10 7 10z"/><path d="M10 18c0-2 1-3 2-4 1 1 2 2 2 4a2 2 0 0 1-4 0z"/>',
  'file-plus': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M12 12v6M9 15h6"/>',
};
function iconSvg(name, extraClass = '') {
  const key = Object.prototype.hasOwnProperty.call(ICON_PATHS, name) ? name : 'file';
  const cls = ('ui-icon icon-' + key + (extraClass ? ' ' + extraClass : '')).replace(/[^a-zA-Z0-9_ -]/g, '');
  return `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[key]}</svg>`;
}
$$('[data-icon]').forEach(el => { el.innerHTML = iconSvg(el.dataset.icon); });

/* ============================================================
   主题
   ============================================================ */
function updateThemeLabel() {
  const isLight = document.documentElement.classList.contains('light');
  $('#theme-lbl').textContent = isLight ? '明亮' : '暗色';
}
$('#theme-toggle').addEventListener('click', () => {
  document.documentElement.classList.toggle('light');
  const isLight = document.documentElement.classList.contains('light');
  try { localStorage.setItem('panel-theme', isLight ? 'light' : 'dark'); } catch(e){}
  updateThemeLabel();
});
updateThemeLabel();

async function api(url, options = {}) {
  const opts = { credentials: 'same-origin', ...options };
  if (opts.body !== undefined && !(opts.body instanceof FormData)) {
    opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, opts);
  if (res.status === 401) { location.href = '/login'; throw new Error('未登录'); }
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); }
  catch { throw new Error('服务器返回异常: ' + text.slice(0, 150)); }
  return data;
}

let confirmResolve = null;
function showConfirm(title, message, icon = 'alert-triangle') {
  return new Promise(resolve => {
    $('#confirm-title').textContent = title;
    $('#confirm-text').textContent = message;
    $('#confirm-icon').innerHTML = iconSvg(icon);
    $('#confirm-modal').hidden = false;
    confirmResolve = resolve;
    setTimeout(() => $('#confirm-ok').focus(), 50);
  });
}
function closeConfirm(v) {
  $('#confirm-modal').hidden = true;
  if (confirmResolve) { confirmResolve(v); confirmResolve = null; }
}
$('#confirm-ok').addEventListener('click', () => closeConfirm(true));
$('#confirm-cancel').addEventListener('click', () => closeConfirm(false));
$('#confirm-modal').addEventListener('click', e => {
  if (e.target.id === 'confirm-modal') closeConfirm(false);
});

function toast(msg, type = 'info', ms = 2600) {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  $('#toast-wrap').appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .25s, transform .25s';
    el.style.opacity = '0'; el.style.transform = 'translateY(-16px)';
    setTimeout(() => el.remove(), 260);
  }, ms);
}
function toastProgress(title) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `<div class="title"></div>
    <div class="prog"><div class="bar"></div></div>
    <div class="pct"><span class="cur">0%</span><span class="total"></span></div>`;
  el.querySelector('.title').textContent = title;
  $('#toast-wrap').appendChild(el);
  return {
    el,
    set(pct, loaded, total) {
      el.querySelector('.bar').style.width = pct + '%';
      el.querySelector('.cur').textContent = pct + '%';
      if (loaded !== undefined && total !== undefined)
        el.querySelector('.total').textContent = humanSize(loaded) + ' / ' + humanSize(total);
    },
    done() {
      el.classList.add('ok');
      el.querySelector('.bar').style.width = '100%';
      el.querySelector('.cur').textContent = '完成';
      setTimeout(() => {
        el.style.transition = 'opacity .3s, transform .3s'; el.style.opacity = '0';
        el.style.transform = 'translateY(-16px)';
        setTimeout(() => el.remove(), 320);
      }, 800);
    },
    fail(msg) {
      el.classList.add('error');
      el.querySelector('.title').textContent = title + ' - ' + msg;
      setTimeout(() => {
        el.style.transition = 'opacity .3s, transform .3s'; el.style.opacity = '0';
        el.style.transform = 'translateY(-16px)';
        setTimeout(() => el.remove(), 320);
      }, 4000);
    }
  };
}

// 批量上传只创建一个进度提示，避免大量小文件导致提示条堆叠。
function toastBatchUpload(totalFiles, totalSize) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `<div class="title"></div>
    <div class="prog"><div class="bar"></div></div>
    <div class="pct"><span class="cur">0%</span><span class="total"></span></div>`;
  $('#toast-wrap').appendChild(el);
  const titleEl = el.querySelector('.title');
  const barEl = el.querySelector('.bar');
  const pctEl = el.querySelector('.cur');
  const totalEl = el.querySelector('.total');
  let completed = 0;
  let bytesDone = 0;
  let currentLoaded = 0;
  let currentFileSize = 0;

  function update() {
    const sent = Math.min(totalSize, bytesDone + currentLoaded);
    let pct = totalSize > 0
      ? Math.round(sent / totalSize * 100)
      : Math.round(completed / Math.max(1, totalFiles) * 100);
    pct = Math.max(0, Math.min(100, pct));
    barEl.style.width = pct + '%';
    pctEl.textContent = pct + '%';
    totalEl.textContent = totalSize > 0
      ? `${humanSize(sent)} / ${humanSize(totalSize)} · ${completed}/${totalFiles} 个文件`
      : `${completed}/${totalFiles} 个文件`;
  }

  return {
    start(relativePath, index, fileSize) {
      currentLoaded = 0;
      currentFileSize = Math.max(0, Number(fileSize) || 0);
      titleEl.textContent = `上传中 ${index}/${totalFiles}：${relativePath}`;
      update();
    },
    progress(loaded) {
      currentLoaded = Math.min(currentFileSize, Math.max(0, Number(loaded) || 0));
      update();
    },
    complete(sentBytes = currentLoaded) {
      const sent = Math.min(currentFileSize, Math.max(currentLoaded, Number(sentBytes) || 0));
      bytesDone = Math.min(totalSize, bytesDone + sent);
      completed = Math.min(totalFiles, completed + 1);
      currentLoaded = 0;
      currentFileSize = 0;
      titleEl.textContent = `已处理 ${completed}/${totalFiles} 个文件`;
      update();
    },
    skip(relativePath, index) {
      titleEl.textContent = `跳过 ${index}/${totalFiles}：${relativePath}`;
      completed = Math.min(totalFiles, completed + 1);
      currentLoaded = 0;
      currentFileSize = 0;
      update();
    },
    finish(okCount, failCount) {
      el.classList.add(failCount ? 'error' : 'ok');
      titleEl.textContent = failCount
        ? `上传结束：成功 ${okCount} 个，失败 ${failCount} 个`
        : `上传完成：${okCount} 个文件`;
      if (!failCount) barEl.style.width = '100%';
      pctEl.textContent = failCount ? '已结束' : '完成';
      totalEl.textContent = `${okCount} 成功 · ${failCount} 失败 · 共 ${totalFiles} 个文件`;
      setTimeout(() => {
        el.style.transition = 'opacity .3s, transform .3s';
        el.style.opacity = '0';
        el.style.transform = 'translateY(-16px)';
        setTimeout(() => el.remove(), 320);
      }, failCount ? 5000 : 1400);
    }
  };
}

const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function humanSize(n) {
  if (n === null || n === undefined) return '-';
  if (n < 1024) return n + ' B';
  const u = ['KB','MB','GB','TB','PB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1) + ' ' + u[i];
}
function fmtTime(ts) {
  if (!ts) return '-';
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
  if (isNaN(d)) return '-';
  const p = x => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px'; ta.style.top = '0';
    ta.setAttribute('readonly', '');
    document.body.appendChild(ta);
    ta.select(); ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch (e) { return false; }
}

$$('[data-close]').forEach(btn => {
  btn.addEventListener('click', () => {
    const m = btn.closest('.modal'); if (m) m.hidden = true;
  });
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') $$('.modal:not([hidden])').forEach(m => {
    if (m.id === 'confirm-modal') closeConfirm(false);
    else m.hidden = true;
  });
});

$$('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    $$('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    const v = item.dataset.view;
    $$('.view').forEach(x => x.classList.toggle('active', x.id === 'view-' + v));
    if (v === 'terminal') setTimeout(initOrFitTerminal, 80);
    if (v === 'firewall') loadFirewall();
    if (v === 'ssh') { loadSshService(); loadKeys(); }
  });
});

async function openAccountModal() {
  const res = await api('/api/account');
  if (res.code === 0) $('#ac-user').value = res.data.username || '';
  $('#ac-oldpass').value = ''; $('#ac-newpass').value = '';
  $('#ac-hint').textContent = '';
  $('#account-modal').hidden = false;
  setTimeout(() => $('#ac-oldpass').focus(), 60);
}
$('#user-box').addEventListener('click', openAccountModal);

$('#ac-save').addEventListener('click', async () => {
  const username = $('#ac-user').value.trim();
  const oldp = $('#ac-oldpass').value;
  const newp = $('#ac-newpass').value;
  if (!oldp) { $('#ac-hint').textContent = '请填写当前密码'; return; }
  if (!username) { $('#ac-hint').textContent = '请填写用户名'; return; }
  const btn = $('#ac-save'); btn.disabled = true; btn.textContent = '保存中…';
  try {
    const r = await api('/api/account', { method: 'POST',
      body: { old_password: oldp, new_password: newp, new_username: username } });
    if (r.code === 0) {
      toast(r.msg || '已保存', 'ok');
      $('#account-modal').hidden = true;
      if (r.need_relogin) setTimeout(() => location.href = '/login', 1000);
      else setTimeout(() => location.reload(), 500);
    } else $('#ac-hint').textContent = r.msg;
  } finally { btn.disabled = false; btn.textContent = '保存'; }
});

$('#ac-logout').addEventListener('click', async () => {
  const ok = await showConfirm('退出登录', '确定要退出当前登录吗？', 'log-out');
  if (!ok) return;
  await api('/api/logout', { method: 'POST' });
  location.href = '/login';
});

let promptResolve = null;
function showPrompt(title, placeholder = '', hint = '', def = '') {
  return new Promise(resolve => {
    $('#prompt-title').textContent = title;
    $('#prompt-input').placeholder = placeholder;
    $('#prompt-input').value = def;
    $('#prompt-hint').textContent = hint;
    $('#prompt-modal').hidden = false;
    setTimeout(() => { $('#prompt-input').focus(); $('#prompt-input').select(); }, 50);
    promptResolve = resolve;
  });
}
function closePrompt(v) {
  $('#prompt-modal').hidden = true;
  if (promptResolve) { promptResolve(v); promptResolve = null; }
}
$('#prompt-ok').addEventListener('click', () => closePrompt($('#prompt-input').value.trim()));
$('#prompt-cancel').addEventListener('click', () => closePrompt(null));
$('#prompt-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') closePrompt($('#prompt-input').value.trim());
  if (e.key === 'Escape') closePrompt(null);
});

/* ============================================================
   文件管理
   ============================================================ */
let currentPath = '';
let allEntries = [];       // 服务器返回的所有条目
let clipboard = null;
let ctxTarget = null;
let currentDisk = null;
let sortField = 'name';    // 排序字段
let sortDir = 'asc';       // asc | desc
let lastClickTime = 0;
let lastClickRow = null;

const fileListEl = $('#file-list'), fileEmptyEl = $('#file-empty'), checkAllEl = $('#check-all');
const breadcrumbEl = $('#breadcrumb');
const searchBox = $('#search-box');

async function loadFiles(path = '') {
  try {
    const res = await api('/api/files?path=' + encodeURIComponent(path));
    if (res.code !== 0) { toast(res.msg, 'error'); return; }
    currentPath = res.data.path;
    currentDisk = res.data.disk;
    allEntries = res.data.entries || [];
    renderBreadcrumb(currentPath);
    refreshView();
    renderDisk(res.data.disk);
    checkAllEl.checked = false; checkAllEl.indeterminate = false;
  } catch (e) { toast(e.message, 'error'); }
}

/* 过滤 + 排序 + 渲染 */
function refreshView() {
  const q = (searchBox.value || '').trim().toLowerCase();
  let list = allEntries;
  if (q) {
    list = list.filter(e => e.name.toLowerCase().includes(q));
  }
  // 排序：目录永远优先
  list = [...list].sort((a, b) => {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    let va, vb;
    switch (sortField) {
      case 'name': va = a.name.toLowerCase(); vb = b.name.toLowerCase(); break;
      case 'note': va = (a.note || '').toLowerCase(); vb = (b.note || '').toLowerCase(); break;
      case 'size': va = a.size; vb = b.size; break;
      case 'mode': va = a.mode; vb = b.mode; break;
      case 'owner': va = a.owner.toLowerCase(); vb = b.owner.toLowerCase(); break;
      case 'mtime': va = a.mtime; vb = b.mtime; break;
      default: va = a.name.toLowerCase(); vb = b.name.toLowerCase();
    }
    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });
  renderFileList(list);
  // 更新表头排序状态
  $$('.data-table thead th').forEach(th => {
    if (th.classList.contains('sortable')) {
      const arrow = th.querySelector('.sort-arrow');
      if (th.dataset.sort === sortField) {
        th.classList.add('sorted');
        arrow.textContent = sortDir === 'asc' ? '▲' : '▼';
      } else {
        th.classList.remove('sorted');
        arrow.textContent = '⇅';
      }
    }
  });
}

/* 表头排序点击 */
$$('.data-table thead th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const field = th.dataset.sort;
    if (sortField === field) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortField = field;
      sortDir = 'asc';
    }
    refreshView();
  });
});

/* 搜索框 */
searchBox.addEventListener('input', () => refreshView());

/* 面包屑：保持单行，空间不足时从中间开始折叠目录 */
function renderBreadcrumb(path) {
  breadcrumbEl.innerHTML = '';
  const rootA = document.createElement('a');
  rootA.className = 'bc-part bc-root';
  rootA.textContent = '根目录';
  rootA.title = '返回根目录';
  rootA.addEventListener('click', (e) => { e.stopPropagation(); loadFiles(''); });
  breadcrumbEl.appendChild(rootA);

  const nodes = [];
  let acc = '';
  const parts = (path || '').split('/').filter(Boolean);
  parts.forEach((part, index) => {
    acc = acc ? acc + '/' + part : part;
    const node = document.createElement('span');
    node.className = 'bc-node';
    node.dataset.index = String(index);

    const sep = document.createElement('span');
    sep.className = 'sep';
    sep.textContent = '/';
    node.appendChild(sep);

    const a = document.createElement('a');
    a.className = 'bc-part';
    a.textContent = part;
    a.title = part;
    const target = acc;
    a.addEventListener('click', (e) => { e.stopPropagation(); loadFiles(target); });
    node.appendChild(a);
    breadcrumbEl.appendChild(node);
    nodes.push(node);
  });

  const ellipsisNode = document.createElement('span');
  ellipsisNode.className = 'bc-node bc-ellipsis-node';
  const ellipsisSep = document.createElement('span');
  ellipsisSep.className = 'sep';
  ellipsisSep.textContent = '/';
  const ellipsis = document.createElement('a');
  ellipsis.className = 'bc-part bc-ellipsis';
  ellipsis.textContent = '…';
  ellipsis.title = '点击编辑完整路径';
  ellipsis.addEventListener('click', (e) => { e.stopPropagation(); enterBcEdit(); });
  ellipsisNode.append(ellipsisSep, ellipsis);
  breadcrumbEl.appendChild(ellipsisNode);

  const fill = document.createElement('span');
  fill.className = 'bc-fill';
  breadcrumbEl.appendChild(fill);
  fitBreadcrumb();
}

function fitBreadcrumb() {
  // 正在手动编辑完整路径时，不调整输入框布局。
  if (breadcrumbEl.querySelector('.bc-input')) return;
  const root = breadcrumbEl.querySelector('.bc-root');
  const nodes = Array.from(breadcrumbEl.querySelectorAll('.bc-node:not(.bc-ellipsis-node)'));
  const ellipsisNode = breadcrumbEl.querySelector('.bc-ellipsis-node');
  const fill = breadcrumbEl.querySelector('.bc-fill');
  if (!root || !ellipsisNode || !fill) return;

  nodes.forEach(node => {
    node.style.display = '';
    const link = node.querySelector('.bc-part');
    if (link) link.style.maxWidth = '';
  });
  ellipsisNode.style.display = 'none';
  if (!nodes.length) return;

  const overflows = () => breadcrumbEl.scrollWidth > breadcrumbEl.clientWidth + 1;
  if (!overflows()) return;

  // 优先折叠中间目录，保留第一级和当前目录；省略号插在第一级之后。
  ellipsisNode.style.display = 'inline-flex';
  if (nodes.length > 1) breadcrumbEl.insertBefore(ellipsisNode, nodes[1]);
  else breadcrumbEl.insertBefore(ellipsisNode, fill);

  const middle = nodes.slice(1, -1).sort((a, b) => {
    const mid = (nodes.length - 1) / 2;
    return Math.abs(Number(a.dataset.index) - mid) - Math.abs(Number(b.dataset.index) - mid);
  });
  for (const node of middle) {
    node.style.display = 'none';
    if (!overflows()) break;
  }

  // 如果仍然放不下，连同第一级一起折叠，只保留根目录、省略号和末级目录。
  if (overflows() && nodes.length > 1) {
    nodes[0].style.display = 'none';
    breadcrumbEl.insertBefore(ellipsisNode, nodes[0]);
  }

  // 极窄窗口下缩短当前目录名，而不是让工具栏换行或横向溢出。
  if (overflows()) {
    const currentLink = nodes[nodes.length - 1].querySelector('.bc-part');
    if (currentLink) {
      currentLink.style.maxWidth = Math.max(36, breadcrumbEl.clientWidth - 100) + 'px';
    }
  }

  const hidden = nodes.filter(node => node.style.display === 'none')
    .map(node => node.querySelector('.bc-part')?.textContent || '')
    .filter(Boolean);
  const ellipsis = ellipsisNode.querySelector('.bc-ellipsis');
  if (ellipsis) ellipsis.title = hidden.length
    ? '已省略目录：' + hidden.join(' / ') + '；点击可编辑完整路径'
    : '点击编辑完整路径';
}

// 窗口宽度变化时重新计算省略位置。
if (typeof ResizeObserver !== 'undefined') {
  const breadcrumbObserver = new ResizeObserver(() => fitBreadcrumb());
  breadcrumbObserver.observe(breadcrumbEl);
}
window.addEventListener('resize', fitBreadcrumb);

breadcrumbEl.addEventListener('click', (e) => {
  if (e.target.closest('.bc-part')) return;
  if (breadcrumbEl.querySelector('input')) return;
  enterBcEdit();
});

function enterBcEdit() {
  const pathBefore = currentPath;
  breadcrumbEl.innerHTML = '';
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'bc-input';
  input.value = '/' + pathBefore;
  input.spellcheck = false;
  breadcrumbEl.appendChild(input);
  input.focus();
  input.select();

  let done = false;
  const finish = (commit) => {
    if (done) return;
    done = true;
    if (commit) {
      let p = input.value.trim().replace(/^\/+/, '').replace(/\/+$/, '');
      if (p === pathBefore) renderBreadcrumb(pathBefore);
      else loadFiles(p);
    } else {
      renderBreadcrumb(pathBefore);
    }
  };
  input.addEventListener('blur', () => finish(true));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
    if (e.key === 'Escape') { e.preventDefault(); finish(false); }
  });
}

function renderDisk(disk) {
  if (!disk) { $('#disk-info').textContent = ''; return; }
  const pct = disk.total ? (disk.used / disk.total * 100).toFixed(1) : 0;
  $('#disk-info').innerHTML = `磁盘 ${humanSize(disk.used)} / ${humanSize(disk.total)} (${pct}%) · 剩余 <b>${humanSize(disk.free)}</b>`;
}

function fileIcon(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['zip','tar','gz','tgz','bz2','xz','7z','rar','iso'].includes(ext)) return iconSvg('archive');
  if (['png','jpg','jpeg','gif','bmp','webp','svg','ico'].includes(ext)) return iconSvg('image');
  if (['mp4','mkv','avi','mov','webm'].includes(ext)) return iconSvg('film');
  if (['mp3','wav','flac','ogg'].includes(ext)) return iconSvg('music');
  if (['sh','py','js','ts','go','rb','php','c','cpp','java','rs'].includes(ext)) return iconSvg('file-code');
  if (['json','yml','yaml','toml','ini','conf','cnf'].includes(ext)) return iconSvg('settings');
  if (['log','txt','md','csv'].includes(ext)) return iconSvg('file-text');
  return iconSvg('file');
}

function renderFileList(entries) {
  fileListEl.innerHTML = '';
  fileEmptyEl.hidden = entries.length > 0;
  if (entries.length === 0) {
    fileEmptyEl.textContent = (searchBox.value || '').trim() ? '没有匹配的文件' : '该目录为空';
  }
  const frag = document.createDocumentFragment();
  entries.forEach(e => {
    const tr = document.createElement('tr');
    tr.dataset.path = e.path;
    tr.dataset.dir = e.dir ? '1' : '0';
    tr.dataset.name = e.name;
    const icon = e.dir ? iconSvg('folder') : fileIcon(e.name);
    const linkMark = e.link ? '<span class="link-mark" title="符号链接">↗</span>' : '';
    tr.innerHTML = `
      <td class="w-check"><input type="checkbox" class="row-check"></td>
      <td><div class="name-cell">
        <span class="icon">${icon}</span>
        <span class="name" title="${esc(e.name)}">${esc(e.name)}</span>
        ${linkMark}
      </div></td>
      <td class="w-note"><span class="note-cell" data-path="${esc(e.path)}" title="${esc(e.note)}">${esc(e.note)}</span></td>
      <td class="w-size">${e.dir ? '-' : humanSize(e.size)}</td>
      <td class="w-mode"><code>${e.mode}</code></td>
      <td class="w-owner">${esc(e.owner)}:${esc(e.group)}</td>
      <td class="w-time">${fmtTime(e.mtime)}</td>`;
    frag.appendChild(tr);
  });
  fileListEl.appendChild(frag);
}

/* Windows 操作逻辑：单击选中、Ctrl+单击多选、双击打开 */
fileListEl.addEventListener('click', ev => {
  const tr = ev.target.closest('tr');
  if (!tr) return;

  // 备注单元格 → 编辑
  const noteCell = ev.target.closest('.note-cell');
  if (noteCell) {
    ev.stopPropagation();
    startEditNote(noteCell);
    return;
  }

  // 复选框 → 由浏览器切换状态，同步 .selected
  if (ev.target.closest('.row-check')) {
    const cb = ev.target;
    tr.classList.toggle('selected', cb.checked);
    updateCheckAll();
    return;
  }

  // 双击检测
  const now = Date.now();
  const isDbl = (now - lastClickTime < 350) && lastClickRow === tr;
  lastClickTime = now;
  lastClickRow = tr;

  if (isDbl) {
    // 双击打开
    const path = tr.dataset.path, isDir = tr.dataset.dir === '1';
    if (isDir) loadFiles(path);
    else openEditor(path, tr.dataset.name);
    return;
  }

  // 单击选中
  const isMulti = ev.ctrlKey || ev.metaKey;
  const cb = tr.querySelector('.row-check');

  if (isMulti) {
    // Ctrl+单击：切换当前行
    cb.checked = !cb.checked;
    tr.classList.toggle('selected', cb.checked);
  } else {
    // 普通单击：清除其他，只选中当前
    $$('.row-check', fileListEl).forEach(other => {
      other.checked = false;
      other.closest('tr').classList.remove('selected');
    });
    cb.checked = true;
    tr.classList.add('selected');
  }
  keyboardAnchorIndex = Array.from(fileListEl.querySelectorAll('tr')).indexOf(tr);
  updateCheckAll();
});

/* 编辑备注 */
function startEditNote(cell) {
  if (cell.querySelector('input')) return;
  const path = cell.dataset.path;
  const oldVal = cell.textContent.trim();
  const input = document.createElement('input');
  input.type = 'text';
  input.value = oldVal;
  input.placeholder = '输入备注…';
  cell.textContent = '';
  cell.appendChild(input);
  input.focus();
  input.select();

  let done = false;
  const save = async () => {
    if (done) return;
    done = true;
    const v = input.value.trim();
    input.remove();
    if (v === oldVal) { cell.textContent = oldVal; return; }
    const r = await api('/api/files/note', { method: 'POST', body: { path, note: v } });
    if (r.code === 0) {
      cell.textContent = v; cell.title = v;
      const entry = allEntries.find(x => x.path === path);
      if (entry) entry.note = v;
    } else {
      toast(r.msg, 'error'); cell.textContent = oldVal;
    }
  };
  input.addEventListener('blur', save);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
    if (e.key === 'Escape') { done = true; input.value = oldVal; input.blur(); }
  });
}

checkAllEl.addEventListener('change', () => {
  $$('.row-check', fileListEl).forEach(cb => {
    cb.checked = checkAllEl.checked;
    cb.closest('tr').classList.toggle('selected', cb.checked);
  });
});
function updateCheckAll() {
  const all = $$('.row-check', fileListEl);
  const c = all.filter(x => x.checked).length;
  checkAllEl.checked = all.length > 0 && c === all.length;
  checkAllEl.indeterminate = c > 0 && c < all.length;
}
function getCheckedPaths() {
  return $$('.row-check', fileListEl).filter(cb => cb.checked)
    .map(cb => cb.closest('tr').dataset.path);
}

/* 右键菜单 */
const ctxMenu = $('#ctx-menu');
document.addEventListener('click', () => ctxMenu.classList.remove('show'));
document.addEventListener('contextmenu', e => {
  if (!e.target.closest('#file-table-wrap')) return;
  e.preventDefault();
  const tr = e.target.closest('tr');
  ctxTarget = tr ? {
    path: tr.dataset.path, name: tr.dataset.name, isDir: tr.dataset.dir === '1',
  } : null;
  let selected = getCheckedPaths();
  if (ctxTarget && !selected.includes(ctxTarget.path)) {
    selected = [ctxTarget.path];
    $$('.row-check', fileListEl).forEach(cb => {
      const p = cb.closest('tr').dataset.path;
      cb.checked = (p === ctxTarget.path);
      cb.closest('tr').classList.toggle('selected', cb.checked);
    });
    updateCheckAll();
  }
  if (ctxTarget) {
    keyboardAnchorIndex = Array.from(fileListEl.querySelectorAll('tr')).findIndex(row => row.dataset.path === ctxTarget.path);
  }
  const items = ctxMenu.querySelectorAll('.item');
  const seps = ctxMenu.querySelectorAll('.sep');
  items.forEach(it => {
    it.hidden = false;
    const act = it.dataset.act;
    let usable = true;
    if (!ctxTarget && !['paste','newfile','newdir','upload','refresh'].includes(act)) usable = false;
    if (act === 'edit' && ctxTarget && ctxTarget.isDir) usable = false;
    if (act === 'paste' && !clipboard) usable = false;
    if (act === 'extract') {
      if (!ctxTarget || ctxTarget.isDir) usable = false;
      else {
        const nm = ctxTarget.name.toLowerCase();
        if (!['.zip','.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz']
            .some(ext => nm.endsWith(ext))) usable = false;
      }
    }
    if (!usable) it.hidden = true;
  });
  seps.forEach(sep => {
    let hasVisible = false, sib = sep.nextElementSibling;
    while (sib && !sib.classList.contains('sep')) {
      if (sib.classList.contains('item') && !sib.hidden) { hasVisible = true; break; }
      sib = sib.nextElementSibling;
    }
    let prevVisible = false, prev = sep.previousElementSibling;
    while (prev && !prev.classList.contains('sep')) {
      if (prev.classList.contains('item') && !prev.hidden) { prevVisible = true; break; }
      prev = prev.previousElementSibling;
    }
    sep.hidden = !(hasVisible && prevVisible);
  });

  const menuWidth = 200;
  const menuHeight = ctxMenu.offsetHeight || 400;
  let x = Math.min(e.clientX, window.innerWidth - menuWidth - 10);
  let y = e.clientY;
  if (y + menuHeight > window.innerHeight - 10) {
    y = Math.max(10, window.innerHeight - menuHeight - 10);
  }
  ctxMenu.style.left = x + 'px';
  ctxMenu.style.top = y + 'px';
  ctxMenu.classList.add('show');
});

ctxMenu.addEventListener('click', async ev => {
  const it = ev.target.closest('.item');
  if (!it || it.hidden) return;
  ctxMenu.classList.remove('show');
  const act = it.dataset.act;
  const selected = getCheckedPaths().length
    ? getCheckedPaths()
    : (ctxTarget ? [ctxTarget.path] : []);

  if (act === 'open' && ctxTarget) {
    if (ctxTarget.isDir) loadFiles(ctxTarget.path);
    else openEditor(ctxTarget.path, ctxTarget.name);
  }
  if (act === 'edit' && ctxTarget && !ctxTarget.isDir) openEditor(ctxTarget.path, ctxTarget.name);
  if (act === 'download' && ctxTarget) {
    window.location.href = '/api/files/download?path=' + encodeURIComponent(ctxTarget.path);
  }
  if (act === 'copy' && selected.length) {
    clipboard = { op: 'copy', paths: selected };
    toast(`已复制 ${selected.length} 项到剪贴板`, 'ok');
  }
  if (act === 'cut' && selected.length) {
    clipboard = { op: 'cut', paths: selected };
    toast(`已剪切 ${selected.length} 项到剪贴板`, 'ok');
  }
  if (act === 'paste' && clipboard) {
    const ep = clipboard.op === 'copy' ? '/api/files/copy' : '/api/files/move';
    const res = await api(ep, { method: 'POST',
      body: { paths: clipboard.paths, target: currentPath } });
    if (res.code === 0) {
      toast(res.msg || '完成', 'ok');
      if (clipboard.op === 'cut') clipboard = null;
      loadFiles(currentPath);
    } else toast(res.msg, 'error');
  }
  if (act === 'compress' && selected.length) openCompressModal(selected);
  if (act === 'extract' && ctxTarget && !ctxTarget.isDir) {
    const tp = toastProgress(`解压：${ctxTarget.name}`);
    try {
      const res = await api('/api/files/extract', {
        method: 'POST',
        body: { path: ctxTarget.path, target: currentPath },
      });
      if (res.code === 0) { tp.done(); toast(res.msg || '解压完成', 'ok'); loadFiles(currentPath); }
      else tp.fail(res.msg || '失败');
    } catch (e) { tp.fail(e.message); }
  }
  if (act === 'rename' && ctxTarget) renameEntry(ctxTarget.path, ctxTarget.name);
  if (act === 'chmod' && selected.length) openPermModal(selected);
  if (act === 'chown' && selected.length) openPermModal(selected, 'owner');
  if (act === 'prop' && ctxTarget) openPropModal(ctxTarget.path);
  if (act === 'newfile') {
    const name = await showPrompt('新建文件', '文件名，如 index.html');
    if (!name) return;
    const res = await api('/api/files/touch', { method: 'POST',
      body: { path: currentPath, name } });
    if (res.code === 0) { toast('创建成功', 'ok'); loadFiles(currentPath); }
    else toast(res.msg, 'error');
  }
  if (act === 'newdir') {
    const name = await showPrompt('新建文件夹', '文件夹名称');
    if (!name) return;
    const res = await api('/api/files/mkdir', { method: 'POST',
      body: { path: currentPath, name } });
    if (res.code === 0) { toast('创建成功', 'ok'); loadFiles(currentPath); }
    else toast(res.msg, 'error');
  }
  if (act === 'upload') { const inp = $('#file-input'); inp.value = ''; inp.click(); }
  if (act === 'refresh') loadFiles(currentPath);
  if (act === 'delete' && selected.length) {
    const ok = await showConfirm('删除确认',
      `确定删除选中的 ${selected.length} 项吗？\n此操作不可恢复！`, 'trash-2');
    if (!ok) return;
    const res = await api('/api/files/delete', { method: 'POST', body: { paths: selected } });
    if (res.code === 0) { toast('已删除', 'ok'); loadFiles(currentPath); }
    else toast(res.msg, 'error');
  }
});

let compressPaths = [];
function openCompressModal(paths) {
  compressPaths = paths;
  const firstName = paths[0].split('/').pop() || 'archive';
  $('#cf-archive-name').value = firstName;
  $('#cf-curpath').textContent = '/' + (currentPath || '');
  $$('input[name=cf-fmt]').forEach(r => r.checked = r.value === 'zip');
  $('#compress-modal').hidden = false;
  setTimeout(() => { $('#cf-archive-name').focus(); $('#cf-archive-name').select(); }, 60);
}
$('#cf-do-compress').addEventListener('click', async () => {
  const fmt = ($$('input[name=cf-fmt]').find(r => r.checked) || {}).value || 'zip';
  let archiveName = $('#cf-archive-name').value.trim();
  if (!archiveName) archiveName = compressPaths[0].split('/').pop() || 'archive';
  $('#compress-modal').hidden = true;
  const tp = toastProgress(`压缩 ${compressPaths.length} 项 → ${archiveName}`);
  try {
    const res = await api('/api/files/compress', {
      method: 'POST',
      body: { paths: compressPaths, format: fmt,
              archive_name: archiveName, target: currentPath },
    });
    if (res.code === 0) { tp.done(); toast(res.msg || '压缩完成', 'ok'); loadFiles(currentPath); }
    else tp.fail(res.msg || '失败');
  } catch (e) { tp.fail(e.message); }
});

$('#btn-batch-del').addEventListener('click', async () => {
  const paths = getCheckedPaths();
  if (!paths.length) { toast('请先勾选文件', 'warn'); return; }
  const ok = await showConfirm('删除确认',
    `确定删除选中的 ${paths.length} 项吗？\n此操作不可恢复！`, 'trash-2');
  if (!ok) return;
  const res = await api('/api/files/delete', { method: 'POST', body: { paths } });
  if (res.code === 0) { toast('已删除', 'ok'); loadFiles(currentPath); }
  else toast(res.msg, 'error');
});

/* Windows 风格文件管理快捷键 */
let keyboardAnchorIndex = null;
function fileShortcutsEnabled() {
  if (!$('#view-files').classList.contains('active')) return false;
  if ($$('.modal:not([hidden])').length) return false;
  const active = document.activeElement;
  // 输入框、编辑器、路径编辑框等保留浏览器/文本编辑器自身快捷键。
  if (active && (active.matches('input, textarea, select, [contenteditable="true"]') || active.isContentEditable)) {
    return false;
  }
  return true;
}
function applyRowSelection(indices) {
  const rows = Array.from(fileListEl.querySelectorAll('tr'));
  const chosen = new Set(indices);
  rows.forEach((tr, i) => {
    const cb = tr.querySelector('.row-check');
    if (!cb) return;
    cb.checked = chosen.has(i);
    tr.classList.toggle('selected', cb.checked);
  });
  updateCheckAll();
}
async function pasteFileClipboard() {
  if (!clipboard || !clipboard.paths || !clipboard.paths.length) return;
  const ep = clipboard.op === 'copy' ? '/api/files/copy' : '/api/files/move';
  const res = await api(ep, { method: 'POST',
    body: { paths: clipboard.paths, target: currentPath } });
  if (res.code === 0) {
    toast(res.msg || '粘贴完成', 'ok');
    if (clipboard.op === 'cut') clipboard = null;
    loadFiles(currentPath);
  } else toast(res.msg || '粘贴失败', 'error');
}
async function createDirectoryFromShortcut() {
  const name = await showPrompt('新建文件夹', '文件夹名称');
  if (!name) return;
  const res = await api('/api/files/mkdir', { method: 'POST',
    body: { path: currentPath, name } });
  if (res.code === 0) { toast('创建成功', 'ok'); loadFiles(currentPath); }
  else toast(res.msg || '创建失败', 'error');
}
document.addEventListener('keydown', async e => {
  if (!fileShortcutsEnabled()) return;

  const key = (e.key || '').toLowerCase();
  const mod = e.ctrlKey || e.metaKey;
  const selected = getCheckedPaths();
  const rows = Array.from(fileListEl.querySelectorAll('tr'));

  // Ctrl+A：全选当前显示的条目（搜索过滤后仅选择匹配项）。
  if (mod && !e.shiftKey && !e.altKey && key === 'a') {
    if (!rows.length) return;
    e.preventDefault();
    applyRowSelection(rows.map((_, i) => i));
    keyboardAnchorIndex = 0;
    return;
  }

  // Ctrl+C / Ctrl+X / Ctrl+V：面板内部复制、剪切、粘贴。
  if (mod && !e.shiftKey && !e.altKey && (key === 'c' || key === 'x')) {
    if (!selected.length) return;
    e.preventDefault();
    clipboard = { op: key === 'c' ? 'copy' : 'cut', paths: selected.slice() };
    toast(`${key === 'c' ? '已复制' : '已剪切'} ${selected.length} 项`, 'ok');
    return;
  }
  if (mod && !e.shiftKey && !e.altKey && key === 'v') {
    if (!clipboard || !clipboard.paths || !clipboard.paths.length) return;
    e.preventDefault();
    await pasteFileClipboard();
    return;
  }

  // Ctrl+Alt+N：新建文件夹（避开 Chrome 的 Ctrl+Shift+N 无痕窗口快捷键）。
  if (mod && e.altKey && !e.shiftKey && key === 'n') {
    e.preventDefault();
    await createDirectoryFromShortcut();
    return;
  }

  // Ctrl+F：聚焦面板内的文件名搜索框。
  if (mod && !e.shiftKey && !e.altKey && key === 'f') {
    e.preventDefault();
    searchBox.focus();
    searchBox.select();
    return;
  }

  if (e.key === 'Delete' && selected.length) {
    e.preventDefault();
    $('#btn-batch-del').click();
    return;
  }

  // F2：重命名单个选中项。
  if (e.key === 'F2' && selected.length === 1) {
    e.preventDefault();
    const entry = allEntries.find(item => item.path === selected[0]);
    if (entry) await renameEntry(entry.path, entry.name);
    return;
  }

  // Enter：打开单个选中项；目录进入目录，文件使用内置编辑器打开。
  if (e.key === 'Enter' && selected.length === 1) {
    if (e.target && e.target.closest('button, a, [role="button"]')) return;
    e.preventDefault();
    const entry = allEntries.find(item => item.path === selected[0]);
    if (entry) {
      if (entry.dir) loadFiles(entry.path);
      else openEditor(entry.path, entry.name);
    }
    return;
  }

  // F5：刷新当前目录；Alt+↑：进入上级目录。
  if (e.key === 'F5') {
    e.preventDefault();
    loadFiles(currentPath);
    return;
  }
  if (e.altKey && e.key === 'ArrowUp') {
    if (!currentPath) return;
    e.preventDefault();
    const parts = currentPath.split('/').filter(Boolean);
    parts.pop();
    loadFiles(parts.join('/'));
    return;
  }

  // ↑ / ↓：在文件列表中移动选择；按住 Shift 可扩展范围。
  if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && rows.length) {
    const selectedIndex = rows.findIndex(tr => tr.querySelector('.row-check')?.checked);
    const direction = e.key === 'ArrowDown' ? 1 : -1;
    const nextIndex = selectedIndex < 0
      ? (direction > 0 ? 0 : rows.length - 1)
      : Math.max(0, Math.min(rows.length - 1, selectedIndex + direction));
    e.preventDefault();
    if (e.shiftKey) {
      if (keyboardAnchorIndex === null) keyboardAnchorIndex = selectedIndex < 0 ? nextIndex : selectedIndex;
      const start = Math.min(keyboardAnchorIndex, nextIndex);
      const end = Math.max(keyboardAnchorIndex, nextIndex);
      applyRowSelection(Array.from({ length: end - start + 1 }, (_, i) => start + i));
    } else {
      keyboardAnchorIndex = nextIndex;
      applyRowSelection([nextIndex]);
    }
    rows[nextIndex].scrollIntoView({ block: 'nearest' });
    return;
  }

  // Esc：关闭右键菜单，或清空文件选择。
  if (e.key === 'Escape') {
    if (ctxMenu.classList.contains('show')) {
      ctxMenu.classList.remove('show');
      return;
    }
    if (selected.length) {
      e.preventDefault();
      applyRowSelection([]);
      keyboardAnchorIndex = null;
    }
  }
});

$('#btn-upload').addEventListener('click', () => {
  const inp = $('#file-input'); inp.value = ''; inp.click();
});
async function uploadOneFile(file, targetPath = currentPath, batchProgress = null,
                             relativePath = file.name, index = 1) {
  return new Promise((resolve) => {
    const url = '/api/files/upload_stream'
      + '?path=' + encodeURIComponent(targetPath)
      + '&name=' + encodeURIComponent(file.name);
    const xhr = new XMLHttpRequest();
    const tp = batchProgress ? null : toastProgress(`上传：${file.name}（${humanSize(file.size)}）`);
    if (batchProgress) batchProgress.start(relativePath, index, file.size);

    xhr.upload.addEventListener('progress', e => {
      if (!e.lengthComputable) return;
      if (batchProgress) batchProgress.progress(e.loaded);
      else tp.set(Math.round((e.loaded / e.total) * 100), e.loaded, e.total);
    });

    xhr.addEventListener('load', () => {
      const completeProgress = () => {
        if (batchProgress) batchProgress.complete(file.size);
      };
      if (xhr.status === 200) {
        try {
          const res = JSON.parse(xhr.responseText);
          if (res.code === 0) {
            if (batchProgress) completeProgress(); else tp.done();
            resolve({ ok: true });
          } else {
            if (batchProgress) completeProgress(); else tp.fail(res.msg || '失败');
            if (res.code === 507 && !batchProgress) toast(res.msg, 'error', 6000);
            resolve({ ok: false, msg: res.msg || '上传失败' });
          }
        } catch {
          if (batchProgress) completeProgress(); else tp.fail('响应解析失败');
          resolve({ ok: false, msg: '响应解析失败' });
        }
      } else if (xhr.status === 413) {
        if (batchProgress) completeProgress(); else tp.fail('超出服务端大小限制');
        resolve({ ok: false, msg: '超出服务端大小限制' });
      } else if (xhr.status === 401) {
        if (batchProgress) completeProgress(); else tp.fail('登录已过期');
        location.href = '/login';
        resolve({ ok: false, msg: '登录已过期' });
      } else {
        if (batchProgress) completeProgress(); else tp.fail('HTTP ' + xhr.status);
        resolve({ ok: false, msg: 'HTTP ' + xhr.status });
      }
    });
    xhr.addEventListener('error', () => {
      if (batchProgress) batchProgress.complete(); else tp.fail('网络中断');
      resolve({ ok: false, msg: '网络中断' });
    });
    xhr.addEventListener('abort', () => {
      if (batchProgress) batchProgress.complete(); else tp.fail('已取消');
      resolve({ ok: false, msg: '已取消' });
    });
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.send(file);
  });
}

function safeUploadParts(relativePath) {
  const parts = String(relativePath || '').replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
  if (!parts.length || parts.some(part => part === '.' || part === '..' || part.includes('\\') || part.includes('\0'))) {
    throw new Error('上传路径包含不支持的目录名称');
  }
  return parts;
}

async function ensureUploadDirectory(basePath, relativeDir) {
  // 目录按层级从浅到深创建，因此每次只需创建当前目录，避免反复请求已有父目录。
  const parts = safeUploadParts(relativeDir);
  const name = parts.pop();
  const parent = [basePath || '', parts.join('/')].filter(Boolean).join('/');
  const nextPath = [parent, name].filter(Boolean).join('/');
  const res = await api('/api/files/mkdir', {
    method: 'POST', body: { path: parent, name }
  });
  if (res.code !== 0) {
    if (res.msg !== '已存在') throw new Error(res.msg || `无法创建目录：${nextPath}`);
    const check = await api('/api/files?path=' + encodeURIComponent(nextPath));
    if (check.code !== 0) throw new Error(`路径已存在但不是目录：${nextPath}`);
  }
  return nextPath;
}

async function runUploadQueue(items, directories = [], basePath = currentPath) {
  if (!items.length && !directories.length) return;
  const totalSize = items.reduce((sum, item) => sum + (item.file?.size || 0), 0);
  if (currentDisk && totalSize > currentDisk.free) {
    const ok = await showConfirm('空间可能不足',
      `即将上传总大小 ${humanSize(totalSize)}，\n` +
      `当前目录所在分区剩余 ${humanSize(currentDisk.free)}。\n\n` +
      `继续上传可能会中途失败，是否继续？`, 'alert-triangle');
    if (!ok) return;
  }

  // 先按层级创建文件夹，保留拖入目录的相对结构，也保留空文件夹。
  const allDirs = new Set(directories);
  try {
    for (const item of items) {
      const parts = safeUploadParts(item.relativePath);
      parts.pop();
      for (let i = 1; i <= parts.length; i++) allDirs.add(parts.slice(0, i).join('/'));
    }
  } catch (e) {
    toast('无法上传：' + e.message, 'error', 5000);
    return;
  }
  const orderedDirs = Array.from(allDirs).filter(Boolean).sort((a, b) => {
    const depth = a.split('/').length - b.split('/').length;
    return depth || a.localeCompare(b);
  });
  try {
    for (const dir of orderedDirs) await ensureUploadDirectory(basePath, dir);
  } catch (e) {
    toast('创建上传目录失败：' + e.message, 'error', 5000);
    return;
  }

  let okCount = 0, failCount = 0;
  const uploadProgress = items.length ? toastBatchUpload(items.length, totalSize) : null;
  const failureDetails = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    let targetPath = basePath || '';
    try {
      const parts = safeUploadParts(item.relativePath);
      parts.pop(); // 文件名由 upload_stream 使用 File 对象自带的 name。
      if (parts.length) targetPath = [basePath, parts.join('/')].filter(Boolean).join('/');
      // 全批次复用同一个进度提示，防止每个文件各弹出一条进度条。
      const result = await uploadOneFile(item.file, targetPath, uploadProgress, item.relativePath, i + 1);
      if (result.ok) okCount++;
      else {
        failCount++;
        if (failureDetails.length < 3) failureDetails.push(`${item.relativePath}: ${result.msg || '上传失败'}`);
      }
    } catch (e) {
      failCount++;
      if (uploadProgress) uploadProgress.skip(item.relativePath, i + 1);
      if (failureDetails.length < 3) failureDetails.push(`${item.relativePath}: ${e.message}`);
    }
  }
  if (currentPath === basePath) loadFiles(currentPath);
  if (uploadProgress) uploadProgress.finish(okCount, failCount);
  else toast(`目录创建完成：${orderedDirs.length} 个目录`, 'ok');
  if (failCount) {
    const detail = failureDetails.length ? '；' + failureDetails.join('；') : '';
    toast(`上传完成：成功 ${okCount} 个，失败 ${failCount} 个${detail}`, 'warn', 6500);
  }
}

$('#file-input').addEventListener('change', async ev => {
  const files = Array.from(ev.target.files || []);
  if (!files.length) return;
  const basePath = currentPath;
  await runUploadQueue(files.map(file => ({ file, relativePath: file.name })), [], basePath);
  ev.target.value = '';
});

// Chrome/Edge 支持通过 webkitGetAsEntry 遍历拖入的目录内容。
function readDirectoryEntries(dirEntry) {
  return new Promise((resolve, reject) => {
    const reader = dirEntry.createReader();
    const collected = [];
    const readBatch = () => reader.readEntries(entries => {
      if (!entries.length) resolve(collected);
      else { collected.push(...entries); readBatch(); }
    }, reject);
    readBatch();
  });
}

async function collectDropEntry(entry, parentPath, result) {
  const relativePath = parentPath ? parentPath + '/' + entry.name : entry.name;
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    result.files.push({ file, relativePath });
    return;
  }
  if (entry.isDirectory) {
    result.directories.add(relativePath);
    const children = await readDirectoryEntries(entry);
    for (const child of children) await collectDropEntry(child, relativePath, result);
  }
}

const fileDropZone = $('#file-table-wrap');
let fileDragDepth = 0;
function dragHasFiles(ev) {
  return !!(ev.dataTransfer && Array.from(ev.dataTransfer.types || []).includes('Files'));
}
window.addEventListener('dragover', ev => { if (dragHasFiles(ev)) ev.preventDefault(); });
window.addEventListener('drop', ev => { if (dragHasFiles(ev)) ev.preventDefault(); });
fileDropZone.addEventListener('dragenter', ev => {
  if (!dragHasFiles(ev)) return;
  ev.preventDefault();
  fileDragDepth++;
  fileDropZone.classList.add('drag-over');
});
fileDropZone.addEventListener('dragover', ev => {
  if (!dragHasFiles(ev)) return;
  ev.preventDefault();
  ev.dataTransfer.dropEffect = 'copy';
  fileDropZone.classList.add('drag-over');
});
fileDropZone.addEventListener('dragleave', ev => {
  if (!dragHasFiles(ev)) return;
  ev.preventDefault();
  fileDragDepth = Math.max(0, fileDragDepth - 1);
  if (!fileDragDepth) fileDropZone.classList.remove('drag-over');
});
fileDropZone.addEventListener('drop', async ev => {
  if (!dragHasFiles(ev)) return;
  ev.preventDefault();
  ev.stopPropagation();
  fileDragDepth = 0;
  fileDropZone.classList.remove('drag-over');
  const basePath = currentPath;
  const transfer = ev.dataTransfer;
  const result = { files: [], directories: new Set() };
  const items = Array.from(transfer.items || []).filter(item => item.kind === 'file');
  let usedEntries = false;
  try {
    // 必须在 drop 事件同步阶段取出所有 entry，再异步递归读取目录。
    const entries = [];
    for (const item of items) {
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) entries.push(entry);
    }
    usedEntries = entries.length > 0;
    for (const entry of entries) await collectDropEntry(entry, '', result);
  } catch (e) {
    toast('读取拖入的文件/文件夹失败：' + e.message, 'error', 5000);
    return;
  }
  if (!usedEntries) {
    result.files = Array.from(transfer.files || []).map(file => ({
      file, relativePath: file.webkitRelativePath || file.name
    }));
  }
  if (!result.files.length && !result.directories.size) {
    toast('没有识别到可上传的文件或文件夹', 'warn');
    return;
  }
  await runUploadQueue(result.files, Array.from(result.directories), basePath);
});

async function renameEntry(path, oldName) {
  const name = await showPrompt('重命名', '新名称', '', oldName);
  if (!name || name === oldName) return;
  const res = await api('/api/files/rename', { method: 'POST', body: { path, name } });
  if (res.code === 0) { toast('已重命名', 'ok'); loadFiles(currentPath); }
  else toast(res.msg, 'error');
}

let permPaths = [];
let permUsers = [], permGroups = [];
async function loadUsersGroups() {
  if (permUsers.length) return;
  const res = await api('/api/system/users_groups');
  if (res.code === 0) { permUsers = res.data.users; permGroups = res.data.groups; }
}
async function openPermModal(paths, focus = 'mode') {
  permPaths = paths;
  await loadUsersGroups();
  const statRes = await api('/api/files/stat?path=' + encodeURIComponent(paths[0]));
  const info = statRes.code === 0 ? statRes.data : { mode: '755', owner: 'root', group: 'root' };
  const ownerSel = $('#perm-owner'); ownerSel.innerHTML = '';
  permUsers.forEach(u => {
    const o = document.createElement('option'); o.value = u.name; o.textContent = u.name;
    ownerSel.appendChild(o);
  });
  ownerSel.value = info.owner || 'root';
  const groupSel = $('#perm-group'); groupSel.innerHTML = '';
  permGroups.forEach(g => {
    const o = document.createElement('option'); o.value = g.name; o.textContent = g.name;
    groupSel.appendChild(o);
  });
  groupSel.value = info.group || 'root';
  applyModeToCheckboxes(info.mode);
  $('#perm-mode').value = info.mode;
  $('#perm-recursive').checked = false;
  $('#perm-title').textContent = paths.length === 1
    ? `文件权限 - ${paths[0].split('/').pop()}`
    : `批量修改权限 - 已选 ${paths.length} 项`;
  $('#perm-modal').hidden = false;
  setTimeout(() => {
    if (focus === 'owner') ownerSel.focus();
    else $('#perm-mode').focus();
  }, 80);
}
function applyModeToCheckboxes(mode) {
  const m = parseInt(mode, 8) || 0;
  $$('#perm-modal input[type=checkbox][data-role]').forEach(cb => {
    const role = cb.dataset.role;
    const bit = parseInt(cb.dataset.bit, 10);
    const shift = (role === 'u' ? 6 : role === 'g' ? 3 : 0) +
                  (bit === 4 ? 2 : bit === 2 ? 1 : 0);
    cb.checked = ((m >> shift) & 1) === 1;
  });
}
function computeModeFromCheckboxes() {
  let m = 0;
  $$('#perm-modal input[type=checkbox][data-role]').forEach(cb => {
    if (!cb.checked) return;
    const role = cb.dataset.role;
    const bit = parseInt(cb.dataset.bit, 10);
    const shift = (role === 'u' ? 6 : role === 'g' ? 3 : 0) +
                  (bit === 4 ? 2 : bit === 2 ? 1 : 0);
    m |= (1 << shift);
  });
  return m.toString(8).padStart(3, '0');
}
$$('#perm-modal input[type=checkbox][data-role]').forEach(cb => {
  cb.addEventListener('change', () => { $('#perm-mode').value = computeModeFromCheckboxes(); });
});
$('#perm-mode').addEventListener('input', e => {
  let v = e.target.value.replace(/[^0-7]/g, '').slice(0, 4);
  e.target.value = v;
  if (v.length >= 3) applyModeToCheckboxes(v);
});
$('#perm-apply').addEventListener('click', async () => {
  const mode = $('#perm-mode').value.trim();
  const owner = $('#perm-owner').value;
  const group = $('#perm-group').value;
  const recursive = $('#perm-recursive').checked;
  if (!/^[0-7]{3,4}$/.test(mode)) { toast('权限必须是 3~4 位八进制', 'error'); return; }
  const btn = $('#perm-apply'); btn.disabled = true; btn.textContent = '应用中…';
  try {
    const r1 = await api('/api/files/chmod', { method: 'POST',
      body: { paths: permPaths, mode, recursive } });
    if (r1.code !== 0) { toast(r1.msg, 'error'); return; }
    const r2 = await api('/api/files/chown', { method: 'POST',
      body: { paths: permPaths, owner, group, recursive } });
    if (r2.code !== 0) { toast(r2.msg, 'error'); return; }
    toast('修改成功', 'ok');
    $('#perm-modal').hidden = true;
    loadFiles(currentPath);
  } finally { btn.disabled = false; btn.textContent = '应用'; }
});

async function openPropModal(path) {
  const res = await api('/api/files/stat?path=' + encodeURIComponent(path));
  if (res.code !== 0) { toast(res.msg, 'error'); return; }
  const d = res.data;
  const t = $('#prop-table');
  const rows = [
    ['名称', d.name], ['完整路径', d.path],
    ['类型', d.is_link ? '符号链接' : d.is_dir ? '目录' : '普通文件'],
    ['大小', d.is_dir ? '-' : humanSize(d.size) + ` (${d.size} 字节)`],
    ['权限', d.mode],
    ['所有者', `${d.owner} (uid ${d.uid})`],
    ['用户组', `${d.group} (gid ${d.gid})`],
    ['修改时间', fmtTime(d.mtime)],
    ['访问时间', fmtTime(d.atime)],
    ['创建时间', fmtTime(d.ctime)],
  ];
  if (d.note) rows.push(['备注', d.note]);
  let html = rows.map(r => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join('');
  if (!d.is_dir) {
    html += `<tr class="hash-row"><td>文件哈希</td><td id="hash-result">
        <div class="hint">正在计算…</div>
      </td></tr>`;
  }
  t.innerHTML = html;
  $('#prop-modal').hidden = false;
  if (!d.is_dir) calcHashAuto(d.rel);
}

async function calcHashAuto(rel) {
  const out = $('#hash-result');
  if (!out) return;
  try {
    const res = await api('/api/files/hash?path=' + encodeURIComponent(rel));
    if (res.code !== 0) {
      out.innerHTML = `<span style="color:var(--danger)">✗ ${esc(res.msg)}</span>`;
      return;
    }
    const hashes = res.data.hashes;
    out.innerHTML = Object.entries(hashes).map(([k, v]) =>
      `<div class="hash-line">
        <span class="k">${k.toUpperCase()}</span>
        <span class="v" data-v="${esc(v)}" title="点击复制">${v}</span>
      </div>`).join('');
    out.querySelectorAll('.v').forEach(el => {
      el.addEventListener('click', async () => {
        const ok = await copyText(el.dataset.v);
        if (ok) toast('已复制', 'ok');
        else toast('复制失败，请手动选择文本', 'error');
      });
    });
  } catch (e) {
    out.innerHTML = `<span style="color:var(--danger)">✗ ${esc(e.message)}</span>`;
  }
}

let editingPath = '';
async function openEditor(path, name) {
  try {
    const res = await api('/api/files/read?path=' + encodeURIComponent(path));
    if (res.code !== 0) { toast(res.msg, 'error'); return; }
    editingPath = path;
    $('#editor-title').textContent = '编辑：' + name;
    $('#editor-hint').textContent = `大小 ${humanSize(res.data.size)} · 编码 ${res.data.encoding}` +
      (res.data.truncated ? ' · 已截断' : '');
    $('#editor-area').value = res.data.content;
    $('#editor-modal').hidden = false;
    setTimeout(() => $('#editor-area').focus(), 60);
  } catch (e) { toast(e.message, 'error'); }
}
$('#editor-save').addEventListener('click', async () => {
  if (!editingPath) return;
  const res = await api('/api/files/write', { method: 'POST',
    body: { path: editingPath, content: $('#editor-area').value } });
  if (res.code === 0) { toast('保存成功', 'ok'); $('#editor-modal').hidden = true; loadFiles(currentPath); }
  else toast(res.msg, 'error');
});
$('#editor-area').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); $('#editor-save').click(); }
  if (e.key === 'Tab') {
    e.preventDefault();
    const ta = e.target, s = ta.selectionStart, en = ta.selectionEnd;
    ta.value = ta.value.slice(0, s) + '    ' + ta.value.slice(en);
    ta.selectionStart = ta.selectionEnd = s + 4;
  }
});

/* ============================================================
   SSH 管理
   ============================================================ */
$$('.subtab').forEach(t => {
  t.addEventListener('click', () => {
    $$('.subtab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $$('.subpanel').forEach(p => p.classList.remove('active'));
    $('#panel-' + t.dataset.tab).classList.add('active');
    if (t.dataset.tab === 'service') loadSshService();
    if (t.dataset.tab === 'key') loadKeys();
  });
});

async function loadSshService() {
  try {
    const res = await api('/api/ssh/service');
    if (res.code !== 0) { toast(res.msg, 'error'); return; }
    const d = res.data, c = d.config;
    $('#ss-port').value = c.port || '22';
    $('#ss-password').checked = c.password_auth === 'yes';
    $('#ss-pubkey').checked = c.pubkey_auth === 'yes';
    const rootVal = (c.root_login || 'yes').toLowerCase();
    const sel = $('#ss-root');
    if (rootVal === 'without-password' || rootVal === 'prohibit-password') sel.value = 'without-password';
    else if (rootVal === 'no') sel.value = 'no';
    else sel.value = 'yes';
    const badge = $('#ss-badge');
    if (d.status === 'active') { badge.className = 'badge on'; badge.textContent = '运行中'; }
    else if (d.status === 'inactive') { badge.className = 'badge off'; badge.textContent = '未运行'; }
    else { badge.className = 'badge'; badge.textContent = d.status; }
    $('#ss-success').textContent = d.stats.success;
    $('#ss-failed').textContent = d.stats.failed;
    renderAuthorizedKeys(d.authorized_keys);
  } catch (e) { toast(e.message, 'error'); }
}

function renderAuthorizedKeys(list) {
  const box = $('#ss-ak-list'); box.innerHTML = '';
  if (!list || !list.length) {
    box.innerHTML = '<div class="hint" style="padding:12px;margin:0">暂无已授权公钥</div>';
    return;
  }
  list.forEach(k => {
    const el = document.createElement('div');
    el.className = 'ak-item';
    el.innerHTML = `
      <span style="color:var(--ok);display:inline-flex">${iconSvg('key-round')}</span>
      <code>${esc(k.key_type)}</code>
      <span class="fp" title="${esc(k.raw)}">${esc(k.fingerprint || k.comment || k.raw.slice(0,60))}</span>
      <span class="cmt">${esc(k.comment || '')}</span>
      <button class="btn tiny danger" data-idx="${k.index}">删除</button>`;
    box.appendChild(el);
  });
  box.querySelectorAll('button[data-idx]').forEach(b => {
    b.addEventListener('click', async () => {
      const idx = parseInt(b.dataset.idx, 10);
      const ok = await showConfirm('删除公钥', '确定删除这个已授权的公钥吗？', 'key-round');
      if (!ok) return;
      const r = await api('/api/ssh/authorized_keys/remove', {
        method: 'POST', body: { index: idx } });
      if (r.code === 0) { toast('已删除', 'ok'); loadSshService(); }
      else toast(r.msg, 'error');
    });
  });
}
$('#ss-ak-refresh').addEventListener('click', loadSshService);

$('#ss-save').addEventListener('click', async () => {
  const port = $('#ss-port').value;
  const password_auth = $('#ss-password').checked ? 'yes' : 'no';
  const pubkey_auth = $('#ss-pubkey').checked ? 'yes' : 'no';
  const root_login = $('#ss-root').value;
  const ok = await showConfirm('保存 SSH 配置',
    '保存后将重启 SSH 服务，可能导致当前 SSH 连接短暂中断。\n\n' +
    '如果新端口未在防火墙放行，将无法通过 SSH 登录。\n\n确定要继续吗？', 'alert-triangle');
  if (!ok) return;
  const btn = $('#ss-save'); btn.disabled = true; btn.textContent = '保存中…';
  try {
    const res = await api('/api/ssh/service', { method: 'POST',
      body: { port, password_auth, pubkey_auth, root_login } });
    if (res.code === 0) { toast(res.msg || '已保存', 'ok'); loadSshService(); }
    else toast(res.msg, 'error', 4200);
  } finally { btn.disabled = false; btn.textContent = '保存'; }
});

$('#ss-root-save').addEventListener('click', async () => {
  const port = $('#ss-port').value;
  const password_auth = $('#ss-password').checked ? 'yes' : 'no';
  const pubkey_auth = $('#ss-pubkey').checked ? 'yes' : 'no';
  const root_login = $('#ss-root').value;
  const ok = await showConfirm('保存 Root 设置',
    `Root 登录方式将设置为：${root_login}\n\n保存后会重启 SSH 服务。`, 'alert-triangle');
  if (!ok) return;
  const btn = $('#ss-root-save'); btn.disabled = true; btn.textContent = '保存中…';
  try {
    const res = await api('/api/ssh/service', { method: 'POST',
      body: { port, password_auth, pubkey_auth, root_login } });
    if (res.code === 0) { toast('Root 设置已保存', 'ok'); loadSshService(); }
    else toast(res.msg, 'error', 4200);
  } finally { btn.disabled = false; btn.textContent = '保存 Root 设置'; }
});

let keyCache = [];
async function loadKeys(silent = false) {
  try {
    const res = await api('/api/ssh/keys');
    if (res.code !== 0) { if (!silent) toast(res.msg, 'error'); return; }
    keyCache = res.data;
    const list = $('#key-list'); list.innerHTML = '';
    $('#key-empty').hidden = keyCache.length > 0;
    keyCache.forEach(k => {
      const tr = document.createElement('tr');
      tr.dataset.id = k.id;
      tr.innerHTML = `
        <td><div class="name-cell"><span class="name">${esc(k.name)}</span></div></td>
        <td><code>${esc((k.key_type||'').toUpperCase())}${k.bits ? ' ' + k.bits : ''}</code></td>
        <td><code style="font-size:11px">${esc(k.fingerprint || '-')}</code></td>
        <td>${esc(k.comment || '-')}</td>
        <td class="w-time">${fmtTime(k.created_at)}</td>
        <td><div style="display:flex;gap:4px;flex-wrap:nowrap;justify-content:center">
          <button class="btn tiny" data-act="view">查看</button>
          <button class="btn tiny ok" data-act="authorize">添加到本机</button>
          <button class="btn tiny" data-act="download">下载</button>
          <button class="btn tiny danger" data-act="delete">删除</button>
        </div></td>`;
      list.appendChild(tr);
    });
  } catch (e) { if (!silent) toast(e.message, 'error'); }
}

$('#key-list').addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-act]');
  const tr  = ev.target.closest('tr');
  if (!btn || !tr) return;
  const id = parseInt(tr.dataset.id, 10);
  const key = keyCache.find(k => k.id === id);
  if (!key) return;
  if (btn.dataset.act === 'view') {
    $('#kv-title').textContent = '密钥详情：' + key.name;
    $('#kv-pub').value = key.public_key || '';
    $('#kv-fingerprint').textContent = `指纹 (SHA256)：${key.fingerprint || '-'}`;
    $('#kv-add-local').dataset.id = id;
    $('#kv-download-priv').dataset.id = id;
    $('#key-view-modal').hidden = false;
  }
  if (btn.dataset.act === 'authorize') {
    const res = await api(`/api/ssh/keys/${id}/authorize`, { method: 'POST' });
    if (res.code === 0) { toast(res.msg, 'ok'); loadSshService(); } else toast(res.msg, 'error');
  }
  if (btn.dataset.act === 'download') window.location.href = `/api/ssh/keys/${id}/private`;
  if (btn.dataset.act === 'delete') {
    const ok = await showConfirm('删除密钥',
      `确定要删除密钥「${key.name}」吗？\n已用该密钥登录的配置将失效。`, 'key-round');
    if (!ok) return;
    const res = await api(`/api/ssh/keys/${id}`, { method: 'DELETE' });
    if (res.code === 0) { toast('已删除', 'ok'); loadKeys(); } else toast(res.msg, 'error');
  }
});

$('#kv-copy-pub').addEventListener('click', async () => {
  const ta = $('#kv-pub'); ta.select();
  const ok = await copyText(ta.value);
  toast(ok ? '公钥已复制' : '复制失败，请手动选择文本', ok ? 'ok' : 'error');
});
$('#kv-add-local').addEventListener('click', async ev => {
  const id = ev.currentTarget.dataset.id;
  if (!id) return;
  const res = await api(`/api/ssh/keys/${id}/authorize`, { method: 'POST' });
  if (res.code === 0) { toast(res.msg, 'ok'); loadSshService(); } else toast(res.msg, 'error');
});
$('#kv-download-priv').addEventListener('click', ev => {
  const id = ev.currentTarget.dataset.id;
  if (id) window.location.href = `/api/ssh/keys/${id}/private`;
});
$('#btn-refresh-key').addEventListener('click', () => loadKeys());

const BITS_MAP = {
  rsa: [{v:2048,t:'2048'}, {v:3072,t:'3072'}, {v:4096,t:'4096 (推荐)'}],
  ecdsa: [{v:256,t:'P-256'}, {v:384,t:'P-384'}, {v:521,t:'P-521'}],
  ed25519: [],
};
function refreshBitsOptions() {
  const type = $('#kg-type').value;
  const sel = $('#kg-bits'); sel.innerHTML = '';
  const opts = BITS_MAP[type] || [];
  if (!opts.length) { $('#kg-bits-wrap').style.visibility = 'hidden'; return; }
  $('#kg-bits-wrap').style.visibility = 'visible';
  opts.forEach(o => {
    const opt = document.createElement('option'); opt.value = o.v; opt.textContent = o.t;
    sel.appendChild(opt);
  });
}
$('#kg-type').addEventListener('change', refreshBitsOptions);
$('#btn-gen-key').addEventListener('click', () => {
  $('#kg-name').value = ''; $('#kg-comment').value = ''; $('#kg-pass').value = '';
  $('#kg-type').value = 'ed25519';
  refreshBitsOptions();
  $('#key-gen-modal').hidden = false;
});
$('#kg-save').addEventListener('click', async () => {
  const name = $('#kg-name').value.trim();
  if (!name) { toast('请填写名称', 'error'); return; }
  const res = await api('/api/ssh/keys/generate', { method: 'POST',
    body: { name, key_type: $('#kg-type').value,
            bits: parseInt($('#kg-bits').value, 10) || 0,
            comment: $('#kg-comment').value.trim(),
            passphrase: $('#kg-pass').value } });
  if (res.code === 0) {
    toast('密钥已生成', 'ok');
    $('#key-gen-modal').hidden = true;
    loadKeys();
  } else toast(res.msg, 'error');
});
$('#btn-import-key').addEventListener('click', () => {
  $('#ki-name').value = ''; $('#ki-content').value = ''; $('#ki-pass').value = '';
  $('#ki-result').textContent = ''; $('#ki-result').className = 'test-result';
  $('#key-import-modal').hidden = false;
});
$('#ki-save').addEventListener('click', async () => {
  const name = $('#ki-name').value.trim();
  const content = $('#ki-content').value.trim();
  if (!name) { toast('请填写名称', 'error'); return; }
  if (!content) { toast('请粘贴私钥', 'error'); return; }
  const res = await api('/api/ssh/keys/import', { method: 'POST',
    body: { name, private_key: content, passphrase: $('#ki-pass').value } });
  if (res.code === 0) {
    toast('密钥已导入', 'ok');
    $('#key-import-modal').hidden = true;
    loadKeys();
  } else {
    $('#ki-result').className = 'test-result err';
    $('#ki-result').textContent = '✗ ' + res.msg;
  }
});

/* ============================================================
   Web 终端
   ============================================================ */
let term = null, fitAddon = null, socket = null, localConnected = false;
function initTerminal() {
  if (term) return;
  term = new Terminal({
    cursorBlink: true, fontSize: 14, scrollback: 8000,
    fontFamily: 'Menlo, Monaco, Consolas, "Courier New", "PingFang SC", monospace',
    theme: { background:'#12161c', foreground:'#d7dce5', cursor:'#3b82f6',
      selectionBackground:'#2b3b52', black:'#1c222b', red:'#ef4444', green:'#22c55e',
      yellow:'#f59e0b', blue:'#3b82f6', magenta:'#a855f7', cyan:'#06b6d4',
      white:'#d7dce5', brightBlack:'#4b5563', brightRed:'#f87171', brightGreen:'#4ade80',
      brightYellow:'#fbbf24', brightBlue:'#60a5fa', brightMagenta:'#c084fc',
      brightCyan:'#22d3ee', brightWhite:'#f3f4f6' },
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($('#terminal'));
  setTimeout(() => { try { fitAddon.fit(); } catch(e){} }, 80);
  term.onData(d => { if (socket && localConnected) socket.emit('local_input', { d }); });
  term.onResize(({ cols, rows }) => {
    if (socket && localConnected) socket.emit('local_resize', { cols, rows });
  });
  window.addEventListener('resize', () => {
    if (term && $('#view-terminal').classList.contains('active')) {
      try { fitAddon.fit(); } catch(e){}
    }
  });
}
function setTermStatus(text, cls = '') {
  $('#term-dot').className = 'term-dot ' + cls;
  $('#term-title').textContent = text;
}
function startLocalTerminal() {
  initTerminal();
  if (socket) socket.disconnect();
  socket = io({ transports: ['websocket', 'polling'] });
  setTermStatus('正在启动本机终端…');
  term.reset();
  socket.on('connect', () => socket.emit('local_open', { cols: term.cols, rows: term.rows }));
  socket.on('connect_error', err => {
    setTermStatus('后端连接失败', 'err');
    toast('无法连接后端: ' + err.message, 'error');
  });
  socket.on('local_connected', () => {
    localConnected = true;
    setTermStatus(`本机终端 · root@${location.hostname}`, 'on');
    try { fitAddon.fit(); } catch(e){}
    term.focus();
    socket.emit('local_resize', { cols: term.cols, rows: term.rows });
  });
  socket.on('local_output', ({ d }) => { if (term) term.write(b64ToBytes(d)); });
  socket.on('local_error', ({ msg }) => {
    setTermStatus('启动失败', 'err');
    if (term) term.writeln('\r\n\x1b[31m✗ ' + msg + '\x1b[0m');
  });
  socket.on('local_close', () => {
    if (term) term.writeln('\r\n\x1b[33m—— 终端已关闭 ——\x1b[0m');
    localConnected = false;
    setTermStatus('已关闭', 'err');
  });
  socket.on('disconnect', () => {
    localConnected = false;
    setTermStatus('已断开', 'err');
  });
}
$('#btn-term-new').addEventListener('click', async () => {
  const ok = await showConfirm('新开终端', '关闭当前终端并新开一个？', 'terminal');
  if (!ok) return;
  startLocalTerminal();
});
function initOrFitTerminal() {
  initTerminal();
  try { fitAddon.fit(); } catch(e){}
  if (!socket || !localConnected) startLocalTerminal();
  term.focus();
}

/* ============================================================
   防火墙
   ============================================================ */
let fwActive = false;
async function loadFirewall() {
  try {
    const res = await api('/api/firewall');
    if (res.code !== 0) { toast(res.msg, 'error'); return; }
    const d = res.data;
    fwActive = d.active;
    $('#fw-backend').textContent = d.backend_label || d.backend;
    const sw = $('#fw-switch');
    sw.checked = d.active;
    const lbl = $('#fw-switch-label');
    lbl.textContent = d.active ? '已启用' : '未启用';
    lbl.style.color = d.active ? 'var(--ok)' : 'var(--warn)';
    $('#fw-hint').textContent = d.hint || '';
    const list = $('#fw-list'); list.innerHTML = '';
    const rules = d.rules || [];
    $('#fw-empty').hidden = rules.length > 0;
    rules.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${esc(r.port)}</code></td>
        <td>${esc((r.proto || 'any').toUpperCase())}</td>
        <td><span style="color:${r.action === 'deny' ? 'var(--danger)' : 'var(--ok)'}">
            ${r.action === 'deny' ? '拒绝' : '允许'}</span></td>
        <td>${esc(r.source || '所有')}</td>
        <td><button class="btn tiny danger" data-nums='${JSON.stringify(r.nums || [])}'
                  data-port="${esc(r.port)}" data-proto="${esc(r.proto || 'any')}"
                  data-source="${esc(r.source || '')}">删除</button></td>`;
      list.appendChild(tr);
    });
  } catch (e) { toast(e.message, 'error'); }
}
$('#btn-fw-refresh').addEventListener('click', loadFirewall);

$('#fw-switch').addEventListener('change', async e => {
  const enable = e.target.checked;
  const actionName = enable ? '启用' : '关闭';
  const extra = enable
    ? '\n\n注意：请先确保已放行 SSH 端口（默认 22），否则 SSH 连接会被切断！'
    : '\n\n注意：关闭后所有端口将直接暴露，存在安全风险。';
  const ok = await showConfirm(`${actionName}防火墙`,
    `确定要${actionName}防火墙吗？${extra}`, enable ? 'shield-check' : 'alert-triangle');
  if (!ok) { e.target.checked = !enable; return; }
  try {
    const res = await api('/api/firewall/switch', { method: 'POST', body: { enable } });
    if (res.code === 0) {
      toast(`防火墙已${actionName}`, 'ok');
      loadFirewall();
    } else {
      toast(res.msg, 'error', 4200);
      e.target.checked = !enable;
    }
  } catch (err) {
    toast(err.message, 'error');
    e.target.checked = !enable;
  }
});

$('#fw-form').addEventListener('submit', async e => {
  e.preventDefault();
  const port = $('#fw-port').value.trim();
  const proto = $('#fw-proto').value;
  const source = $('#fw-source').value.trim();
  if (!port) { toast('请填写端口', 'error'); return; }
  const btn = $('#fw-form button[type=submit]');
  btn.disabled = true; btn.textContent = '处理中…';
  try {
    const res = await api('/api/firewall/add', { method: 'POST',
      body: { port, proto, source } });
    if (res.code === 0) {
      toast(res.msg || '放行成功', 'ok');
      $('#fw-port').value = ''; $('#fw-source').value = '';
      loadFirewall();
    } else toast(res.msg, 'error', 4200);
  } finally { btn.disabled = false; btn.textContent = '放 行'; }
});
$('#fw-list').addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-port]');
  if (!btn) return;
  const { port, proto, source } = btn.dataset;
  let nums = [];
  try { nums = JSON.parse(btn.dataset.nums || '[]'); } catch {}
  const ok = await showConfirm('删除放行规则',
    `确定删除该放行规则吗？\n\n端口：${port}\n协议：${proto.toUpperCase()}\n来源：${source || '所有'}`,
    'flame');
  if (!ok) return;
  btn.disabled = true;
  const res = await api('/api/firewall/delete', { method: 'POST',
    body: { nums, port, proto, source } });
  if (res.code === 0) { toast('规则已删除', 'ok'); loadFirewall(); }
  else { toast(res.msg, 'error', 4200); btn.disabled = false; }
});

/* ============================================================
   初始化
   ============================================================ */
loadFiles('');
loadKeys(true);
loadSshService();
refreshBitsOptions();
</script>
</body>
</html>"""


# ============================================================================
# 启动
# ============================================================================
def require_root():
    """强制要求以 root 身份运行，否则立即退出。"""
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

if __name__ == "__main__":
    require_root()          # 必须在最前面，其他初始化之前
    print("\n面板启动中…")
    check_ufw()
    print(f"📡 http://{HOST}:{PORT}")
    print(f"📂 文件根目录: {FILE_ROOT}")
    print(f"📄 日志: {LOG_FILE}")
    socketio.run(app, host=HOST, port=PORT, debug=False,
                 allow_unsafe_werkzeug=True)
