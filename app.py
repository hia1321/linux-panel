import base64, errno, fcntl, hashlib, hmac, io, ipaddress, json, logging, os, pty, re, secrets, shlex
import select, shutil, signal, socket as pysocket, sqlite3, stat, struct
import subprocess, sys, tarfile, tempfile, termios, threading, time, zipfile
from datetime import datetime
from pathlib import Path
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

# 计划任务相关目录
TASK_DIR = os.path.join(DATA_DIR, "tasks")
LOG_DIR  = os.path.join(DATA_DIR, "logs")
os.makedirs(TASK_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

CRON_DIR = "/etc/cron.d"
CRON_PREFIX = "linux-panel-"

FILE_ROOT = os.path.realpath(os.environ.get("PANEL_FILE_ROOT", "/"))
HOST = os.environ.get("PANEL_HOST", "::")
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
            CREATE TABLE IF NOT EXISTS cron_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                task_type TEXT NOT NULL DEFAULT 'shell',
                run_user TEXT NOT NULL DEFAULT 'root',
                schedule_type TEXT NOT NULL DEFAULT 'daily',
                schedule_json TEXT NOT NULL DEFAULT '{}',
                script TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                use_lock INTEGER NOT NULL DEFAULT 1,
                last_run TEXT,
                last_status TEXT,
                created_at TEXT NOT NULL,
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
# 计划任务：辅助函数
# ============================================================================
WEEKDAYS_CN = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]

# 与宝塔相同的黑名单
FORBIDDEN_KEYWORDS = [
    "shutdown", "init 0", "init 6", "reboot", "halt", "poweroff",
    "mkfs", "mkfs.ext", "mke2fs", "passwd", "chpasswd", "--stdin",
]


def check_script_safety(script: str):
    text = script or ""
    for kw in FORBIDDEN_KEYWORDS:
        if kw in text:
            raise RuntimeError(f"脚本中不允许出现敏感命令：{kw}")


def _safe_int(v, default, lo, hi):
    try:
        n = int(v)
        if lo <= n <= hi: return n
    except (TypeError, ValueError):
        pass
    return default


def build_cron_expr(schedule: dict) -> str:
    """把用户友好的 schedule dict 转换成 5 段 cron 表达式"""
    t = (schedule or {}).get("type", "daily")
    if t == "daily":
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"{m} {h} * * *"
    if t == "hourly":
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"{m} * * * *"
    if t == "n_minutes":
        n = _safe_int(schedule.get("n"), 5, 1, 59)
        return f"*/{n} * * * *"
    if t == "n_hours":
        n = _safe_int(schedule.get("n"), 1, 1, 23)
        return f"0 */{n} * * *"
    if t == "weekly":
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        d = _safe_int(schedule.get("weekday"), 1, 0, 6)
        return f"{m} {h} * * {d}"
    if t == "monthly":
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        d = _safe_int(schedule.get("monthday"), 1, 1, 31)
        return f"{m} {h} {d} * *"
    if t == "custom":
        expr = (schedule.get("cron") or "").strip()
        if not re.match(r"^[\d\*\-,/\s]+$", expr):
            raise RuntimeError("自定义 cron 表达式只能包含数字、*、/、,、- 和空格")
        parts = expr.split()
        if len(parts) != 5:
            raise RuntimeError("自定义 cron 表达式必须是 5 段，例如：0 3 * * *")
        return " ".join(parts)
    raise RuntimeError("未知的执行周期类型")


def describe_schedule(schedule: dict) -> str:
    t = (schedule or {}).get("type", "daily")
    if t == "daily":
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"每天的 {h:02d}:{m:02d} 执行一次"
    if t == "hourly":
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"每小时的 {m:02d} 分执行一次"
    if t == "n_minutes":
        return f"每 {_safe_int(schedule.get('n'), 5, 1, 59)} 分钟执行一次"
    if t == "n_hours":
        return f"每 {_safe_int(schedule.get('n'), 1, 1, 23)} 小时执行一次"
    if t == "weekly":
        wd = _safe_int(schedule.get("weekday"), 1, 0, 6)
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"每{WEEKDAYS_CN[wd]} {h:02d}:{m:02d} 执行一次"
    if t == "monthly":
        d = _safe_int(schedule.get("monthday"), 1, 1, 31)
        h = _safe_int(schedule.get("hour"), 0, 0, 23)
        m = _safe_int(schedule.get("minute"), 0, 0, 59)
        return f"每月 {d} 号 {h:02d}:{m:02d} 执行一次"
    if t == "custom":
        return f"cron 表达式：{schedule.get('cron', '')}"
    return "未设置"


def _task_runner_path(tid):
    return os.path.join(TASK_DIR, f"{tid}_runner.sh")


def _task_script_path(tid, task_type):
    ext = "py" if task_type == "python" else "sh"
    return os.path.join(TASK_DIR, f"{tid}.{ext}")


def _task_log_path(tid):
    return os.path.join(LOG_DIR, f"{tid}.log")


def _cron_file_path(tid):
    return os.path.join(CRON_DIR, f"{CRON_PREFIX}{tid}")


def write_task_files(task):
    """把任务脚本与 runner 写到磁盘"""
    tid = int(task["id"])
    task_type = task["task_type"] or "shell"
    use_lock = int(task["use_lock"] or 0)
    run_user = (task["run_user"] or "root").strip()
    name = task["name"] or f"task-{tid}"

    script_path = _task_script_path(tid, task_type)
    runner_path = _task_runner_path(tid)
    log_path = _task_log_path(tid)

    # 写脚本正文
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(task["script"] or "")
    os.chmod(script_path, 0o700)

    # 构造实际执行命令
    if task_type == "python":
        base_cmd = f"/usr/bin/python3 {shlex.quote(script_path)}"
    else:
        base_cmd = f"/bin/bash {shlex.quote(script_path)}"

    if run_user and run_user != "root":
        exec_cmd = f"/usr/sbin/runuser -u {shlex.quote(run_user)} -- {base_cmd}"
    else:
        exec_cmd = base_cmd

    lines = [
        "#!/bin/bash",
        f"# linux-panel runner for task #{tid}",
        f'LOG="{log_path}"',
        'mkdir -p "$(dirname "$LOG")"',
    ]

    if use_lock:
        lines += [
            f'LOCK="/var/lock/linux-panel-{tid}.lock"',
            'exec 200>"$LOCK"',
            'if ! flock -n 200; then',
            '    echo "[$(date \'+%Y-%m-%d %H:%M:%S\')] 任务正在运行中，跳过本次执行" >> "$LOG"',
            '    exit 0',
            'fi',
        ]

    lines += [
        '# 日志轮转：超过 5MB 时保留最后 5MB',
        'if [ -f "$LOG" ]; then',
        '    SIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)',
        '    if [ "$SIZE" -gt 5242880 ]; then',
        '        tail -c 5242880 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"',
        '    fi',
        'fi',
        '',
        '{',
        '    echo ""',
        f'    echo "===== [$(date \'+%Y-%m-%d %H:%M:%S\')] 开始执行任务：{name} ====="',
        '    cd /root 2>/dev/null || cd /',
        f'    {exec_cmd}',
        '    EC=$?',
        '    echo "===== [$(date \'+%Y-%m-%d %H:%M:%S\')] 执行结束，退出码：$EC ====="',
        '} >> "$LOG" 2>&1',
        '',
    ]
    with open(runner_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.chmod(runner_path, 0o700)


def sync_cron_file(tid):
    """根据任务状态更新 /etc/cron.d/linux-panel-<tid>"""
    cron_path = _cron_file_path(tid)
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task or not int(task["enabled"] or 0):
        try: os.remove(cron_path)
        except FileNotFoundError: pass
        except OSError: pass
        return
    try:
        schedule = json.loads(task["schedule_json"] or "{}")
    except Exception:
        schedule = {}
    try:
        expr = build_cron_expr(schedule)
    except Exception:
        try: os.remove(cron_path)
        except FileNotFoundError: pass
        except OSError: pass
        return

    runner = _task_runner_path(tid)
    content = (
        f"# linux-panel task #{tid}: {task['name']}\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        f"{expr} root {runner} >/dev/null 2>&1\n"
    )
    try:
        os.makedirs(CRON_DIR, exist_ok=True)
        with open(cron_path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(cron_path, 0o644)
    except OSError as e:
        log.error(f"写入 cron 文件失败：{e}")


def remove_task_files(tid):
    for p in (
        _cron_file_path(tid),
        _task_runner_path(tid),
        _task_script_path(tid, "shell"),
        _task_script_path(tid, "python"),
        _task_log_path(tid),
        f"/var/lock/linux-panel-{tid}.lock",
    ):
        try: os.remove(p)
        except (FileNotFoundError, OSError): pass


def sync_all_cron_files():
    """启动时重新生成所有任务的 crontab，防止手工误删"""
    try:
        tasks = db_all("SELECT * FROM cron_tasks")
    except Exception:
        return
    for t in tasks:
        try:
            if int(t["enabled"] or 0):
                write_task_files(t)
            sync_cron_file(t["id"])
        except Exception as e:
            log.error(f"同步任务 #{t['id']} 失败：{e}")


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
    overwrite = request.args.get("overwrite", "0") == "1"
    try: parent = resolve(rel, must_exist=True)
    except PathError as e: return jsonify(code=400, msg=str(e))
    if not os.path.isdir(parent): return jsonify(code=400, msg="目标不是目录")
    try: name = check_name(name)
    except PathError as e: return jsonify(code=400, msg=str(e))
    target = os.path.join(parent, name)

    # 服务端再次校验冲突，防止前端检查后文件被其他进程创建。
    if os.path.lexists(target):
        if os.path.isdir(target) and not os.path.islink(target):
            return jsonify(code=409, msg=f"同名目录已存在，无法用文件覆盖：{name}"), 409
        if not overwrite:
            return jsonify(code=409, msg=f"同名文件已存在：{name}。请确认是否覆盖。"), 409

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
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".linux-panel-upload-", dir=parent)
        with os.fdopen(fd, "wb") as f:
            stream = request.stream
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk: break
                f.write(chunk); written += len(chunk)
            f.flush()
            os.fsync(f.fileno())
        try: os.chmod(temp_path, 0o644)
        except OSError: pass

        if overwrite:
            # 只有调用方显式授权覆盖时才会原子替换现有文件。
            if os.path.isdir(target) and not os.path.islink(target):
                return jsonify(code=409, msg=f"同名目录已存在，无法用文件覆盖：{name}"), 409
            os.replace(temp_path, target)
            temp_path = None
        else:
            # link() 在目标突然出现时会失败，不会覆盖并发创建的文件。
            try:
                os.link(temp_path, target)
            except FileExistsError:
                return jsonify(code=409, msg=f"上传期间出现同名文件：{name}，请确认是否覆盖。"), 409
            os.unlink(temp_path)
            temp_path = None
        return jsonify(code=0, msg=f"上传成功（{human_size(written)}）", size=written)
    except OSError as e:
        if e.errno == errno.ENOSPC:
            return jsonify(code=507, msg=f"磁盘空间不足，已接收 {human_size(written)} 后中断")
        if e.errno == errno.EACCES:
            return jsonify(code=403, msg="权限不足，无法写入目标目录")
        if e.errno == errno.EROFS:
            return jsonify(code=400, msg="目标目录所在的文件系统为只读")
        return jsonify(code=500, msg=f"写入失败：{e.strerror or e}")
    except Exception as e:
        return jsonify(code=500, msg=f"上传异常：{e}")
    finally:
        if temp_path:
            try: os.unlink(temp_path)
            except OSError: pass

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
            target = os.path.join(parent, name)
            temp_path = None
            try:
                if os.path.lexists(target):
                    failed.append(f"{name}: 同名文件已存在，已拒绝覆盖")
                    continue
                fd, temp_path = tempfile.mkstemp(prefix=".linux-panel-upload-", dir=parent)
                os.close(fd)
                f.save(temp_path)
                try: os.chmod(temp_path, 0o644)
                except OSError: pass
                # 原子地创建新目标；如果文件在检查后被创建，也不会覆盖它。
                os.link(temp_path, target)
                os.unlink(temp_path)
                temp_path = None
                saved.append(name)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    failed.append(f"{name}: 同名文件已存在，已拒绝覆盖")
                elif e.errno == errno.ENOSPC: failed.append(f"{name}: 磁盘空间不足")
                else: failed.append(f"{name}: {e.strerror or e}")
            finally:
                if temp_path:
                    try: os.unlink(temp_path)
                    except OSError: pass
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
# 计划任务 API
# ============================================================================
@app.route("/api/cron/tasks", methods=["GET", "POST"])
@login_required
def api_cron_tasks():
    if request.method == "GET":
        rows = db_all("SELECT * FROM cron_tasks ORDER BY id DESC")
        out = []
        for r in rows:
            try: sched = json.loads(r["schedule_json"] or "{}")
            except Exception: sched = {}
            r2 = dict(r)
            r2["schedule"] = sched
            r2["schedule_desc"] = describe_schedule(sched)
            del r2["schedule_json"]
            out.append(r2)
        return jsonify(code=0, data=out)

    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    task_type = (d.get("task_type") or "shell").lower()
    run_user = (d.get("run_user") or "root").strip() or "root"
    schedule = d.get("schedule") or {}
    script = d.get("script") or ""
    enabled = 1 if d.get("enabled", True) else 0
    use_lock = 1 if d.get("use_lock", True) else 0

    if not name: return jsonify(code=400, msg="请填写任务名称")
    if task_type not in ("shell", "python"): return jsonify(code=400, msg="不支持的任务类型")
    if not script.strip(): return jsonify(code=400, msg="请填写脚本内容")
    try: build_cron_expr(schedule)
    except Exception as e: return jsonify(code=400, msg=str(e))
    try: check_script_safety(script)
    except Exception as e: return jsonify(code=400, msg=str(e))
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$", run_user):
        return jsonify(code=400, msg="执行用户名格式不正确")
    import pwd
    try: pwd.getpwnam(run_user)
    except KeyError: return jsonify(code=400, msg=f"用户 {run_user} 不存在")

    now = datetime.now().isoformat(timespec="seconds")
    tid = db_exec(
        """INSERT INTO cron_tasks
           (name, task_type, run_user, schedule_type, schedule_json, script,
            enabled, use_lock, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (name, task_type, run_user, schedule.get("type", "daily"),
         json.dumps(schedule, ensure_ascii=False), script,
         enabled, use_lock, now, now)
    )
    try:
        t = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
        if t["enabled"]: write_task_files(t)
        sync_cron_file(tid)
    except Exception as e:
        db_exec("DELETE FROM cron_tasks WHERE id=?", (tid,))
        remove_task_files(tid)
        return jsonify(code=500, msg=f"创建失败：{e}")
    return jsonify(code=0, msg="任务已创建", id=tid)


@app.route("/api/cron/tasks/<int:tid>", methods=["PUT", "DELETE"])
@login_required
def api_cron_task_detail(tid):
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task: return jsonify(code=404, msg="任务不存在")

    if request.method == "DELETE":
        remove_task_files(tid)
        db_exec("DELETE FROM cron_tasks WHERE id=?", (tid,))
        return jsonify(code=0, msg="已删除")

    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    task_type = (d.get("task_type") or "shell").lower()
    run_user = (d.get("run_user") or "root").strip() or "root"
    schedule = d.get("schedule") or {}
    script = d.get("script") or ""
    enabled = 1 if d.get("enabled", True) else 0
    use_lock = 1 if d.get("use_lock", True) else 0

    if not name: return jsonify(code=400, msg="请填写任务名称")
    if task_type not in ("shell", "python"): return jsonify(code=400, msg="不支持的任务类型")
    if not script.strip(): return jsonify(code=400, msg="请填写脚本内容")
    try:
        build_cron_expr(schedule); check_script_safety(script)
    except Exception as e:
        return jsonify(code=400, msg=str(e))
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$", run_user):
        return jsonify(code=400, msg="执行用户名格式不正确")
    import pwd
    try: pwd.getpwnam(run_user)
    except KeyError: return jsonify(code=400, msg=f"用户 {run_user} 不存在")

    # 类型变化时清理旧脚本
    if task["task_type"] != task_type:
        old_ext = "py" if task["task_type"] == "python" else "sh"
        try: os.remove(os.path.join(TASK_DIR, f"{tid}.{old_ext}"))
        except OSError: pass

    now = datetime.now().isoformat(timespec="seconds")
    db_exec(
        """UPDATE cron_tasks SET
             name=?, task_type=?, run_user=?, schedule_type=?, schedule_json=?,
             script=?, enabled=?, use_lock=?, updated_at=?
           WHERE id=?""",
        (name, task_type, run_user, schedule.get("type", "daily"),
         json.dumps(schedule, ensure_ascii=False), script,
         enabled, use_lock, now, tid)
    )
    try:
        t = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
        if t["enabled"]: write_task_files(t)
        sync_cron_file(tid)
    except Exception as e:
        return jsonify(code=500, msg=f"保存失败：{e}")
    return jsonify(code=0, msg="已保存")


@app.route("/api/cron/tasks/<int:tid>/toggle", methods=["POST"])
@login_required
def api_cron_task_toggle(tid):
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task: return jsonify(code=404, msg="任务不存在")
    d = request.get_json() or {}
    new_state = 1 if d.get("enabled") else 0
    db_exec("UPDATE cron_tasks SET enabled=?, updated_at=? WHERE id=?",
            (new_state, datetime.now().isoformat(timespec="seconds"), tid))
    try:
        if new_state:
            t = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
            write_task_files(t)
        sync_cron_file(tid)
    except Exception as e:
        return jsonify(code=500, msg=f"操作失败：{e}")
    return jsonify(code=0, msg="已启用" if new_state else "已停用")


@app.route("/api/cron/tasks/<int:tid>/run", methods=["POST"])
@login_required
def api_cron_task_run(tid):
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task: return jsonify(code=404, msg="任务不存在")
    runner = _task_runner_path(tid)
    try:
        # 无论启用状态，手动执行时确保文件存在
        write_task_files(task)
    except Exception as e:
        return jsonify(code=500, msg=f"无法准备任务文件：{e}")
    try:
        subprocess.Popen(["/bin/bash", runner],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)
        db_exec("UPDATE cron_tasks SET last_run=?, last_status='running' WHERE id=?",
                (datetime.now().isoformat(timespec="seconds"), tid))
        return jsonify(code=0, msg="已启动，请稍后查看日志")
    except Exception as e:
        return jsonify(code=500, msg=f"启动失败：{e}")


@app.route("/api/cron/tasks/<int:tid>/log", methods=["GET", "DELETE"])
@login_required
def api_cron_task_log(tid):
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task: return jsonify(code=404, msg="任务不存在")
    log_path = _task_log_path(tid)
    if request.method == "DELETE":
        try: os.remove(log_path)
        except FileNotFoundError: pass
        return jsonify(code=0, msg="日志已清空")
    if not os.path.exists(log_path):
        return jsonify(code=0, data={"content": "", "size": 0})
    size = os.path.getsize(log_path)
    try:
        with open(log_path, "rb") as f:
            if size > 512 * 1024:
                f.seek(-512 * 1024, os.SEEK_END)
            raw = f.read()
        content = raw.decode("utf-8", "replace")
    except Exception as e:
        return jsonify(code=500, msg=f"读取日志失败：{e}")
    return jsonify(code=0, data={"content": content, "size": size, "truncated": size > 512 * 1024})


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
# Docker 管理：所有参数以 argv 传递，不经过 shell
# ============================================================================
DOCKER_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
DOCKER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DOCKER_ID_RE = re.compile(r"^(?:[a-fA-F0-9]{12,64}|sha256:[a-fA-F0-9]{64})$")


def docker_command(args, timeout=20):
    """运行固定子命令列表；不使用 shell，防止参数被解释为 shell 语法。"""
    binary = shutil.which("docker")
    if not binary:
        return 127, "", "未检测到 Docker CLI，请先安装 Docker Engine。"
    try:
        p = subprocess.run([binary, *args], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Docker 命令执行超时。"
    except OSError as e:
        return 127, "", str(e)


def docker_require_ok(args, timeout=20):
    code, out, err = docker_command(args, timeout=timeout)
    if code != 0:
        msg = (err or out or f"Docker 命令失败，退出码 {code}").strip()
        raise RuntimeError(msg[-5000:])
    return out


def docker_json_lines(args):
    raw = docker_require_ok(args)
    values = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError:
            # 过滤掉 Docker 插件/版本输出中的非 JSON 行，但保留可解析项目。
            continue
    return values


def docker_validate_container_id(value):
    value = str(value or "").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{12,64}", value):
        raise ValueError("容器 ID 格式不正确，请刷新列表后重试")
    return value


def docker_validate_named_resource(value, label="资源"):
    value = str(value or "").strip()
    if not DOCKER_NAME_RE.fullmatch(value):
        raise ValueError(f"{label}名称格式不正确")
    return value


def _docker_path_relative_to_file_root(path):
    """Return a file-manager-relative path only when a host path is inside FILE_ROOT."""
    path = str(path or "").strip()
    if not path:
        return ""
    try:
        real = os.path.realpath(path)
        root = os.path.realpath(FILE_ROOT)
        prefix = root if root.endswith(os.sep) else root + os.sep
        if real != root and not real.startswith(prefix):
            return ""
        return "" if real == root else os.path.relpath(real, root).replace(os.sep, "/")
    except Exception:
        return ""


@app.route("/api/docker/status")
@login_required
def api_docker_status():
    binary = shutil.which("docker")
    if not binary:
        return jsonify(code=0, data={
            "installed": False, "running": False, "version": "",
            "message": "未安装 Docker CLI。Ubuntu/Debian 可安装 Docker Engine 后使用本模块。"})
    code, out, err = docker_command(["info", "--format", "{{.ServerVersion}}"], timeout=8)
    if code != 0:
        detail = (err or out or "Docker 服务不可用").strip()
        return jsonify(code=0, data={
            "installed": True, "running": False, "version": "",
            "message": detail[-800:]})
    return jsonify(code=0, data={
        "installed": True, "running": True, "version": out.strip(),
        "message": "Docker 服务运行正常"})


_docker_install_lock = threading.Lock()
_docker_install_state_lock = threading.Lock()
_docker_install_state = {
    "task_id": "", "running": False, "done": False, "success": False,
    "percent": 0, "stage": "", "message": "尚未开始", "logs": [], "result": ""
}


def _docker_install_state_update(task_id, **changes):
    with _docker_install_state_lock:
        if _docker_install_state.get("task_id") != task_id:
            return
        for key, value in changes.items():
            if key == "log_line":
                logs = _docker_install_state.setdefault("logs", [])
                logs.append(str(value)[-1000:])
                del logs[:-120]
            elif key == "percent":
                _docker_install_state[key] = max(int(_docker_install_state.get(key, 0) or 0), int(value or 0))
            else:
                _docker_install_state[key] = value


def _docker_install_worker(task_id):
    import queue
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["APT_LISTCHANGES_FRONTEND"] = "none"
    steps = [
        ("更新软件包索引", ["apt-get", "update", "-o", "APT::Status-Fd=1"], 300, 3, 24),
        ("安装 Docker Engine", ["apt-get", "install", "-y", "-o", "APT::Status-Fd=1", "-o", "Dpkg::Use-Pty=0", "docker.io"], 600, 25, 88),
        ("启动并设置 Docker 开机自启", ["systemctl", "enable", "--now", "docker"], 90, 91, 97),
    ]

    def run_step(label, args, timeout, low, high):
        _docker_install_state_update(task_id, stage=label, message=f"正在执行：{label}", percent=low)
        try:
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env
            )
        except OSError as e:
            raise RuntimeError(f"{label}启动失败：{e}") from e
        lines = queue.Queue()

        def reader():
            try:
                for line in proc.stdout:
                    lines.put(line.rstrip("\r\n"))
            finally:
                lines.put(None)

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()
        deadline = time.monotonic() + timeout
        line_count = 0
        stream_closed = False
        latest_detail = ""
        while True:
            if time.monotonic() > deadline:
                try: proc.kill()
                except OSError: pass
                try: proc.wait(timeout=3)
                except Exception: pass
                raise RuntimeError(f"{label}超时。请检查服务器网络及 apt 软件源后重试。")
            try:
                line = lines.get(timeout=0.25)
                if line is None:
                    stream_closed = True
                elif line:
                    # APT::Status-Fd 输出包含可用于实时进度的结构化状态。
                    line_count += 1
                    low_line = line.lower()
                    pct = None
                    match = re.match(r"pmstatus:[^:]*:(\d{1,3}):", line)
                    if match and label == "安装 Docker Engine":
                        pct = int(match.group(1))
                    elif line.startswith("dlstatus:"):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            try: pct = int(parts[-1])
                            except (TypeError, ValueError): pct = None
                    if pct is not None:
                        pct = max(0, min(100, pct))
                        mapped = low + (high - low) * pct / 100.0
                        _docker_install_state_update(task_id, percent=int(mapped))
                        # 状态行用于进度，避免把大段 URI 写入弹窗日志。
                        status_msg = line.split(":")[-1].strip() if ":" in line else line
                        latest_detail = status_msg[:240] or label
                        _docker_install_state_update(task_id, message=f"{label}：{latest_detail}",
                                                     log_line=f"[{label}] {latest_detail}")
                    else:
                        # 非结构化输出也实时展示，并提供平滑但不虚报完成的进度。
                        latest_detail = line[:240]
                        ceiling = max(low, high - 2)
                        fallback = min(ceiling, low + min(1 + line_count // 3, max(1, high-low-2)))
                        _docker_install_state_update(task_id, percent=fallback,
                                                     message=f"{label}：{latest_detail}",
                                                     log_line=f"[{label}] {line}")
            except queue.Empty:
                pass
            if proc.poll() is not None and stream_closed:
                break
        reader_thread.join(timeout=1)
        rc = proc.wait()
        if rc != 0:
            detail = latest_detail or f"退出码 {rc}"
            raise RuntimeError(f"{label}失败：{detail}")
        _docker_install_state_update(task_id, percent=high,
                                     message=f"{label}完成", log_line=f"[{label}] 完成")

    try:
        if shutil.which("docker"):
            code, out, err = docker_command(["info", "--format", "{{.ServerVersion}}"], timeout=10)
            if code == 0:
                result = "Docker 已安装且正在运行，版本 " + out.strip()
                _docker_install_state_update(task_id, running=False, done=True, success=True,
                                             percent=100, stage="完成", message=result, result=result,
                                             log_line=result)
                return
        for label, args, timeout, low, high in steps:
            run_step(label, args, timeout, low, high)
        _docker_install_state_update(task_id, stage="验证 Docker 服务", percent=98,
                                     message="正在验证 Docker 服务是否正常启动")
        code, out, err = docker_command(["info", "--format", "{{.ServerVersion}}"], timeout=20)
        if code != 0:
            detail = (err or out or "Docker 服务尚未就绪").strip()
            raise RuntimeError("Docker 已安装，但服务检测失败：" + detail[-1200:])
        version = out.strip()
        result = f"Docker Engine 安装并启动成功，版本 {version}"
        log.info("用户通过面板完成 Docker 安装，版本 %s", version)
        _docker_install_state_update(task_id, running=False, done=True, success=True,
                                     percent=100, stage="完成", message=result, result=result,
                                     log_line=result)
    except Exception as e:
        error = str(e)
        log.error("Docker 安装任务失败：%s", error)
        _docker_install_state_update(task_id, running=False, done=True, success=False,
                                     stage="安装失败", message=error, result=error,
                                     log_line="错误：" + error)
    finally:
        _docker_install_lock.release()


@app.route("/api/docker/install", methods=["POST"])
@login_required
def api_docker_install():
    """启动后台 Docker 安装任务，进度通过 /api/docker/install/status 查询。"""
    if shutil.which("docker"):
        code, out, err = docker_command(["info", "--format", "{{.ServerVersion}}"], timeout=10)
        if code == 0:
            return jsonify(code=0, msg="Docker 已安装且正在运行", data={
                "already_running": True, "done": True, "success": True,
                "percent": 100, "message": "Docker 已安装且正在运行，版本 " + out.strip()
            })
    if not os.path.exists("/usr/bin/apt-get"):
        return jsonify(code=400, msg="一键安装仅支持 Ubuntu/Debian 的 apt 软件包管理器")
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
            os_release = f.read().lower()
    except OSError:
        os_release = ""
    if not any(x in os_release for x in ("id=ubuntu", "id=debian", "id_like=debian")):
        return jsonify(code=400, msg="检测到的系统不是受支持的 Ubuntu/Debian，请手动安装 Docker Engine")
    if not _docker_install_lock.acquire(blocking=False):
        with _docker_install_state_lock:
            state = dict(_docker_install_state)
        return jsonify(code=0, msg="Docker 安装任务正在执行", data=state)

    task_id = secrets.token_hex(8)
    with _docker_install_state_lock:
        _docker_install_state.clear()
        _docker_install_state.update({
            "task_id": task_id, "running": True, "done": False, "success": False,
            "percent": 1, "stage": "准备安装", "message": "安装任务已启动，正在准备软件包管理器",
            "logs": ["安装任务已启动"], "result": ""
        })
    try:
        worker = threading.Thread(target=_docker_install_worker, args=(task_id,), daemon=True)
        worker.start()
    except Exception as e:
        _docker_install_lock.release()
        with _docker_install_state_lock:
            _docker_install_state.update({"running": False, "done": True, "success": False,
                                          "message": f"无法启动安装任务：{e}", "result": str(e)})
        return jsonify(code=500, msg=f"无法启动安装任务：{e}")
    return jsonify(code=0, msg="Docker 安装任务已启动", data={"task_id": task_id, "running": True})


@app.route("/api/docker/install/status")
@login_required
def api_docker_install_status():
    with _docker_install_state_lock:
        state = dict(_docker_install_state)
        state["logs"] = list(_docker_install_state.get("logs", []))
    if not state.get("task_id"):
        return jsonify(code=0, data={"running": False, "done": False, "success": False,
                                     "percent": 0, "stage": "", "message": "没有安装任务", "logs": []})
    return jsonify(code=0, data=state)

# Docker Engine 设置与镜像源管理
DOCKER_CONFIG_PATH = "/etc/docker/daemon.json"
DOCKER_KNOWN_PACKAGES = {
    "docker.io", "docker-ce", "docker-ce-cli", "docker-ce-rootless-extras",
    "containerd", "containerd.io", "runc", "docker-compose", "docker-compose-v2",
    "docker-compose-plugin", "docker-buildx-plugin", "docker-doc"
}
DOCKER_MIRROR_PRESETS = {
    "1panel": "https://docker.1panel.live",
    "daocloud": "https://docker.m.daocloud.io",
    "1ms": "https://docker.1ms.run",
    "dockerproxy": "https://dockerproxy.net",
    "dockerproxy-link": "https://dockerproxy.link",
    "dockerproxy-cool": "https://dockerproxy.cool",
    "cnix": "https://docker.m.ixdev.cn",
    "rat": "https://hub.rat.dev",
    "jiaxin": "https://docker.jiaxin.site",
    "tencent-internal": "https://mirror.ccs.tencentyun.com",
}


def _docker_systemctl(args, timeout=45):
    if not shutil.which("systemctl"):
        return 127, "", "当前系统未检测到 systemctl。"
    try:
        p = subprocess.run(["systemctl", *args], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "systemctl 命令执行超时。"
    except OSError as e:
        return 127, "", str(e)


def _docker_service_state():
    active_code, active_out, _ = _docker_systemctl(["is-active", "docker"], timeout=5)
    enabled_code, enabled_out, _ = _docker_systemctl(["is-enabled", "docker"], timeout=5)
    return {
        "active": active_code == 0 and active_out.strip() == "active",
        "active_state": active_out.strip() or "unknown",
        "enabled": enabled_code == 0 and enabled_out.strip() == "enabled",
        "enabled_state": enabled_out.strip() or "unknown",
    }


def _docker_read_config_bytes():
    try:
        with open(DOCKER_CONFIG_PATH, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _docker_atomic_write_config(raw_bytes):
    directory = os.path.dirname(DOCKER_CONFIG_PATH)
    os.makedirs(directory, exist_ok=True)
    old = _docker_read_config_bytes()
    backup_path = ""
    if old is not None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = f"{DOCKER_CONFIG_PATH}.backup-{stamp}"
        # Avoid overwriting a same-second backup.
        suffix = 1
        while os.path.exists(backup_path):
            backup_path = f"{DOCKER_CONFIG_PATH}.backup-{stamp}-{suffix}"
            suffix += 1
        with open(backup_path, "xb") as f:
            f.write(old)
        try: os.chmod(backup_path, 0o600)
        except OSError: pass
    fd, tmp_path = tempfile.mkstemp(prefix=".daemon.json.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, DOCKER_CONFIG_PATH)
    finally:
        try:
            if os.path.exists(tmp_path): os.unlink(tmp_path)
        except OSError:
            pass
    return old, backup_path


def _docker_restore_config_bytes(raw_bytes):
    if raw_bytes is None:
        try: os.unlink(DOCKER_CONFIG_PATH)
        except FileNotFoundError: pass
        return
    directory = os.path.dirname(DOCKER_CONFIG_PATH)
    fd, tmp_path = tempfile.mkstemp(prefix=".daemon.json.rollback.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw_bytes); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, DOCKER_CONFIG_PATH)
    finally:
        try:
            if os.path.exists(tmp_path): os.unlink(tmp_path)
        except OSError:
            pass


def _docker_restart_if_active():
    state = _docker_service_state()
    if not state["active"]:
        return False, "Docker 当前未运行，配置将在下次启动时生效。"
    code, out, err = _docker_systemctl(["restart", "docker"], timeout=90)
    if code != 0:
        raise RuntimeError((err or out or "重启 Docker 服务失败").strip()[-3000:])
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = _docker_service_state()
        if state["active"]:
            return True, "Docker 已重启，配置已生效。"
        time.sleep(0.5)
    raise RuntimeError("systemctl 已执行重启，但 Docker 服务未在 20 秒内恢复。请检查 journalctl -u docker。")


def _docker_config_as_object(raw_bytes=None):
    if raw_bytes is None:
        raw_bytes = _docker_read_config_bytes()
    if not raw_bytes:
        return {}
    obj = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Docker daemon.json 顶层必须是 JSON 对象")
    return obj


def _docker_validate_mirror_url(value, label="镜像源"):
    from urllib.parse import urlparse
    value = str(value or "").strip().rstrip("/")
    if not value:
        raise ValueError(f"请填写{label}地址")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{label}必须是有效的 HTTPS 地址，且不能包含账号、密码、查询参数或片段")
    if parsed.path not in ("", "/"):
        raise ValueError(f"{label}地址请填写到域名层级，不要附带路径")
    return value


@app.route("/api/docker/settings")
@login_required
def api_docker_settings():
    config_text = "{}\n"
    config_exists = os.path.exists(DOCKER_CONFIG_PATH)
    mirrors = []
    config_error = ""
    try:
        raw = _docker_read_config_bytes()
        if raw is not None:
            config_text = raw.decode("utf-8", errors="replace")
        obj = _docker_config_as_object(raw)
        value = obj.get("registry-mirrors", [])
        if isinstance(value, list): mirrors = [str(x) for x in value]
        elif value is not None: config_error = "daemon.json 中 registry-mirrors 不是数组"
    except Exception as e:
        config_error = f"配置文件解析失败：{e}"
    return jsonify(code=0, data={
        "installed": bool(shutil.which("docker")),
        "service": _docker_service_state(),
        "config_path": DOCKER_CONFIG_PATH,
        "config_exists": config_exists,
        "config_text": config_text,
        "mirrors": mirrors,
        "config_error": config_error,
        "presets": DOCKER_MIRROR_PRESETS,
    })


@app.route("/api/docker/service", methods=["POST"])
@login_required
def api_docker_service():
    d = request.get_json(silent=True) or {}
    action = str(d.get("action", "")).lower()
    cmds = {
        "start": ["enable", "--now", "docker"],
        "stop": ["stop", "docker"],
        "restart": ["restart", "docker"],
        "enable": ["enable", "docker"],
        "disable": ["disable", "docker"],
    }
    if action not in cmds:
        return jsonify(code=400, msg="不支持的 Docker 服务操作")
    if not shutil.which("docker") and action not in ("enable", "disable"):
        return jsonify(code=400, msg="未检测到 Docker CLI，请先安装 Docker Engine")
    code, out, err = _docker_systemctl(cmds[action], timeout=90)
    if code != 0:
        return jsonify(code=500, msg=(err or out or "Docker 服务操作失败").strip()[-3000:])
    state = _docker_service_state()
    labels = {"start": "Docker 服务已启动并设置为开机自启", "stop": "Docker 服务已停止",
              "restart": "Docker 服务已重启", "enable": "Docker 已设置为开机自启",
              "disable": "已取消 Docker 开机自启；当前运行中的服务不会自动停止"}
    log.info("Docker 服务操作：%s", action)
    return jsonify(code=0, msg=labels[action], data=state)


@app.route("/api/docker/mirror", methods=["POST"])
@login_required
def api_docker_mirror():
    d = request.get_json(silent=True) or {}
    source = str(d.get("source", "")).strip().lower()
    try:
        if source == "official":
            mirror_urls = []
        elif source == "aliyun":
            url = _docker_validate_mirror_url(d.get("url"), "阿里云加速器")
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
            if not host.endswith(".mirror.aliyuncs.com"):
                raise ValueError("阿里云源应填写控制台为你的账号生成的专属地址，例如 https://xxxx.mirror.aliyuncs.com")
            mirror_urls = [url]
        elif source == "ustc":
            raise ValueError("中国科大 USTC 的 Docker Hub 缓存目前已暂停服务，不能作为可用源启用；请选用公共源或自定义高校/单位源。")
        elif source in DOCKER_MIRROR_PRESETS:
            mirror_urls = [DOCKER_MIRROR_PRESETS[source]]
        elif source in ("custom", "school-custom"):
            mirror_urls = [_docker_validate_mirror_url(d.get("url"), "自定义镜像源")]
        else:
            raise ValueError("请选择有效的 Docker 镜像源")

        old = _docker_read_config_bytes()
        try:
            cfg = _docker_config_as_object(old)
        except Exception as e:
            raise ValueError(f"当前 daemon.json 无法解析，请先使用配置文件编辑器修复：{e}")
        if mirror_urls:
            cfg["registry-mirrors"] = mirror_urls
        else:
            cfg.pop("registry-mirrors", None)
        raw = (json.dumps(cfg, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        old_snapshot, backup_path = _docker_atomic_write_config(raw)
        try:
            restarted, detail = _docker_restart_if_active()
        except Exception as e:
            # If daemon fails to restart, put the previous config back and try to restore service.
            try: _docker_restore_config_bytes(old_snapshot)
            except Exception as rollback_error:
                raise RuntimeError(f"Docker 重启失败：{e}；配置回滚也失败：{rollback_error}")
            try: _docker_restart_if_active()
            except Exception: pass
            raise RuntimeError(f"Docker 重启失败，已尝试恢复原配置：{e}")
        chosen = mirror_urls[0] if mirror_urls else "Docker Hub 官方源（不配置加速器）"
        log.info("Docker 镜像源已修改为 %s", chosen)
        msg = f"已保存镜像源：{chosen}。{detail}"
        if backup_path: msg += f" 旧配置备份：{backup_path}"
        return jsonify(code=0, msg=msg, data={"mirrors": mirror_urls, "restarted": restarted})
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/mirror/test", methods=["POST"])
@login_required
def api_docker_mirror_test():
    from urllib.parse import urlparse
    d = request.get_json(silent=True) or {}
    try:
        raw_url = _docker_validate_mirror_url(d.get("url"), "镜像源")
        parsed = urlparse(raw_url)
        # Query only /v2/, which should answer with an HTTP status (often 401) if registry endpoint is reachable.
        result = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                                 "--max-time", "8", "--connect-timeout", "5", raw_url + "/v2/"],
                                capture_output=True, text=True, errors="replace", timeout=12)
        status = result.stdout.strip()
        if result.returncode == 0 and status and status != "000":
            ok = status in ("200", "401")
            message = f"镜像源 HTTPS 可连接，HTTP 状态码 {status}。" + ("可继续尝试拉取镜像。" if ok else "服务器可连接，但该状态码可能表示镜像源限制访问或未提供 Registry API。")
            return jsonify(code=0, msg=message, data={"ok": ok, "http_status": status, "url": raw_url})
        detail = (result.stderr or "连接失败或未收到 HTTP 响应").strip()
        return jsonify(code=0, msg=f"镜像源测试失败：{detail[-1200:]}", data={"ok": False, "http_status": status or "000", "url": raw_url})
    except Exception as e:
        return jsonify(code=400, msg=str(e), data={"ok": False})


@app.route("/api/docker/config", methods=["GET", "POST"])
@login_required
def api_docker_config():
    if request.method == "GET":
        try:
            raw = _docker_read_config_bytes()
            content = raw.decode("utf-8", errors="replace") if raw is not None else "{}\n"
            return jsonify(code=0, data={"path": DOCKER_CONFIG_PATH, "exists": raw is not None, "content": content})
        except Exception as e:
            return jsonify(code=500, msg=f"读取 Docker 配置失败：{e}")

    d = request.get_json(silent=True) or {}
    content = d.get("content", "")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 65536:
        return jsonify(code=400, msg="配置文件必须是字符串，且不能超过 64 KiB")
    try:
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("JSON 顶层必须是对象")
        old = _docker_read_config_bytes()
        old_snapshot, backup_path = _docker_atomic_write_config((json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        try:
            restarted, detail = _docker_restart_if_active()
        except Exception as e:
            try: _docker_restore_config_bytes(old_snapshot)
            except Exception as rollback_error:
                raise RuntimeError(f"Docker 重启失败：{e}；回滚失败：{rollback_error}")
            try: _docker_restart_if_active()
            except Exception: pass
            raise RuntimeError(f"Docker 重启失败，已恢复旧配置：{e}")
        msg = "Docker 配置已保存。" + detail
        if backup_path: msg += f" 旧配置备份：{backup_path}"
        return jsonify(code=0, msg=msg, data={"restarted": restarted, "content": json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"})
    except json.JSONDecodeError as e:
        return jsonify(code=400, msg=f"JSON 格式错误：第 {e.lineno} 行，第 {e.colno} 列：{e.msg}")
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=f"保存 Docker 配置失败：{e}")


@app.route("/api/docker/uninstall", methods=["POST"])
@login_required
def api_docker_uninstall():
    if os.geteuid() != 0:
        return jsonify(code=403, msg="卸载 Docker 需要面板以 root 权限运行")
    if not shutil.which("apt-get"):
        return jsonify(code=400, msg="一键卸载目前只支持通过 apt 安装的 Ubuntu/Debian 系统")
    try:
        q = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${binary:Package}\\n"],
                           capture_output=True, text=True, errors="replace", timeout=30)
        installed = []
        for line in q.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("ii"):
                pkg = parts[1].split(":", 1)[0]
                if pkg in DOCKER_KNOWN_PACKAGES:
                    installed.append(pkg)
        installed = sorted(set(installed))
        if not installed:
            return jsonify(code=400, msg="未找到通过 apt/dpkg 安装的 Docker Engine 软件包")
        # Stop known services; ignore missing unit files, but report package purge errors.
        _docker_systemctl(["disable", "--now", "docker.service"], timeout=45)
        _docker_systemctl(["disable", "--now", "docker.socket"], timeout=45)
        env = os.environ.copy(); env["DEBIAN_FRONTEND"] = "noninteractive"; env["APT_LISTCHANGES_FRONTEND"] = "none"
        p = subprocess.run(["apt-get", "purge", "-y", *installed], capture_output=True, text=True,
                           errors="replace", timeout=600, env=env)
        if p.returncode != 0:
            detail = (p.stderr or p.stdout or "apt-get purge 失败").strip()
            return jsonify(code=500, msg=detail[-5000:])
        log.warning("Docker 软件包已通过面板卸载：%s；未删除 /var/lib/docker 数据目录", ", ".join(installed))
        return jsonify(code=0, msg="Docker 软件包已卸载。为避免数据丢失，/var/lib/docker、镜像层和数据卷未主动删除。", data={"removed_packages": installed})
    except subprocess.TimeoutExpired:
        return jsonify(code=500, msg="卸载超时。请检查 apt/dpkg 是否仍在运行，再查看软件包状态。")
    except Exception as e:
        return jsonify(code=500, msg=f"卸载 Docker 失败：{e}")


@app.route("/api/docker/containers/<container_id>/inspect")
@login_required
def api_docker_container_inspect(container_id):
    try:
        cid = docker_validate_container_id(container_id)
        rows = json.loads(docker_require_ok(["inspect", cid], timeout=20))
        if not isinstance(rows, list) or not rows:
            return jsonify(code=404, msg="未找到该容器")
        return jsonify(code=0, data=rows[0])
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/containers/<container_id>/edit", methods=["POST"])
@login_required
def api_docker_container_edit(container_id):
    """Edit CPU/RAM limits; port changes recreate a container while preserving its writable layer."""
    try:
        cid = docker_validate_container_id(container_id)
        d = request.get_json(silent=True) or {}
        try:
            cpu = float(str(d.get("cpus", "0") or "0").strip())
            memory_mb = int(str(d.get("memory_mb", "0") or "0").strip())
        except (TypeError, ValueError):
            return jsonify(code=400, msg="CPU 或内存数值格式不正确")
        if not (0 <= cpu <= 256):
            return jsonify(code=400, msg="CPU 限制须为 0–256 核，0 表示不限制")
        if not (0 <= memory_mb <= 1048576):
            return jsonify(code=400, msg="内存限制须为 0–1048576 MiB，0 表示不限制")

        new_ports = []
        for raw in str(d.get("ports", "") or "").replace(",", "\n").splitlines():
            port = raw.strip()
            if not port:
                continue
            match = re.fullmatch(r"(?:(\[[0-9a-fA-F:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):)?(\d{1,5}):(\d{1,5})(?:/(tcp|udp))?", port, re.I)
            if not match or not (1 <= int(match.group(2)) <= 65535 and 1 <= int(match.group(3)) <= 65535):
                return jsonify(code=400, msg=f"端口映射格式不正确：{port}，示例：8080:80、5353:53/udp 或 127.0.0.1:8080:80")
            host_ip = (match.group(1) or "").strip("[]")
            if host_ip:
                try:
                    ipaddress.ip_address(host_ip)
                except ValueError:
                    return jsonify(code=400, msg=f"端口绑定 IP 地址不正确：{host_ip}")
            proto = (match.group(4) or "tcp").lower()
            new_ports.append((host_ip, int(match.group(2)), int(match.group(3)), proto))
        if len({(ip, hp, proto) for ip, hp, _cp, proto in new_ports}) != len(new_ports):
            return jsonify(code=400, msg="相同 IP、宿主机端口和协议不能重复")

        info_rows = json.loads(docker_require_ok(["inspect", cid], timeout=20))
        if not isinstance(info_rows, list) or not info_rows:
            return jsonify(code=404, msg="未找到该容器")
        info = info_rows[0]
        cfg = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        state = info.get("State") or {}
        old_name = str(info.get("Name") or "").lstrip("/")
        image_id = str(info.get("Image") or "")
        image_name = str(cfg.get("Image") or image_id)
        if not old_name:
            return jsonify(code=400, msg="无法读取容器名称")

        old_ports = []
        for target, bindings in (host.get("PortBindings") or {}).items():
            cport, _, proto = str(target).partition("/")
            for bind in bindings or []:
                hport = str((bind or {}).get("HostPort") or "").strip()
                host_ip = str((bind or {}).get("HostIp") or "").strip()
                if hport and hport.isdigit() and cport.isdigit():
                    old_ports.append((host_ip, int(hport), int(cport), (proto or "tcp").lower()))
        ports_changed = sorted(set(new_ports)) != sorted(set(old_ports))

        # Live resource update is safer and avoids downtime whenever published ports stay unchanged.
        if not ports_changed:
            args = ["update", f"--cpus={cpu:g}", f"--memory={memory_mb * 1024 * 1024}", cid]
            docker_require_ok(args, timeout=60)
            log.info("Docker 容器资源限制已修改：%s cpu=%s memory_mb=%s", old_name, cpu, memory_mb)
            return jsonify(code=0, msg="CPU 和内存限制已更新", data={"recreated": False})

        labels = cfg.get("Labels") or {}
        if labels.get("com.docker.compose.project"):
            return jsonify(code=400, msg="该容器由 Docker Compose 管理，本次没有修改任何配置。端口需要在原 Compose 配置文件中修改后重建，避免面板配置与 Compose 文件不一致；若仅修改 CPU/RAM，请先恢复原端口值并单独保存。")
        if host.get("AutoRemove"):
            return jsonify(code=400, msg="该容器设置了自动删除（--rm），停止时 Docker 会自动删除容器，因此不能通过本页安全重建修改端口。请先使用不带 --rm 的容器配置重新创建。")
        network_mode = str(host.get("NetworkMode") or "default")
        if network_mode in ("host", "container", "none") or network_mode.startswith("container:"):
            return jsonify(code=400, msg=f"当前网络模式 {network_mode} 不支持通过本页修改发布端口")
        if network_mode == "default":
            network_mode = "bridge"

        snapshot_tag = f"linux-panel-snapshot:{re.sub(r'[^A-Za-z0-9_.-]+', '-', old_name)[:48]}-{secrets.token_hex(4)}"
        backup_name = f"lp-backup-{secrets.token_hex(6)}"
        created_new = False
        renamed_old = False
        original_was_running = bool(state.get("Running"))
        snapshot_created = False
        try:
            # Snapshot filesystem changes in the writable layer before replacement; bind/volume data remains external.
            docker_require_ok(["commit", "--pause=true", cid, snapshot_tag], timeout=300)
            snapshot_created = True
            if state.get("Running"):
                docker_require_ok(["stop", "--time", "20", cid], timeout=45)
            docker_require_ok(["rename", cid, backup_name], timeout=30)
            renamed_old = True

            args = ["create", "--name", old_name]
            rp = host.get("RestartPolicy") or {}
            rp_name = str(rp.get("Name") or "no")
            retry = int(rp.get("MaximumRetryCount") or 0)
            if rp_name == "on-failure" and retry > 0:
                rp_name += ":" + str(retry)
            args += ["--restart", rp_name]
            args += ["--cpus", f"{cpu:g}", "--memory", str(memory_mb * 1024 * 1024)]
            if host.get("AutoRemove"):
                args.append("--rm")
            if cfg.get("Hostname"):
                args += ["--hostname", str(cfg["Hostname"])]
            if cfg.get("Domainname"):
                args += ["--domainname", str(cfg["Domainname"])]
            if cfg.get("User"):
                args += ["--user", str(cfg["User"])]
            if cfg.get("WorkingDir"):
                args += ["--workdir", str(cfg["WorkingDir"])]
            if cfg.get("OpenStdin"):
                args.append("-i")
            if cfg.get("Tty"):
                args.append("-t")
            if host.get("Privileged"):
                args.append("--privileged")
            if host.get("ReadonlyRootfs"):
                args.append("--read-only")
            if host.get("Init"):
                args.append("--init")
            if host.get("ShmSize"):
                args += ["--shm-size", str(int(host["ShmSize"]))]
            if network_mode:
                args += ["--network", network_mode]
            for env in cfg.get("Env") or []:
                if isinstance(env, str) and "=" in env:
                    args += ["--env", env]
            for key, value in (labels or {}).items():
                if str(key).startswith("com.docker.compose."):
                    continue
                args += ["--label", f"{key}={value}"]
            for cap in host.get("CapAdd") or []:
                args += ["--cap-add", str(cap)]
            for cap in host.get("CapDrop") or []:
                args += ["--cap-drop", str(cap)]
            for device in host.get("Devices") or []:
                source = str(device.get("PathOnHost") or "")
                dest = str(device.get("PathInContainer") or source)
                perm = str(device.get("CgroupPermissions") or "rwm")
                if source:
                    args += ["--device", f"{source}:{dest}:{perm}"]
            for dns in host.get("Dns") or []:
                args += ["--dns", str(dns)]
            for item in host.get("DnsSearch") or []:
                args += ["--dns-search", str(item)]
            for item in host.get("ExtraHosts") or []:
                args += ["--add-host", str(item)]
            for item in host.get("SecurityOpt") or []:
                args += ["--security-opt", str(item)]
            for item in host.get("GroupAdd") or []:
                args += ["--group-add", str(item)]
            for key, value in (host.get("Tmpfs") or {}).items():
                args += ["--tmpfs", f"{key}:{value}" if value else str(key)]
            for item in host.get("VolumesFrom") or []:
                args += ["--volumes-from", str(item)]
            for bind in host.get("Binds") or []:
                args += ["--volume", str(bind)]
            # Preserve named/anonymous volumes and bind mounts from inspect, avoiding duplicates already in HostConfig.Binds.
            known_dests = set()
            for bind in host.get("Binds") or []:
                bits = str(bind).split(":")
                if len(bits) >= 2:
                    known_dests.add(bits[1])
            for mount in info.get("Mounts") or []:
                dest = str(mount.get("Destination") or "")
                if not dest or dest in known_dests or mount.get("Type") == "tmpfs":
                    continue
                src = str(mount.get("Source") or mount.get("Name") or "")
                if not src:
                    continue
                mode = "ro" if mount.get("RW") is False else "rw"
                args += ["--volume", f"{src}:{dest}:{mode}"]
                known_dests.add(dest)
            for target, bindings in (cfg.get("ExposedPorts") or {}).items():
                if "/" in str(target):
                    args += ["--expose", str(target)]
            for host_ip, host_port, container_port, proto in new_ports:
                if host_ip:
                    host_part = f"[{host_ip}]" if ":" in host_ip else host_ip
                    binding = f"{host_part}:{host_port}:{container_port}/{proto}"
                else:
                    binding = f"{host_port}:{container_port}/{proto}"
                args += ["--publish", binding]

            entrypoint = cfg.get("Entrypoint")
            cmd = cfg.get("Cmd") or []
            if isinstance(entrypoint, str):
                entrypoint = [entrypoint]
            if entrypoint:
                args += ["--entrypoint", str(entrypoint[0])]
                cmd = list(entrypoint[1:]) + list(cmd)
            args.append(snapshot_tag)
            if isinstance(cmd, list):
                args.extend(str(part) for part in cmd)
            elif cmd:
                args.append(str(cmd))
            docker_require_ok(args, timeout=120)
            created_new = True
            docker_require_ok(["start", old_name], timeout=90)
            # Reattach additional user-defined networks after preserving the primary network.
            network_rows = ((info.get("NetworkSettings") or {}).get("Networks") or {})
            for net_name, net_cfg in network_rows.items():
                if net_name == network_mode or net_name == "bridge" and network_mode == "bridge":
                    continue
                connect_args = ["network", "connect"]
                for alias in (net_cfg or {}).get("Aliases") or []:
                    if alias and alias != old_name and alias != cid[:12]:
                        connect_args += ["--alias", str(alias)]
                connect_args += [str(net_name), old_name]
                docker_require_ok(connect_args, timeout=45)
            # Keep the snapshot image: it contains the old writable layer and is now the replacement container's base.
            docker_require_ok(["rm", "-f", backup_name], timeout=60)
            renamed_old = False
            log.warning("Docker 容器 %s 因端口修改而重建；可写层快照保留为 %s", old_name, snapshot_tag)
            return jsonify(code=0, msg=f"容器已重建并应用端口配置。为保护原容器可写层，已保留快照镜像 {snapshot_tag}；挂载目录/数据卷保持不变。", data={"recreated": True, "snapshot_image": snapshot_tag})
        except Exception:
            # Best effort rollback to the original named container if replacement failed.
            if created_new:
                docker_command(["rm", "-f", old_name], timeout=45)
            if renamed_old:
                docker_command(["rename", backup_name, old_name], timeout=30)
                if original_was_running:
                    docker_command(["start", old_name], timeout=90)
            elif original_was_running:
                docker_command(["start", cid], timeout=90)
            raise
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=f"编辑容器失败：{e}")


@app.route("/api/docker/containers/<container_id>/backup")
@login_required
def api_docker_container_backup(container_id):
    try:
        cid = docker_validate_container_id(container_id)
        name = str(request.args.get("name", "container")).strip()
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:80] or "container"
        fd, archive_path = tempfile.mkstemp(prefix="docker-export-", suffix=".tar", dir=DATA_DIR)
        os.close(fd)
        try:
            docker_require_ok(["export", "-o", archive_path, cid], timeout=1800)
            response = send_file(archive_path, mimetype="application/x-tar", as_attachment=True,
                                 download_name=f"{name}-filesystem.tar", conditional=True)
            response.call_on_close(lambda: os.path.exists(archive_path) and os.unlink(archive_path))
            return response
        except Exception:
            try: os.unlink(archive_path)
            except OSError: pass
            raise
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=f"备份失败：{e}")


@app.route("/api/docker/containers/<container_id>/rebuild", methods=["POST"])
@login_required
def api_docker_container_rebuild(container_id):
    try:
        cid = docker_validate_container_id(container_id)
        raw = docker_require_ok(["inspect", cid], timeout=20)
        rows = json.loads(raw)
        info = rows[0] if isinstance(rows, list) and rows else {}
        labels = ((info.get("Config") or {}).get("Labels") or {})
        workdir = str(labels.get("com.docker.compose.project.working_dir") or "")
        service = str(labels.get("com.docker.compose.service") or "")
        config_files_raw = str(labels.get("com.docker.compose.project.config_files") or "")
        if not workdir or not service or not config_files_raw:
            return jsonify(code=400, msg="该容器不是由 Docker Compose 创建的，面板无法安全地自动重建；可先查看详情或重新配置后创建新容器。")
        if not os.path.isdir(workdir):
            return jsonify(code=400, msg=f"Compose 工作目录不存在：{workdir}")
        config_files = [os.path.realpath(x.strip()) for x in config_files_raw.split(",") if x.strip()]
        if not config_files or any(not os.path.isfile(x) for x in config_files):
            return jsonify(code=400, msg="找不到容器原先使用的 Compose 配置文件，无法重建")
        docker_bin = shutil.which("docker")
        args = [docker_bin, "compose", "--project-directory", workdir]
        for cf in config_files: args += ["-f", cf]
        args += ["up", "-d", "--no-deps", "--force-recreate", service]
        p = subprocess.run(args, cwd=workdir, capture_output=True, text=True, errors="replace", timeout=600)
        if p.returncode != 0:
            return jsonify(code=500, msg=(p.stderr or p.stdout or "Compose 重建失败").strip()[-5000:])
        return jsonify(code=0, msg=f"Compose 服务 {service} 已重建", data={"output": p.stdout[-3000:]})
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except subprocess.TimeoutExpired:
        return jsonify(code=500, msg="重建操作超时，请检查 docker compose 状态")
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/containers")
@login_required
def api_docker_containers():
    try:
        rows = docker_json_lines(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
        labels_by_id = {}
        for row in rows:
            labels_text = str(row.get("Labels") or "")
            labels = {}
            for item in labels_text.split(","):
                key, sep, value = item.partition("=")
                if sep:
                    labels[key.strip()] = value.strip()
            labels_by_id[str(row.get("ID") or "")] = labels
            row["AccessDomain"] = labels.get("com.hia1321.linux-panel.access-domain", "")
            row["AccessPort"] = labels.get("com.hia1321.linux-panel.access-port", "")
            row["WorkDirPanelPath"] = ""
            row["MountPanelPath"] = ""
            row["MountCount"] = 0
        # Inspect all listed containers once to obtain host-side project and mount paths.
        ids = [str(row.get("ID") or "") for row in rows if re.fullmatch(r"[a-fA-F0-9]{12,64}", str(row.get("ID") or ""))]
        if ids:
            code, inspect_out, _inspect_err = docker_command(["inspect", *ids], timeout=35)
            if code == 0:
                try:
                    inspected = json.loads(inspect_out)
                except json.JSONDecodeError:
                    inspected = []
                rows_by_id = {str(row.get("ID") or ""): row for row in rows}
                rows_by_id.update({str(row.get("ID") or "").lower(): row for row in rows})
                for info in inspected if isinstance(inspected, list) else []:
                    iid = str(info.get("Id") or "")
                    row = rows_by_id.get(iid) or rows_by_id.get(iid.lower())
                    if not row:
                        continue
                    info_labels = ((info.get("Config") or {}).get("Labels") or {})
                    compose_dir = str(info_labels.get("com.docker.compose.project.working_dir") or "")
                    custom_dir = str(info_labels.get("com.hia1321.linux-panel.run-dir") or "")
                    run_dir = compose_dir or custom_dir
                    mounts = info.get("Mounts") or []
                    host_mounts = [str(m.get("Source") or "") for m in mounts
                                   if m.get("Source") and m.get("Type") in ("bind", "volume")]
                    row["MountCount"] = len(host_mounts)
                    row["WorkDirPanelPath"] = _docker_path_relative_to_file_root(run_dir)
                    row["MountPanelPath"] = _docker_path_relative_to_file_root(host_mounts[0]) if host_mounts else ""
                    row["WorkDirDisplay"] = run_dir
                    row["MountDisplay"] = host_mounts[0] if host_mounts else ""
        # Pending creates appear as cards immediately, and failed creates remain visible until dismissed.
        with _docker_pull_state_lock:
            task_rows = list(_docker_pull_tasks.values())
        for task in task_rows:
            if task.get("kind") != "container-create" or task.get("dismissed"):
                continue
            if task.get("done") and task.get("success"):
                continue
            state = "failed" if task.get("done") and not task.get("success") else "installing"
            rows.append({
                "ID": "", "Names": task.get("container_name", ""),
                "Image": task.get("container_image", ""), "Ports": task.get("container_ports", ""),
                "State": state, "Status": task.get("message", "安装中"),
                "RunningFor": "", "CreatedAt": "", "Pending": True,
                "PendingTaskId": task.get("task_id", ""),
                "PendingPercent": int(task.get("percent", 0) or 0),
                "PendingStage": task.get("stage", "安装中"),
                "PendingMessage": task.get("message", ""),
            })
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/containers/<container_id>/action", methods=["POST"])
@login_required
def api_docker_container_action(container_id):
    try:
        cid = docker_validate_container_id(container_id)
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    d = request.get_json(silent=True) or {}
    action = str(d.get("action", "")).lower()
    commands = {"start": "start", "stop": "stop", "restart": "restart",
                "pause": "pause", "unpause": "unpause"}
    if action == "remove":
        try:
            # The UI always asks for confirmation before removal; -f also stops a running container.
            docker_require_ok(["rm", "-f", cid], timeout=60)
            return jsonify(code=0, msg="容器已卸载（容器可写层已删除，挂载目录和数据卷保留）")
        except Exception as e:
            return jsonify(code=500, msg=str(e))
    if action not in commands:
        return jsonify(code=400, msg="不支持的容器操作")
    timeout = 90 if action in ("stop", "restart") else 30
    try:
        docker_require_ok([commands[action], cid], timeout=timeout)
        labels = {"start": "已启动", "stop": "已停止", "restart": "已重启",
                  "pause": "已暂停", "unpause": "已恢复"}
        return jsonify(code=0, msg=labels[action])
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/containers/<container_id>/logs")
@login_required
def api_docker_container_logs(container_id):
    try:
        cid = docker_validate_container_id(container_id)
        tail = _safe_int(request.args.get("tail"), 200, 1, 1000)
        # Docker logs 返回的 stdout 与 stderr 都展示在面板中。
        code, out, err = docker_command(["logs", "--timestamps", "--tail", str(tail), cid], timeout=20)
        text = out + (("\n" if out and err else "") + err)
        if code != 0:
            return jsonify(code=500, msg=(text or "读取容器日志失败")[-5000:])
        return jsonify(code=0, data={"logs": text[-200000:], "tail": tail})
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/containers/run", methods=["POST"])
@login_required
def api_docker_container_run():
    """Create a pending task immediately; missing images are pulled in a background worker."""
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()
    image = str(d.get("image", "")).strip()
    if not DOCKER_NAME_RE.fullmatch(name):
        return jsonify(code=400, msg="容器名称只允许字母、数字、点、下划线和连字符，且不能以符号开头")
    if not DOCKER_IMAGE_RE.fullmatch(image):
        return jsonify(code=400, msg="镜像名称格式不正确")

    restart = str(d.get("restart", "unless-stopped"))
    if restart not in ("no", "always", "unless-stopped", "on-failure"):
        return jsonify(code=400, msg="重启策略不正确")

    args = ["run", "-d", "--name", name, "--restart", restart]
    raw_ports = str(d.get("ports", "") or "")
    normalized_ports = []
    for item in raw_ports.replace(",", "\n").splitlines():
        port = item.strip()
        if not port:
            continue
        m = re.fullmatch(r"(\d{1,5}):(\d{1,5})(?:/(tcp|udp))?", port)
        if not m or not (1 <= int(m.group(1)) <= 65535 and 1 <= int(m.group(2)) <= 65535):
            return jsonify(code=400, msg=f"端口映射格式不正确：{port}，示例：8080:80 或 5353:53/udp")
        args += ["-p", port]
        protocol = (m.group(3) or "tcp").lower()
        normalized_ports.append(f"0.0.0.0:{m.group(1)}->{m.group(2)}/{protocol}")

    raw_volumes = str(d.get("volumes", "") or "")
    for item in raw_volumes.replace(",", "\n").splitlines():
        mount = item.strip()
        if not mount:
            continue
        parts = mount.split(":")
        if len(parts) not in (2, 3) or not parts[0].startswith("/") or not parts[1].startswith("/"):
            return jsonify(code=400, msg=f"挂载格式不正确：{mount}，示例：/宿主机绝对路径:/容器路径 或 /路径:/路径:ro")
        if len(parts) == 3 and parts[2] not in ("ro", "rw"):
            return jsonify(code=400, msg=f"挂载权限只能是 ro 或 rw：{mount}")
        if any(p in ("..", ".") for p in parts[0].split("/") if p):
            return jsonify(code=400, msg=f"宿主机挂载路径不允许包含 . 或 ..：{mount}")
        args += ["-v", mount]

    raw_env = str(d.get("env", "") or "")
    for item in raw_env.splitlines():
        entry = item.strip()
        if not entry:
            continue
        if "=" not in entry:
            return jsonify(code=400, msg=f"环境变量格式不正确：{entry}，请使用 KEY=VALUE")
        key, val = entry.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or "\x00" in val:
            return jsonify(code=400, msg=f"环境变量格式不正确：{entry}")
        args += ["-e", f"{key}={val}"]

    # Avoid starting an expensive image pull for a name that is already occupied.
    code, _out, _err = docker_command(["container", "inspect", name], timeout=10)
    if code == 0:
        return jsonify(code=409, msg=f"容器名称「{name}」已被占用，请先启动、重命名或移除现有容器。")

    args.append(image)
    try:
        task_id = _docker_pull_start(image, create_container={
            "args": args, "name": name, "image": image,
            "ports": ", ".join(normalized_ports),
        })
        return jsonify(code=0, msg="容器创建任务已提交，后台将检查镜像并创建容器", data={
            "task_id": task_id, "kind": "container-create", "name": name,
            "container_name": name, "image": image, "container_image": image,
            "ports": ", ".join(normalized_ports), "container_ports": ", ".join(normalized_ports),
            "stage": "排队中", "running": True, "done": False, "success": False,
            "percent": 1, "logs": [], "message": "正在准备容器创建任务", "updated_at": time.time()
        })
    except RuntimeError as e:
        return jsonify(code=409, msg=str(e))


@app.route("/api/docker/images")
@login_required
def api_docker_images():
    try:
        rows = docker_json_lines(["image", "ls", "--no-trunc", "--format", "{{json .}}"])
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


_docker_pull_state_lock = threading.Lock()
_docker_pull_tasks = {}
_DOCKER_PULL_TASK_LIMIT = 24

def _docker_pull_update(task_id, **changes):
    with _docker_pull_state_lock:
        state = _docker_pull_tasks.get(task_id)
        if not state:
            return
        for key, value in changes.items():
            if key == "log_line":
                logs = state.setdefault("logs", [])
                logs.append(str(value)[-1200:])
                del logs[:-160]
            elif key == "percent":
                state[key] = max(int(state.get("percent", 0) or 0), max(0, min(100, int(value or 0))))
            else:
                state[key] = value
        state["updated_at"] = time.time()


def _docker_pull_snapshot(task_id):
    with _docker_pull_state_lock:
        state = _docker_pull_tasks.get(task_id)
        if not state:
            return None
        # Never return the internal docker run argv (it may contain environment values).
        return {k: (list(v) if k == "logs" else v) for k, v in state.items()
                if k not in ("container_args", "_process")}


@app.route("/api/docker/tasks")
@login_required
def api_docker_tasks():
    with _docker_pull_state_lock:
        rows = sorted(_docker_pull_tasks.values(), key=lambda item: item.get("updated_at", 0), reverse=True)
        safe_rows = [{k: (list(v) if k == "logs" else v) for k, v in row.items()
                      if k not in ("container_args", "_process")} for row in rows[:24] if not row.get("dismissed")]
    return jsonify(code=0, data=safe_rows)


@app.route("/api/docker/tasks/<task_id>/dismiss", methods=["POST"])
@login_required
def api_docker_task_dismiss(task_id):
    if not re.fullmatch(r"[a-f0-9]{32}", str(task_id or "")):
        return jsonify(code=400, msg="任务 ID 不正确")
    with _docker_pull_state_lock:
        state = _docker_pull_tasks.get(task_id)
        if not state:
            return jsonify(code=404, msg="任务不存在或已过期")
        if state.get("running"):
            return jsonify(code=409, msg="任务仍在运行，不能清除")
        state["dismissed"] = True
        state["updated_at"] = time.time()
    return jsonify(code=0, msg="任务记录已清除")


@app.route("/api/docker/tasks/<task_id>/cancel", methods=["POST"])
@login_required
def api_docker_task_cancel(task_id):
    if not re.fullmatch(r"[a-f0-9]{32}", str(task_id or "")):
        return jsonify(code=400, msg="任务 ID 不正确")
    with _docker_pull_state_lock:
        state = _docker_pull_tasks.get(task_id)
        if not state:
            return jsonify(code=404, msg="任务不存在或已过期")
        if not state.get("running"):
            return jsonify(code=409, msg="任务已经结束")
        state["cancel_requested"] = True
        proc = state.get("_process")
        state["stage"] = "正在停止"
        state["message"] = "已请求停止镜像拉取，正在终止 Docker 进程…"
        state["updated_at"] = time.time()
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
    return jsonify(code=0, msg="已发送停止请求")


def _docker_pull_prune_locked():
    if len(_docker_pull_tasks) <= _DOCKER_PULL_TASK_LIMIT:
        return
    completed = sorted(
        ((tid, st.get("updated_at", 0)) for tid, st in _docker_pull_tasks.items() if st.get("done")),
        key=lambda item: item[1]
    )
    for tid, _ in completed[:max(0, len(_docker_pull_tasks) - _DOCKER_PULL_TASK_LIMIT)]:
        _docker_pull_tasks.pop(tid, None)


def _docker_pull_start(image, *, create_container=None):
    task_id = secrets.token_hex(16)
    kind = "container-create" if create_container else "pull"
    state = {
        "task_id": task_id, "kind": kind, "image": image,
        "container_name": create_container.get("name", "") if create_container else "",
        "container_image": create_container.get("image", image) if create_container else image,
        "container_ports": create_container.get("ports", "") if create_container else "",
        "running": True, "done": False, "success": False,
        "percent": 1, "stage": "准备任务", "message": f"正在准备处理：{image}",
        "logs": [], "result": "", "updated_at": time.time(), "dismissed": False
    }
    with _docker_pull_state_lock:
        _docker_pull_tasks[task_id] = state
        _docker_pull_prune_locked()
    threading.Thread(target=_docker_pull_worker,
                     args=(task_id, image, create_container), daemon=True,
                     name="docker-task-" + task_id[:8]).start()
    return task_id


def _docker_pull_stream(task_id, image, binary):
    """Stream Docker pull output (including carriage-return progress) into task state."""
    import queue
    layer_stats = {}
    _docker_pull_update(task_id, stage="拉取镜像", message=f"正在连接镜像仓库：{image}", percent=2,
                        log_line=f"$ docker pull {image}")
    proc = subprocess.Popen([binary, "pull", image], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    with _docker_pull_state_lock:
        state = _docker_pull_tasks.get(task_id)
        if state is not None:
            state["_process"] = proc
    chunks = queue.Queue()

    def reader():
        try:
            while True:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                chunks.put(chunk)
        except OSError as exc:
            chunks.put(("__reader_error__", str(exc)))
        finally:
            chunks.put(None)

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    deadline = time.monotonic() + 1800
    pending = ""
    stream_closed = False
    last_line = ""
    unit_scale = {"B": 1, "kB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
                  "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    byte_pattern = re.compile(r"([\d.]+)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)\s*/\s*([\d.]+)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)")

    def report_line(line):
        nonlocal last_line
        line = line.strip()
        if not line:
            return
        last_line = line
        layer_match = re.match(r"^([a-fA-F0-9]{6,})\s*:\s*(.*)$", line)
        if layer_match:
            lid, detail = layer_match.group(1), layer_match.group(2)
            stats = layer_stats.setdefault(lid, {"current": 0, "total": 0, "done": False})
            if any(token in detail.lower() for token in ("download complete", "pull complete", "already exists", "already present")):
                stats["done"] = True
                if stats.get("total"):
                    stats["current"] = stats["total"]
            match = byte_pattern.search(detail)
            if match:
                try:
                    stats["current"] = max(0, float(match.group(1)) * unit_scale[match.group(2)])
                    stats["total"] = max(0, float(match.group(3)) * unit_scale[match.group(4)])
                except (ValueError, KeyError):
                    pass
        known = [st for st in layer_stats.values() if st.get("total", 0) > 0]
        if known:
            total_bytes = sum(st["total"] for st in known)
            current_bytes = sum(min(st["total"], st["current"]) for st in known)
            pct = min(96, max(2, int(current_bytes / total_bytes * 96))) if total_bytes else 2
        elif layer_stats:
            done_count = sum(1 for st in layer_stats.values() if st.get("done"))
            pct = min(90, 2 + int(done_count / max(1, len(layer_stats)) * 80))
        else:
            pct = 2
        _docker_pull_update(task_id, percent=pct, message=line[-400:], log_line=line, updated_at=time.time())

    while True:
        with _docker_pull_state_lock:
            current_state = _docker_pull_tasks.get(task_id, {})
            cancel_requested = bool(current_state.get("cancel_requested"))
        if cancel_requested:
            if proc.poll() is None:
                try: proc.terminate()
                except OSError: pass
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try: proc.kill()
                    except OSError: pass
                    try: proc.wait(timeout=3)
                    except Exception: pass
            raise RuntimeError("用户已停止镜像拉取")
        if time.monotonic() > deadline:
            try: proc.kill()
            except OSError: pass
            try: proc.wait(timeout=3)
            except Exception: pass
            raise RuntimeError("镜像拉取超过 30 分钟仍未完成，请检查网络或镜像源。")
        try:
            item = chunks.get(timeout=0.25)
            if item is None:
                stream_closed = True
            elif isinstance(item, tuple) and item[0] == "__reader_error__":
                report_line("读取 Docker 输出失败：" + item[1])
            else:
                pending += item.decode("utf-8", errors="replace")
                pieces = re.split(r"[\r\n]", pending)
                pending = pieces.pop() if pieces else ""
                for piece in pieces:
                    report_line(piece)
        except queue.Empty:
            pass
        if proc.poll() is not None and stream_closed:
            break
    if pending.strip():
        report_line(pending)
    reader_thread.join(timeout=1)
    rc = proc.wait()
    if rc != 0:
        raise RuntimeError((last_line or f"docker pull 失败，退出码 {rc}")[-1800:])
    _docker_pull_update(task_id, stage="镜像下载完成", percent=96,
                        message="镜像层已下载", log_line="镜像拉取命令已完成", updated_at=time.time())


def _docker_pull_worker(task_id, image, create_container=None):
    try:
        binary = shutil.which("docker")
        if not binary:
            raise RuntimeError("未检测到 Docker CLI，请先安装 Docker Engine。")

        needs_pull = True
        if create_container:
            _docker_pull_update(task_id, stage="检查本地镜像", percent=5,
                                message=f"正在检查本地是否已有镜像：{image}",
                                log_line=f"$ docker image inspect {image}", updated_at=time.time())
            code, out, err = docker_command(["image", "inspect", image], timeout=15)
            if code == 0:
                needs_pull = False
                _docker_pull_update(task_id, stage="使用本地镜像", percent=88,
                                    message="本地镜像已存在，跳过下载，准备创建容器",
                                    log_line="检测到本地镜像，跳过 docker pull", updated_at=time.time())

        if needs_pull:
            _docker_pull_stream(task_id, image, binary)

        if create_container:
            name = create_container["name"]
            _docker_pull_update(task_id, stage="创建容器", percent=97,
                                message=f"镜像已就绪，正在创建容器：{name}",
                                log_line="$ docker run -d --name " + name + " ...", updated_at=time.time())
            out = docker_require_ok(create_container["args"], timeout=300)
            container_id = out.strip()
            result = f"容器已创建并启动：{name}（{container_id[:12]}）"
            _docker_pull_update(task_id, stage="容器启动完成", percent=100, message=result,
                                log_line=result, updated_at=time.time())
        else:
            result = f"镜像拉取成功：{image}"
            _docker_pull_update(task_id, stage="拉取完成", percent=100,
                                message=result, log_line=result, updated_at=time.time())

        with _docker_pull_state_lock:
            current_state = _docker_pull_tasks.get(task_id, {})
            current_state.pop("_process", None)
        _docker_pull_update(task_id, running=False, done=True, success=True, result=result,
                            updated_at=time.time())
    except Exception as exc:
        err = str(exc)
        with _docker_pull_state_lock:
            current_state = _docker_pull_tasks.get(task_id, {})
            cancelled = bool(current_state.get("cancel_requested"))
            current_state.pop("_process", None)
        if not cancelled:
            log.error("Docker background task failed (%s): %s", task_id, err)
        _docker_pull_update(task_id, running=False, done=True, success=False,
                            cancelled=cancelled, stage=("已停止" if cancelled else "执行失败"),
                            message=("镜像拉取已停止" if cancelled else err), result=("镜像拉取已停止" if cancelled else err),
                            log_line=("已由用户停止任务" if cancelled else "错误：" + err), updated_at=time.time())


@app.route("/api/docker/images/pull", methods=["POST"])
@login_required
def api_docker_image_pull():
    d = request.get_json(silent=True) or {}
    image = str(d.get("image", "")).strip()
    if not DOCKER_IMAGE_RE.fullmatch(image):
        return jsonify(code=400, msg="镜像名称格式不正确，例如 nginx:alpine 或 redis:7")
    try:
        task_id = _docker_pull_start(image)
        return jsonify(code=0, msg="镜像拉取任务已在后台启动", data=_docker_pull_snapshot(task_id))
    except RuntimeError as e:
        return jsonify(code=409, msg=str(e))


@app.route("/api/docker/images/pull/status")
@login_required
def api_docker_image_pull_status():
    task_id = str(request.args.get("task_id", "")).strip()
    if not re.fullmatch(r"[a-f0-9]{32}", task_id):
        return jsonify(code=400, msg="拉取任务 ID 不正确")
    state = _docker_pull_snapshot(task_id)
    if not state:
        return jsonify(code=404, msg="拉取任务不存在或已过期，请重新操作")
    return jsonify(code=0, data=state)


@app.route("/api/docker/images/<path:image_id>/delete", methods=["POST"])
@login_required
def api_docker_image_delete(image_id):
    image_id = str(image_id or "").strip()
    if not re.fullmatch(r"sha256:[a-fA-F0-9]{64}|[a-fA-F0-9]{12,64}", image_id):
        return jsonify(code=400, msg="镜像 ID 格式不正确")
    try:
        docker_require_ok(["image", "rm", image_id], timeout=60)
        return jsonify(code=0, msg="镜像已删除")
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/networks")
@login_required
def api_docker_networks():
    try:
        rows = docker_json_lines(["network", "ls", "--no-trunc", "--format", "{{json .}}"])
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/networks/<name>/delete", methods=["POST"])
@login_required
def api_docker_network_delete(name):
    try:
        name = docker_validate_named_resource(name, "网络")
        docker_require_ok(["network", "rm", name], timeout=30)
        return jsonify(code=0, msg="网络已删除")
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/volumes")
@login_required
def api_docker_volumes():
    try:
        rows = docker_json_lines(["volume", "ls", "--format", "{{json .}}"])
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@app.route("/api/docker/volumes/<name>/delete", methods=["POST"])
@login_required
def api_docker_volume_delete(name):
    try:
        name = docker_validate_named_resource(name, "数据卷")
        docker_require_ok(["volume", "rm", name], timeout=30)
        return jsonify(code=0, msg="数据卷已删除")
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


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
<link rel="icon" type="image/x-icon" href="https://myec.hia1321.cn/icon/favicon.ico">
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
html,body{margin:0;height:100%;color:var(--text);
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
  <p class="sub">文件管理 · SSH 管理 · Web 终端 · 计划任务 · 防火墙 · Docker 管理</p>
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
<link rel="icon" type="image/x-icon" href="https://myec.hia1321.cn/icon/favicon.ico">
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
.browser-bar input.search-box{width:240px;min-width:240px;max-width:240px;flex:0 0 240px;
  padding:9px 12px 9px 34px;background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%238b95a7' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='11' cy='11' r='8'/><path d='m21 21-4.35-4.35'/></svg>");
  background-repeat:no-repeat;background-position:10px center;
  transition:border-color .15s,box-shadow .15s,background-color .35s}
.browser-bar input.search-box:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}

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

/* 计划任务样式 */
.schedule-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:4px 0}
.schedule-row select.mini,
.schedule-row input.mini{width:auto;padding:6px 8px;font-size:13px}
.schedule-row select.mini{min-width:70px}
.schedule-row input[type=number].mini{width:80px;text-align:center}
.schedule-row span{color:var(--muted);font-size:13px}
.schedule-params{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.cron-script-area{width:100%;font-family:ui-monospace,Menlo,Consolas,"Courier New",monospace;
  font-size:12px;line-height:1.6;resize:vertical;min-height:280px}
.cron-log-area{width:100%;height:60vh;font-family:ui-monospace,Menlo,Consolas,"Courier New",monospace;
  font-size:12px;line-height:1.5;resize:vertical;white-space:pre;overflow:auto;background:#0b0e13;color:#d7dce5}
html.light .cron-log-area{background:#fbf7ec;color:#3a3225}
.cron-type-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;
  background:rgba(59,130,246,.15);color:var(--accent);border:1px solid rgba(59,130,246,.35)}
.cron-type-tag.py{background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)}
.cron-toggle{position:relative;display:inline-block;width:36px;height:20px;cursor:pointer}
.cron-toggle input{opacity:0;width:0;height:0}
.cron-toggle .slider{position:absolute;inset:0;background:var(--panel-3);border-radius:20px;transition:.3s}
.cron-toggle .slider:before{position:absolute;content:"";height:14px;width:14px;left:3px;bottom:3px;
  background:#fff;border-radius:50%;transition:.3s}
.cron-toggle input:checked + .slider{background:var(--accent)}
.cron-toggle input:checked + .slider:before{transform:translateX(16px)}

.modal{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.5);display:flex;align-items:center;
  justify-content:center;padding:24px;backdrop-filter:blur(4px);animation:fadeIn .2s ease-out}
.modal[hidden]{display:none}
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
.cron-form-box{max-width:820px;max-height:92vh}
.cron-log-box{max-width:1000px;max-height:92vh}
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
  #docker-stats{grid-template-columns:repeat(2,minmax(0,1fr)) !important}
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

/* Docker Manager cards and settings */
.docker-container-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,360px),400px));gap:14px;align-items:start}
.docker-container-card{border:1px solid var(--border);border-radius:10px;padding:14px;background:var(--panel);box-shadow:0 2px 8px rgba(0,0,0,.035);min-width:0;width:100%;max-width:400px;box-sizing:border-box;display:flex;flex-direction:column;gap:0}
.docker-container-card:hover{border-color:color-mix(in srgb,var(--accent) 40%,var(--border))}
.docker-container-main{display:flex;gap:14px;align-items:flex-start;min-width:0}
.docker-app-icon{width:54px;height:54px;min-width:54px;display:flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:50%;font-weight:700;font-size:12px;letter-spacing:.2px;color:var(--text);background:var(--panel-2);box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.docker-container-copy{flex:1;min-width:0}
.docker-container-title{display:flex;align-items:center;gap:8px;flex-wrap:nowrap;min-width:0;white-space:nowrap;overflow:hidden}
.docker-container-title .docker-container-name{flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.docker-container-title .docker-container-shortcuts{flex:0 0 auto}
.docker-container-name{font-size:15px;font-weight:650;overflow-wrap:anywhere;max-width:100%}
.docker-container-shortcuts{display:flex;gap:4px;margin-left:2px}
.docker-container-shortcuts button{width:30px;height:28px;padding:4px;margin:0;display:inline-flex;align-items:center;justify-content:center;background:transparent;color:var(--muted);border:1px solid transparent}
.docker-container-shortcuts button:hover{background:var(--panel-2);color:var(--text);box-shadow:none;border-color:var(--border)}
.docker-container-shortcuts svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.docker-container-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:9px;min-width:0;white-space:normal;overflow:visible}
.docker-container-meta>.docker-meta-chip{flex:0 1 auto;min-width:0;max-width:100%;white-space:normal;overflow-wrap:anywhere;text-overflow:clip}
.docker-container-meta .docker-port-dropdown{flex:0 0 auto;max-width:100%}
.docker-meta-chip{display:inline-flex;align-items:center;gap:4px;padding:4px 7px;border-radius:5px;background:var(--panel-2);border:1px solid var(--border);font-size:11px;line-height:1.35;color:var(--muted);max-width:100%;min-width:0;overflow:hidden;text-overflow:ellipsis;overflow-wrap:anywhere}
.docker-image-ref-chip{max-width:min(100%,180px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.docker-image-tag-chip{color:var(--text);white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis}
.docker-port-link{white-space:nowrap;flex:0 0 auto}
.docker-container-footer{display:flex;gap:5px;align-items:center;flex-wrap:nowrap;white-space:nowrap;overflow:visible;border-top:1px solid var(--border);margin-top:12px;padding-top:10px;min-width:0}
.docker-container-footer>.btn{flex:0 0 auto;min-width:0}
.docker-container-footer .spacer{flex:1;min-width:0}
.docker-container-footer .btn{min-width:0;padding:6px 7px;font-size:12px;white-space:nowrap}
.docker-container-footer .btn.danger{color:var(--danger)}
.docker-port-link{color:var(--accent);text-decoration:none;cursor:pointer}
.docker-port-link:hover{text-decoration:underline;border-color:var(--accent)}
.docker-port-dropdown{position:relative;display:inline-flex;align-items:center;min-width:0;max-width:100%;z-index:3}
.docker-port-trigger{display:inline-flex;align-items:center;gap:5px;min-width:0;white-space:nowrap}
.docker-port-trigger .docker-meta-chip{white-space:nowrap;flex:0 0 auto}
.docker-port-more{font-size:11px;color:var(--muted);padding:3px 5px;border-radius:4px;background:var(--panel-2);border:1px solid var(--border);white-space:nowrap;cursor:pointer}
.docker-port-more:hover{color:var(--accent);border-color:var(--accent)}
.docker-port-menu{display:none;position:absolute;left:0;top:calc(100% - 1px);min-width:190px;max-width:min(320px,calc(100vw - 40px));max-height:260px;overflow:auto;padding:5px;background:var(--panel);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.18);z-index:80;flex-direction:column;gap:3px}
.docker-port-dropdown:hover .docker-port-menu,.docker-port-dropdown:focus-within .docker-port-menu,.docker-port-dropdown.expanded .docker-port-menu{display:flex}
.docker-port-dropdown{padding-bottom:0}
.docker-port-menu{margin-top:0}
.docker-port-menu-item{display:flex;align-items:center;min-width:0}
.docker-port-menu-item .docker-port-link{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;padding:8px 10px;border-radius:5px;color:var(--text);text-decoration:none;white-space:nowrap;border:1px solid transparent}
.docker-port-menu-item .docker-port-link:hover,.docker-port-menu-item .docker-port-link:focus{background:var(--panel-2);border-color:var(--border);text-decoration:none;outline:none}
.docker-port-menu-item .docker-port-link small{font-size:11px;color:var(--muted)}
.docker-container-shortcuts button:disabled{opacity:.35;cursor:not-allowed}
.docker-container-shortcuts [data-docker-path]{color:var(--accent)}
.docker-edit-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.docker-edit-grid .full{grid-column:1/-1}
@media(max-width:560px){.docker-edit-grid{grid-template-columns:minmax(0,1fr)}.docker-edit-grid .full{grid-column:auto}}
.docker-task-log-btn{display:inline-flex;align-items:center;gap:6px;position:relative}
.docker-task-log-btn svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.docker-task-count{min-width:17px;height:17px;padding:0 4px;border-radius:10px;background:var(--accent);color:#fff;font-size:10px;display:inline-flex;align-items:center;justify-content:center}
.docker-task-count[hidden]{display:none}
#docker-image-list .docker-image-actions{white-space:nowrap}
#docker-image-list .docker-image-actions .btn{opacity:0;pointer-events:none;transition:opacity .15s ease}
#docker-image-list tr:hover .docker-image-actions .btn,#docker-image-list tr:focus-within .docker-image-actions .btn{opacity:1;pointer-events:auto}
.docker-pending-card{border-style:dashed}
.docker-pending-card .docker-app-icon{color:var(--accent)}
.docker-pending-message{font-size:12px;color:var(--muted);margin-top:6px;overflow-wrap:anywhere}
@media(hover:none),(max-width:760px){ #docker-image-list .docker-image-actions .btn{opacity:1;pointer-events:auto}}
.docker-template-toggle{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.docker-details-content{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;align-items:start}
.docker-detail-item{border:1px solid var(--border);border-radius:7px;padding:10px;min-width:0;background:var(--panel-2);align-self:start}
.docker-detail-port-map{grid-column:1/-1}
.docker-detail-port-map .docker-detail-value{max-height:220px;overflow:auto}
.docker-detail-created-time{grid-column:auto;display:block;min-width:0;padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--panel-2);align-self:start}
.docker-detail-created-time .docker-detail-label{font-size:12px;color:var(--muted);margin-bottom:5px;white-space:normal}
.docker-detail-created-time .docker-detail-value{min-width:0;color:var(--text);font-size:13px;white-space:pre-wrap;overflow-wrap:anywhere}
.docker-detail-label{font-size:12px;color:var(--muted);margin-bottom:5px}
.docker-detail-value{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}
@media(max-width:700px){.docker-details-content{grid-template-columns:minmax(0,1fr)}.docker-detail-created-time,.docker-detail-port-map{grid-column:1}}
.docker-setting-card{margin-bottom:12px}
.docker-setting-card h3{margin:0 0 8px}
.docker-setting-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.docker-setting-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.docker-setting-actions .btn{width:auto}
.docker-danger-zone{border-color:color-mix(in srgb,var(--danger) 38%,var(--border))}
#docker-config-content{width:100%;box-sizing:border-box;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:7px;padding:12px}
@media(max-width:700px){.docker-container-grid{grid-template-columns:minmax(0,1fr)}.docker-container-card{padding:12px;max-width:none}.docker-container-main{gap:10px}.docker-app-icon{width:44px;height:44px;min-width:44px}.docker-container-footer{gap:4px}.docker-container-footer .spacer{display:none}.docker-container-footer .btn{flex:0 0 auto;padding:6px 6px;font-size:11px}.docker-container-meta{gap:4px}.docker-setting-actions .btn{flex:1 1 auto}}

/* Docker dashboard layout polish: keep every panel inside the viewport. */
#view-docker{width:100%;max-width:100%;min-width:0;box-sizing:border-box;overflow-x:hidden}
#docker-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,205px),1fr)) !important;gap:10px;width:100%;max-width:100%;min-width:0;box-sizing:border-box}
#docker-stats>.stat{min-width:0;max-width:100%;box-sizing:border-box;overflow:hidden;padding:13px 15px;background:linear-gradient(145deg,var(--panel-2),color-mix(in srgb,var(--panel-2) 86%,var(--panel)));transition:border-color .18s,background .18s}
#docker-stats>.stat:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--accent) 38%,var(--border));box-shadow:0 5px 16px rgba(0,0,0,.12)}
#docker-stats .num{font-size:23px;line-height:1.1;font-weight:700;letter-spacing:-.025em}
#docker-stats .lbl{margin-top:5px;font-size:12px;line-height:1.35;overflow-wrap:anywhere}
#docker-panel-containers,#docker-panel-images,#docker-panel-networks,#docker-panel-volumes,#docker-panel-settings{min-width:0;width:100%;max-width:100%;box-sizing:border-box}
.docker-container-grid{grid-template-columns:repeat(auto-fill,minmax(min(100%,350px),380px));gap:12px;align-content:start;min-width:0;width:100%;max-width:100%;box-sizing:border-box}
.docker-container-card{width:100%;min-width:0;max-width:380px;padding:13px;border-radius:12px;background:linear-gradient(145deg,var(--panel),color-mix(in srgb,var(--panel) 93%,var(--panel-2)));box-shadow:0 3px 12px rgba(0,0,0,.09);transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}
.docker-container-card:hover{transform:translateY(-1px);box-shadow:0 7px 18px rgba(0,0,0,.16);border-color:color-mix(in srgb,var(--accent) 48%,var(--border))}
.docker-container-main{gap:11px;align-items:flex-start}
.docker-app-icon{width:48px;height:48px;min-width:48px;background:linear-gradient(145deg,var(--panel-2),var(--panel-3));color:var(--text);border-color:color-mix(in srgb,var(--border) 72%,var(--accent))}
.docker-container-copy{min-width:0;overflow:visible}
.docker-container-title{gap:6px;flex-wrap:wrap;white-space:normal;overflow:visible;row-gap:4px;min-height:28px}
.docker-container-title .docker-container-name{max-width:100%;font-size:15px;line-height:1.35;flex:0 1 auto}
.docker-container-title .docker-container-shortcuts{gap:2px}
.docker-container-shortcuts button{width:27px;height:26px;border-radius:6px}
.docker-container-meta{gap:5px;margin-top:8px;align-items:flex-start;flex-wrap:wrap}
.docker-meta-chip{padding:4px 7px;border-radius:6px;font-size:11px;line-height:1.3;min-height:24px;max-width:100%;overflow-wrap:anywhere}
.docker-image-tag-chip{flex:0 1 auto;max-width:100%;white-space:nowrap;text-overflow:ellipsis}
.docker-image-ref-chip{max-width:min(100%,150px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;overflow-wrap:normal}
.docker-port-dropdown{flex:0 0 auto;max-width:100%}
.docker-port-trigger{gap:4px}
.docker-port-trigger .docker-meta-chip{font-variant-numeric:tabular-nums}
.docker-port-more{padding:4px 6px;min-height:24px;box-sizing:border-box}
.docker-container-footer{display:flex;gap:6px;align-items:center;justify-content:flex-start;flex-wrap:wrap;overflow:visible;margin-top:11px;padding-top:10px;border-top:1px solid color-mix(in srgb,var(--border) 80%,transparent)}
.docker-container-footer>.btn{flex:0 0 auto;padding:6px 9px;font-size:12px;line-height:1.25;border-radius:7px;white-space:nowrap}
.docker-container-footer .spacer{display:none}
.docker-container-footer .btn.danger{border-color:color-mix(in srgb,var(--danger) 34%,var(--border));color:var(--danger)}
.docker-pending-message{font-size:12px;line-height:1.5;overflow-wrap:anywhere;color:var(--muted);margin-top:6px}
@media(max-width:900px){
  #docker-stats{grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr)) !important}
  .docker-container-grid{grid-template-columns:repeat(auto-fill,minmax(min(100%,320px),1fr));gap:10px}
  .docker-container-card{max-width:none}
}
@media(max-width:520px){
  #docker-stats{grid-template-columns:repeat(2,minmax(0,1fr)) !important;gap:8px}
  #docker-stats>.stat{padding:11px 12px}
  .docker-container-grid{grid-template-columns:minmax(0,1fr)}
  .docker-container-footer{gap:5px}
  .docker-container-footer>.btn{padding:6px 8px;font-size:11px}
}


/* Docker card alignment tuned to the requested compact layout. */
#docker-container-list.docker-container-grid,
.docker-container-grid {
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), min(100%, 280px)));
  justify-content: start;
  align-items: start;
  gap: 12px;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
}
.docker-container-card {
  width: 100%;
  max-width: 280px;
  min-width: 0;
  box-sizing: border-box;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 0;
}
.docker-container-main {
  display: grid;
  grid-template-columns: 40px minmax(0, 1fr) auto;
  gap: 6px;
  align-items: start;
  min-width: 0;
  width: 100%;
}
.docker-container-main .docker-app-icon {
  width: 40px;
  height: 40px;
  min-width: 40px;
  font-size: 11px;
}
.docker-container-copy {
  min-width: 0;
  width: 100%;
  overflow: visible;
}
.docker-container-title {
  display: flex;
  align-items: flex-start;
  min-width: 0;
  width: 100%;
  overflow: visible;
  white-space: normal;
}
.docker-container-title-left {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  align-content: flex-start;
  gap: 4px 5px;
  min-width: 0;
  max-width: 100%;
}
.docker-container-title-left .docker-container-name {
  display: inline-block;
  max-width: 96px;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  overflow-wrap: normal;
  line-height: 1.4;
}
.docker-container-title-left .docker-directory-shortcuts {
  display: inline-flex;
  align-items: center;
  gap: 1px;
  margin: 0;
  flex: 0 0 auto;
}
.docker-container-title-left .docker-directory-shortcuts button {
  width: 22px;
  height: 22px;
  padding: 2px;
  border-radius: 5px;
}
.docker-container-title-left .docker-directory-shortcuts svg {
  width: 14px;
  height: 14px;
}
.docker-container-header-actions {
  justify-self: end;
  align-self: start;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  min-width: 0;
  margin-left: auto;
}
.docker-container-header-actions .docker-container-shortcuts {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 1px;
  margin: 0;
}
.docker-container-header-actions .docker-container-shortcuts button {
  width: 22px;
  height: 24px;
  padding: 2px;
  border-radius: 5px;
}
.docker-container-header-actions .docker-container-shortcuts svg {
  width: 14px;
  height: 14px;
}
.docker-container-meta {
  display: flex;
  justify-content: flex-start;
  align-items: center;
  flex-wrap: wrap;
  gap: 5px;
  width: 100%;
  min-width: 0;
  margin-top: 9px;
  padding: 0;
  box-sizing: border-box;
}
.docker-container-meta > .docker-meta-chip,
.docker-container-meta > .docker-port-dropdown {
  flex: 0 0 auto;
  max-width: 100%;
  min-width: 0;
}
.docker-meta-chip {
  padding: 4px 6px;
  min-height: 23px;
  line-height: 1.25;
  font-size: 11px;
  box-sizing: border-box;
}
.docker-image-tag-chip { max-width: 105px; white-space: nowrap; }
.docker-image-ref-chip { max-width: 105px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.docker-port-dropdown { position: relative; z-index: 5; }
.docker-port-trigger { min-width: 0; }
.docker-port-trigger .docker-meta-chip { white-space: nowrap; }
.docker-container-footer {
  display: flex;
  justify-content: flex-start;
  align-items: center;
  flex-wrap: nowrap;
  gap: 4px;
  width: 100%;
  min-width: 0;
  margin-top: 10px;
  padding-top: 9px;
  border-top: 1px solid var(--border);
  box-sizing: border-box;
  overflow: visible;
}
.docker-container-footer > .btn {
  flex: 1 1 0;
  padding: 5px 3px;
  font-size: 11px;
  line-height: 1.25;
  white-space: nowrap;
  min-width: 0;
}
.docker-container-footer .spacer { display: none; }
@media (max-width: 700px) {
  .docker-container-grid { grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), min(100%, 280px))); }
  .docker-container-card { max-width: 280px; }
}
@media (max-width: 340px) {
  .docker-container-grid { grid-template-columns: minmax(0, 1fr); }
  .docker-container-card { max-width: 100%; }
  .docker-container-main { grid-template-columns: 36px minmax(0, 1fr) auto; gap: 5px; }
  .docker-container-main .docker-app-icon { width: 36px; height: 36px; min-width: 36px; }
  .docker-container-footer { gap: 3px; }
  .docker-container-footer > .btn { padding: 5px 2px; font-size: 10px; }
}




/* DOCKER_CARD_LAYOUT_BUILD: 2026-10-20-v3 */
#view-docker { width:100%; max-width:100%; min-width:0; box-sizing:border-box; overflow-x:clip; overflow-y:visible; }
#docker-container-list.docker-container-grid,
.docker-container-grid {
  display:grid;
  grid-template-columns:repeat(auto-fill, minmax(min(100%, 380px), 380px));
  justify-content:start;
  align-items:start;
  gap:12px;
  width:100%; max-width:100%; min-width:0;
  box-sizing:border-box;
  overflow:visible;
}
.docker-container-card {
  position:relative;
  display:flex; flex-direction:column; gap:0;
  width:100%; max-width:380px; min-width:0;
  box-sizing:border-box; padding:13px;
  overflow:visible;
  border-radius:12px;
}
.docker-container-card:hover,
.docker-container-card:focus-within { z-index:30; }
.docker-container-main {
  display:grid;
  grid-template-columns:48px minmax(0,1fr) auto;
  align-items:start; gap:9px;
  width:100%; min-width:0;
  overflow:visible;
}
.docker-container-main .docker-app-icon { width:48px; height:48px; min-width:48px; }
.docker-container-copy { width:100%; min-width:0; overflow:visible; }
.docker-container-title,
.docker-container-title-left {
  display:flex; align-items:center; align-content:center; flex-wrap:wrap;
  gap:4px 6px; min-width:0; width:100%; overflow:visible; white-space:normal;
}
.docker-container-title-left .docker-container-name {
  display:inline-block; flex:0 1 auto; min-width:0; max-width:150px;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; line-height:1.35;
}
.docker-container-title-left .docker-directory-shortcuts { display:inline-flex; align-items:center; gap:2px; flex:0 0 auto; margin:0; }
.docker-container-title-left .docker-directory-shortcuts button { width:25px; height:25px; padding:3px; }
.docker-container-header-actions {
  display:flex; align-items:center; justify-self:end; align-self:start;
  justify-content:flex-end; gap:6px; min-width:max-content;
  position:relative; z-index:20; margin-left:auto;
}
.docker-container-header-actions > .docker-state-dot { order:0; margin-right:2px; }
.docker-container-header-actions > .docker-container-shortcuts { order:1; display:flex; align-items:center; gap:2px; margin:0; }
.docker-container-header-actions .docker-container-shortcuts button { width:24px; height:25px; padding:3px; }
.docker-container-header-actions .docker-container-shortcuts svg { width:14px; height:14px; }
.docker-state-dot {
  display:inline-block; flex:0 0 9px; width:9px; height:9px; border-radius:50%;
  box-shadow:0 0 0 3px color-mix(in srgb,currentColor 12%,transparent);
}
.docker-state-dot.is-running { color:var(--ok); background:var(--ok); }
.docker-state-dot.is-installing { color:var(--warn); background:var(--warn); animation:dockerStatusPulse 1.4s ease-in-out infinite; }
.docker-state-dot.is-stopped { color:var(--danger); background:var(--danger); }
@keyframes dockerStatusPulse { 50% { opacity:.45; box-shadow:0 0 0 5px color-mix(in srgb,currentColor 6%,transparent); } }
.docker-container-meta {
  display:flex !important;
  justify-content:center !important;
  align-items:center !important;
  align-content:center;
  flex-wrap:wrap; gap:6px;
  width:100%; min-width:0; margin:9px auto 0; padding:0;
  position:relative; z-index:4; overflow:visible; box-sizing:border-box;
}
.docker-container-meta > .docker-meta-chip,
.docker-container-meta > .docker-port-dropdown { flex:0 1 auto; min-width:0; max-width:100%; }
.docker-meta-chip { padding:4px 7px; min-height:24px; line-height:1.3; font-size:11px; box-sizing:border-box; }
.docker-image-tag-chip { max-width:120px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.docker-image-ref-chip { max-width:120px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.docker-port-dropdown {
  position:relative; display:inline-flex; align-items:center; flex:0 0 auto;
  min-width:0; max-width:100%; padding:0; margin:0;
  overflow:visible; z-index:5;
}
.docker-port-dropdown:hover,
.docker-port-dropdown:focus-within,
.docker-port-dropdown.expanded { z-index:120; }
.docker-port-trigger { display:inline-flex; align-items:center; gap:4px; position:relative; min-width:0; }
.docker-port-trigger .docker-meta-chip { white-space:nowrap; }
.docker-port-menu {
  display:none; position:absolute; left:0; top:calc(100% - 1px); margin:0;
  min-width:210px; max-width:min(320px,calc(100vw - 36px)); max-height:260px;
  overflow:auto; padding:5px; flex-direction:column; gap:3px;
  background:var(--panel); border:1px solid var(--border); border-radius:8px;
  box-shadow:0 8px 24px rgba(0,0,0,.22); z-index:999; pointer-events:auto;
}
.docker-port-dropdown:hover > .docker-port-menu,
.docker-port-dropdown:focus-within > .docker-port-menu,
.docker-port-dropdown.expanded > .docker-port-menu { display:flex !important; }
.docker-port-menu-item { display:flex; align-items:center; min-width:0; }
.docker-port-menu-item .docker-port-link {
  display:flex; align-items:center; justify-content:space-between; gap:10px; width:100%;
  padding:8px 10px; border-radius:5px; color:var(--text); text-decoration:none;
  white-space:nowrap; border:1px solid transparent; min-width:0;
}
.docker-port-menu-item .docker-port-link:hover,
.docker-port-menu-item .docker-port-link:focus { background:var(--panel-2); border-color:var(--border); text-decoration:none; outline:none; }
.docker-port-menu-item .docker-port-link small { white-space:nowrap; font-size:11px; color:var(--muted); }
.docker-container-footer {
  display:flex; flex-wrap:nowrap; align-items:stretch; gap:5px;
  width:100%; min-width:0; margin-top:11px; padding-top:10px;
  overflow:visible; box-sizing:border-box; border-top:1px solid var(--border);
}
.docker-container-footer > .btn {
  flex:1 1 0; min-width:0; max-width:none; text-align:center;
  padding:6px 4px; font-size:11px; line-height:1.25; white-space:nowrap;
}
.docker-container-footer .spacer { display:none; }
@media (max-width:900px) {
  .docker-container-grid { grid-template-columns:repeat(auto-fill,minmax(min(100%,340px),380px)); }
}
@media (max-width:520px) {
  .docker-container-grid { grid-template-columns:minmax(0,1fr); }
  .docker-container-card { max-width:100%; }
  .docker-container-main { grid-template-columns:40px minmax(0,1fr) auto; gap:6px; }
  .docker-container-main .docker-app-icon { width:40px; height:40px; min-width:40px; }
  .docker-container-header-actions { gap:3px; }
  .docker-container-footer { gap:4px; }
  .docker-container-footer > .btn { padding:6px 2px; font-size:10px; }
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
      <a class="nav-item" data-view="cron">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        <span>计划任务</span>
      </a>
      <a class="nav-item" data-view="firewall">
        <svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9.9C7.4 20.4 4 17 4 12V6l8-3z"/></svg>
        <span>防火墙</span>
      </a>
      <a class="nav-item" data-view="docker" title="Docker 容器、镜像、网络与数据卷">
        <svg viewBox="0 0 24 24"><path d="M3 8h4v4H3zM8 8h4v4H8zM13 8h4v4h-4zM8 3h4v4H8zM13 3h4v4h-4zM18 8h3v4h-3zM3 13h4v4H3zM8 13h4v4H8zM13 13h4v4h-4z"/><path d="M2 18h18c-.8 2-2.4 3-5 3H8c-3 0-5-1-6-3z"/></svg>
        <span>Docker 管理</span>
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

    <section class="view" id="view-cron">
      <div class="toolbar">
        <button class="btn primary" id="btn-add-cron">+ 添加计划任务</button>
        <button class="btn" id="btn-refresh-cron">刷新</button>
        <span class="spacer"></span>
        <span class="hint" id="cron-count"></span>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th style="width:80px">类型</th>
            <th>任务名称</th>
            <th style="width:100px">状态</th>
            <th>执行周期</th>
            <th class="w-time">上次执行</th>
            <th style="width:90px">执行结果</th>
            <th style="width:340px">操作</th>
          </tr></thead>
          <tbody id="cron-list"></tbody>
        </table>
        <div class="empty" id="cron-empty" hidden>暂无计划任务，点击「添加计划任务」创建</div>
      </div>
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

    <section class="view" id="view-docker">
      <div class="toolbar">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span id="docker-status-dot" style="width:9px;height:9px;border-radius:50%;background:var(--muted);display:inline-block"></span>
          <strong id="docker-status-title">正在检测 Docker…</strong>
          <span class="hint" id="docker-version" style="margin:0"></span>
        </div>
        <span class="spacer"></span>
        <button class="btn" id="btn-docker-refresh">刷新</button>
        <button class="btn tiny docker-task-log-btn" id="btn-docker-task-logs" type="button" title="查看镜像拉取和容器创建日志" aria-label="查看 Docker 任务日志">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 4h14a1 1 0 0 1 1 1v14H4V5a1 1 0 0 1 1-1Z"/><path d="m7 9 2 2-2 2M12 14h5M7 17h10"/></svg>
          <span class="docker-task-count" id="docker-task-count" hidden>0</span>
        </button>
        <button class="btn primary" id="btn-docker-create">+ 创建容器</button>
      </div>
      <div class="card" id="docker-unavailable" hidden style="margin-bottom:12px">
        <h3>Docker 不可用</h3>
        <p id="docker-unavailable-msg" class="hint" style="line-height:1.8"></p>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px">
          <button class="btn primary" id="btn-docker-install">安装 Docker Engine</button>
          <span class="hint" style="margin:0">适用于 Ubuntu/Debian；将通过系统 apt 源安装 docker.io，并启用 Docker 服务。</span>
        </div>
        <p class="hint" style="line-height:1.7;margin-top:10px">安装会修改系统软件包并启动后台服务，需要 root 权限及可用的 apt 软件源。若安装失败，请根据提示检查软件源或网络。</p>
      </div>
      <div class="stats-box" id="docker-stats" style="grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:12px">
        <div class="stat"><div class="num" id="docker-stat-running">—</div><div class="lbl">运行中容器</div></div>
        <div class="stat"><div class="num" id="docker-stat-stopped">—</div><div class="lbl">已停止容器</div></div>
        <div class="stat"><div class="num" id="docker-stat-images">—</div><div class="lbl">本地镜像</div></div>
        <div class="stat"><div class="num" id="docker-stat-volumes">—</div><div class="lbl">数据卷</div></div>
      </div>
      <div class="subtabs" id="docker-tabs">
        <button class="subtab active" data-docker-tab="containers">容器</button>
        <button class="subtab" data-docker-tab="images">镜像</button>
        <button class="subtab" data-docker-tab="networks">网络</button>
        <button class="subtab" data-docker-tab="volumes">数据卷</button>
        <button class="subtab" data-docker-tab="settings">设置</button>
      </div>

      <div class="subpanel active" id="docker-panel-containers">
        <div class="toolbar">
          <input type="text" id="docker-container-search" placeholder="搜索容器名称、镜像或端口…" style="max-width:320px">
          <span class="spacer"></span><span class="hint" id="docker-container-count" style="margin:0"></span>
        </div>
        <div class="docker-container-grid" id="docker-container-list"></div>
        <div class="empty" id="docker-container-empty" hidden>暂无容器</div>
      </div>

      <div class="subpanel" id="docker-panel-images">
        <div class="toolbar">
          <input type="text" id="docker-pull-image" placeholder="镜像名称，例如 nginx:alpine、redis:7" style="max-width:420px">
          <button class="btn primary" id="btn-docker-pull">拉取镜像</button>
          <span class="spacer"></span><span class="hint" id="docker-image-count" style="margin:0"></span>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>仓库</th><th>标签</th><th>ID</th><th>大小</th><th>创建时间</th><th style="width:150px">操作</th></tr></thead>
            <tbody id="docker-image-list"></tbody>
          </table>
          <div class="empty" id="docker-image-empty" hidden>暂无镜像</div>
        </div>
      </div>

      <div class="subpanel" id="docker-panel-networks">
        <div class="toolbar"><span class="hint" style="margin:0">删除网络前请确认没有容器仍在使用它。</span><span class="spacer"></span><span class="hint" id="docker-network-count" style="margin:0"></span></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>网络名称</th><th>ID</th><th>驱动</th><th>范围</th><th style="width:130px">操作</th></tr></thead>
            <tbody id="docker-network-list"></tbody>
          </table>
          <div class="empty" id="docker-network-empty" hidden>暂无网络</div>
        </div>
      </div>

      <div class="subpanel" id="docker-panel-volumes">
        <div class="toolbar"><span class="hint" style="margin:0">删除数据卷会永久删除其持久化数据，请先确认不再需要。</span><span class="spacer"></span><span class="hint" id="docker-volume-count" style="margin:0"></span></div>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>数据卷名称</th><th>驱动</th><th>挂载路径</th><th style="width:130px">操作</th></tr></thead>
            <tbody id="docker-volume-list"></tbody>
          </table>
          <div class="empty" id="docker-volume-empty" hidden>暂无数据卷</div>
        </div>
      </div>

      <div class="subpanel" id="docker-panel-settings">
        <div class="card docker-setting-card">
          <div class="docker-setting-head"><div><h3>Docker 服务</h3><p class="hint">启停或重启 Docker Engine。停止服务会影响所有正在运行的容器。</p></div><span id="docker-service-state" class="badge">检测中…</span></div>
          <div class="docker-setting-actions">
            <button class="btn primary" id="btn-docker-service-start">启动服务</button>
            <button class="btn" id="btn-docker-service-stop">停止服务</button>
            <button class="btn" id="btn-docker-service-restart">重启服务</button>
            <button class="btn" id="btn-docker-service-enable">设为开机启动</button>
            <button class="btn" id="btn-docker-service-disable">取消开机启动</button>
          </div>
        </div>

        <div class="card docker-setting-card">
          <h3>Docker Hub 镜像源</h3>
          <p class="hint" style="line-height:1.75">切换镜像源会修改 <code>/etc/docker/daemon.json</code>，Docker 正在运行时将自动重启服务以应用设置。若所选源不可用，可返回此处切换其他源。</p>
          <div class="form-row two-col">
            <div><label for="docker-mirror-source">选择镜像源</label><select id="docker-mirror-source">
              <option value="official">Docker Hub 官方源（不使用加速器）</option>
              <option value="aliyun">阿里云个人专属加速器</option>
              <option value="1panel">1Panel 公共镜像源</option>
              <option value="daocloud">DaoCloud 公共镜像源</option>
              <option value="1ms">毫秒镜像源（docker.1ms.run）</option>
              <option value="dockerproxy">Docker Proxy（dockerproxy.net）</option>
              <option value="dockerproxy-link">Docker Proxy（dockerproxy.link）</option>
              <option value="dockerproxy-cool">Docker Proxy（dockerproxy.cool）</option>
              <option value="cnix">CNIX 公共镜像（docker.m.ixdev.cn）</option>
              <option value="rat">耗子面板公共镜像（hub.rat.dev）</option>
              <option value="jiaxin">简行公共镜像（docker.jiaxin.site）</option>
              <option value="tencent-internal">腾讯云内网镜像（仅腾讯云主机）</option>
              <optgroup label="高校镜像源"><option value="ustc" disabled>中国科大 USTC（Docker Hub 缓存已暂停）</option><option value="school-custom">自定义高校 / 单位镜像源</option></optgroup>
              <option value="custom">其他自定义镜像源</option>
            </select></div>
            <div id="docker-mirror-custom-wrap" hidden><label for="docker-mirror-custom-url">镜像源地址</label><input id="docker-mirror-custom-url" type="url" placeholder="https://xxxx.mirror.aliyuncs.com 或 https://镜像域名"></div>
          </div>
          <p id="docker-mirror-note" class="hint" style="line-height:1.75;margin-top:8px"></p>
          <div class="docker-setting-actions"><button class="btn primary" id="btn-docker-apply-mirror">保存镜像源并应用</button><button class="btn" id="btn-docker-test-mirror">测试所选源</button><button class="btn" id="btn-docker-open-config">打开 Docker 配置文件</button></div>
          <p id="docker-mirror-current" class="hint" style="margin-top:12px;overflow-wrap:anywhere"></p>
        </div>

        <div class="card docker-setting-card docker-danger-zone">
          <h3>危险操作</h3>
          <p class="hint" style="line-height:1.75">卸载 Docker 会移除系统中的 Docker 软件包并停止服务。为避免误删数据，本操作不会主动删除 <code>/var/lib/docker</code>、镜像层、容器数据卷或你的 Compose 文件；卸载后它们仍会占用磁盘空间。</p>
          <button class="btn danger" id="btn-docker-uninstall" style="width:auto">卸载 Docker Engine</button>
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

<div class="modal" id="docker-install-modal" hidden>
  <div class="modal-box" style="max-width:660px">
    <div class="modal-head"><span>安装 Docker Engine</span></div>
    <div class="form-body">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <strong id="docker-install-stage">正在准备安装…</strong>
        <span id="docker-install-percent" style="font-variant-numeric:tabular-nums;font-weight:700">0%</span>
      </div>
      <div style="height:9px;background:var(--panel-3);border-radius:999px;overflow:hidden">
        <div id="docker-install-bar" style="height:100%;width:0%;background:var(--accent);border-radius:999px;transition:width .25s ease"></div>
      </div>
      <div id="docker-install-message" class="hint" style="white-space:pre-wrap;overflow-wrap:anywhere">正在启动安装任务…</div>
      <div style="font-size:12px;font-weight:600">实时安装日志</div>
      <pre id="docker-install-log" style="margin:0;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--panel-2);height:240px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace"></pre>
      <p class="hint" style="margin:0">安装过程中请勿关闭或重启面板服务。安装完成后可关闭此窗口。</p>
    </div>
    <div class="modal-foot">
      <span id="docker-install-footnote" class="hint" style="margin-right:auto">正在等待安装进度…</span>
      <button class="btn primary" id="docker-install-close" disabled>安装中…</button>
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

<!-- 计划任务：添加/编辑 -->
<div class="modal" id="cron-modal" hidden>
  <div class="modal-box cron-form-box">
    <div class="modal-head"><span id="cron-modal-title">添加计划任务</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row two-col">
        <div>
          <label>任务类型</label>
          <select id="cron-type">
            <option value="shell">Shell 脚本</option>
            <option value="python">Python 脚本</option>
          </select>
        </div>
        <div>
          <label>任务名称 <span style="color:#ef4444">*</span></label>
          <input type="text" id="cron-name" placeholder="请输入计划任务名称">
        </div>
      </div>

      <div class="form-row">
        <label>执行周期</label>
        <div class="schedule-row">
          <select id="cron-sched-type">
            <option value="daily">每天</option>
            <option value="hourly">每小时</option>
            <option value="n_minutes">N 分钟</option>
            <option value="n_hours">N 小时</option>
            <option value="weekly">每周</option>
            <option value="monthly">每月</option>
            <option value="custom">自定义</option>
          </select>
          <div id="cron-sched-params" class="schedule-params"></div>
          <label class="perm-check" style="margin-left:auto">
            <input type="checkbox" id="cron-use-lock" checked> 开启进程锁
          </label>
        </div>
        <p class="hint" id="cron-sched-desc"></p>
      </div>

      <div class="form-row">
        <label>执行用户</label>
        <select id="cron-user"></select>
        <p class="hint">默认使用 root 用户执行，也可以切换到其他系统用户</p>
      </div>

      <div class="form-row">
        <label>脚本内容 <span style="color:#ef4444">*</span></label>
        <textarea id="cron-script" class="cron-script-area" spellcheck="false" placeholder="请输入脚本内容"></textarea>
        <p class="hint">温馨提示：为了保证服务器的安全稳定，脚本中以下命令不可使用：shutdown, init 0, init 6, reboot, halt, poweroff, mkfs, mkfs.ext, mke2fs, passwd, chpasswd, --stdin</p>
      </div>
    </div>
    <div class="modal-foot">
      <span class="spacer"></span>
      <button class="btn" data-close>取消</button>
      <button class="btn primary" id="cron-save">确定</button>
    </div>
  </div>
</div>

<!-- 计划任务：日志 -->
<div class="modal" id="cron-log-modal" hidden>
  <div class="modal-box cron-log-box">
    <div class="modal-head"><span id="cron-log-title">任务日志</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <p class="hint" id="cron-log-meta"></p>
      <textarea id="cron-log-area" class="cron-log-area" readonly></textarea>
    </div>
    <div class="modal-foot">
      <button class="btn danger" id="cron-log-clear" style="margin-right:auto">清空日志</button>
      <button class="btn" data-close>关闭</button>
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

<div class="modal" id="docker-config-modal" hidden>
  <div class="modal-box form-box" style="max-width:900px;width:min(900px,94vw);height:min(84vh,900px)">
    <div class="modal-head"><span>Docker Engine 配置文件</span><span class="spacer"></span><button class="btn tiny" id="btn-docker-config-reload">重新读取</button><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body" style="flex:1;min-height:0;overflow:hidden">
      <div class="hint" id="docker-config-path" style="overflow-wrap:anywhere">/etc/docker/daemon.json</div>
      <textarea id="docker-config-content" spellcheck="false" style="flex:1;min-height:320px;resize:vertical;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre;tab-size:2" placeholder="{}"></textarea>
      <p class="hint" style="margin:0;line-height:1.7">只接受合法 JSON 对象。保存后若 Docker 正在运行，面板会自动重启服务。保存前会尝试备份旧配置；若重启失败，会尝试回滚。修改 hosts 等参数可能暴露 Docker 的高权限 API，请谨慎操作。</p>
    </div>
    <div class="modal-foot"><span id="docker-config-msg" class="hint" style="margin-right:auto"></span><button class="btn" data-close>取消</button><button class="btn primary" id="btn-docker-config-save">保存并应用</button></div>
  </div>
</div>

<div class="modal" id="docker-pull-progress-modal" hidden>
  <div class="modal-box" style="max-width:760px;width:min(760px,94vw)">
    <div class="modal-head">
      <span id="docker-pull-progress-title">Docker 任务日志</span>
      <div style="display:flex;align-items:center;gap:8px">
        <select id="docker-pull-task-select" aria-label="选择 Docker 后台任务" style="max-width:310px;min-width:170px"></select>
        <button class="btn tiny" type="button" id="docker-pull-progress-close-top" title="关闭日志窗口" aria-label="关闭日志窗口">×</button>
      </div>
    </div>
    <div class="form-body">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px"><strong id="docker-pull-progress-stage">准备中…</strong><span id="docker-pull-progress-percent" style="font-variant-numeric:tabular-nums;font-weight:700">0%</span></div>
      <div style="height:9px;background:var(--panel-3);border-radius:999px;overflow:hidden"><div id="docker-pull-progress-bar" style="height:100%;width:0%;background:var(--accent);border-radius:999px;transition:width .25s ease"></div></div>
      <p id="docker-pull-progress-message" class="hint" style="white-space:pre-wrap;overflow-wrap:anywhere;margin:0">正在连接镜像仓库…</p>
      <strong style="font-size:12px">实时任务日志</strong>
      <pre id="docker-pull-progress-log" style="margin:0;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--panel-2);height:220px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace"></pre>
    </div>
    <div class="modal-foot"><span id="docker-pull-progress-footnote" class="hint" style="margin-right:auto">任务将在后台运行，你可以关闭这个窗口继续使用面板。</span><button class="btn danger" id="docker-pull-progress-cancel" type="button" hidden>停止拉取</button><button class="btn" id="docker-pull-progress-close">关闭</button></div>
  </div>
</div>

<div class="modal" id="docker-details-modal" hidden>
  <div class="modal-box form-box" style="max-width:900px;width:min(900px,94vw);max-height:84vh">
    <div class="modal-head"><span id="docker-details-title">容器详情</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body" style="overflow:auto"><div id="docker-details-content" class="docker-details-content"></div></div>
    <div class="modal-foot"><span class="spacer"></span><button class="btn" data-close>关闭</button></div>
  </div>
</div>

<div class="modal" id="docker-edit-modal" hidden>
  <div class="modal-box form-box" style="max-width:720px;width:min(720px,94vw)">
    <div class="modal-head"><span id="docker-edit-title">编辑容器</span><span class="spacer"></span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <input type="hidden" id="docker-edit-id">
      <div class="hint" id="docker-edit-image" style="overflow-wrap:anywhere;margin-bottom:10px"></div>
      <div class="docker-edit-grid">
        <div class="form-row"><label for="docker-edit-cpus">CPU 限制（核）</label><input type="number" id="docker-edit-cpus" min="0" max="256" step="0.1" value="0"><p class="hint">0 表示不限制，例如 1.5 表示最多使用 1.5 核。</p></div>
        <div class="form-row"><label for="docker-edit-memory">RAM 限制（MiB）</label><input type="number" id="docker-edit-memory" min="0" max="1048576" step="128" value="0"><p class="hint">0 表示不限制，例如 1024 表示 1 GiB。</p></div>
        <div class="form-row full"><label for="docker-edit-ports">端口映射（每行一条）</label><textarea id="docker-edit-ports" rows="4" placeholder="8080:80/tcp&#10;8443:443/tcp"></textarea><p class="hint">格式为“宿主机端口:容器端口/协议”，也可指定绑定 IP，例如 127.0.0.1:8080:80/tcp；协议可省略，默认 TCP。清空表示不发布端口。</p></div>
      </div>
      <p class="hint" id="docker-edit-port-warning" hidden style="border:1px solid var(--warning);border-radius:8px;padding:10px">端口变更需要短暂停止并重建容器。面板会尝试保留容器可写层快照，挂载目录和数据卷保持不变；快照镜像会保留在本地，避免丢失数据。</p>
      <p class="hint" id="docker-edit-message" style="white-space:pre-wrap;overflow-wrap:anywhere;margin:0"></p>
    </div>
    <div class="modal-foot"><span class="spacer"></span><button class="btn" data-close>取消</button><button class="btn primary" id="btn-docker-edit-save">保存配置</button></div>
  </div>
</div>

<div class="modal" id="docker-create-modal" hidden>
  <div class="modal-box form-box" style="max-width:680px">
    <div class="modal-head"><span>创建并启动容器</span><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body">
      <div class="form-row two-col">
        <div><label>容器名称 *</label><input type="text" id="docker-run-name" placeholder="例如：web-nginx" autocomplete="off"></div>
        <div><label>镜像名称 *</label><input type="text" id="docker-run-image" placeholder="例如：nginx:alpine" autocomplete="off"></div>
      </div>
      <div class="form-row"><label>端口映射（每行一条）</label><textarea id="docker-run-ports" rows="3" placeholder="8080:80&#10;8443:443"></textarea><p class="hint">格式：宿主机端口:容器端口，可指定 /tcp 或 /udp。</p></div>
      <div class="form-row"><label>目录挂载（每行一条）</label><textarea id="docker-run-volumes" rows="3" placeholder="/opt/web:/usr/share/nginx/html:ro"></textarea><p class="hint">宿主机路径和容器路径均使用绝对路径。宿主机挂载会使容器访问对应主机文件，请谨慎配置。</p></div>
      <div class="form-row"><label>环境变量（每行 KEY=VALUE）</label><textarea id="docker-run-env" rows="3" placeholder="TZ=Asia/Shanghai"></textarea></div>
      <div class="form-row"><label>重启策略</label><select id="docker-run-restart"><option value="unless-stopped" selected>除非手动停止，否则自动重启</option><option value="always">始终重启</option><option value="on-failure">失败时重启</option><option value="no">不自动重启</option></select></div>
      <p class="hint">提示：创建前需确保镜像存在；如本机没有该镜像，Docker 会尝试自动拉取。此简易表单不配置特权模式和宿主机网络。</p>
    </div>
    <div class="modal-foot"><span class="spacer"></span><button class="btn" data-close>取消</button><button class="btn primary" id="btn-docker-run-submit">创建并启动</button></div>
  </div>
</div>

<div class="modal" id="docker-logs-modal" hidden>
  <div class="modal-box form-box" style="max-width:1000px;width:min(1000px,94vw);height:min(78vh,760px)">
    <div class="modal-head"><span id="docker-logs-title">容器日志</span><span class="spacer"></span><button class="btn tiny" id="btn-docker-logs-refresh">刷新日志</button><button class="btn tiny" data-close aria-label="关闭"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
    <div class="form-body" style="flex:1;min-height:0;overflow:hidden"><pre id="docker-log-content" style="white-space:pre-wrap;overflow:auto;flex:1;min-height:0;margin:0;padding:14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere">正在加载…</pre></div>
    <div class="modal-foot"><span class="hint" style="margin:0">显示最近 200 行日志（最多保留 200 KB）</span><span class="spacer"></span><button class="btn" data-close>关闭</button></div>
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

// 本地 SVG 线性图标
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
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  play: '<path d="m6 4 14 8-14 8z"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
  history: '<path d="M3 12a9 9 0 1 0 9-9 9 9 0 0 0-6.3 2.6L3 8"/><path d="M3 3v5h5M12 7v5l4 2"/>',
  'x-circle': '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>',
  'check-circle': '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',
  'pause-circle': '<circle cx="12" cy="12" r="10"/><path d="M10 9v6M14 9v6"/>',
};
function iconSvg(name, extraClass = '') {
  const key = Object.prototype.hasOwnProperty.call(ICON_PATHS, name) ? name : 'file';
  const cls = ('ui-icon icon-' + key + (extraClass ? ' ' + extraClass : '')).replace(/[^a-zA-Z0-9_ -]/g, '');
  return `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[key]}</svg>`;
}
$$('[data-icon]').forEach(el => { el.innerHTML = iconSvg(el.dataset.icon); });

/* 主题 */
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
    if (v === 'cron') loadCronTasks();
    if (v === 'ssh') { loadSshService(); loadKeys(); }
    if (v === 'docker') loadDocker();
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
let allEntries = [];
let clipboard = null;
let ctxTarget = null;
let currentDisk = null;
let sortField = 'name';
let sortDir = 'asc';
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

function refreshView() {
  const q = (searchBox.value || '').trim().toLowerCase();
  let list = allEntries;
  if (q) list = list.filter(e => e.name.toLowerCase().includes(q));
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

$$('.data-table thead th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const field = th.dataset.sort;
    if (sortField === field) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortField = field; sortDir = 'asc'; }
    refreshView();
  });
});

searchBox.addEventListener('input', () => refreshView());

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

  if (overflows() && nodes.length > 1) {
    nodes[0].style.display = 'none';
    breadcrumbEl.insertBefore(ellipsisNode, nodes[0]);
  }

  if (overflows()) {
    const currentLink = nodes[nodes.length - 1].querySelector('.bc-part');
    if (currentLink) {
      currentLink.style.maxWidth = Math.max(36, breadcrumbEl.clientWidth - 100) + 'px';
    }
  }

  const hidden = nodes.filter(node => node.style.display === 'none')
    .map(node => node.querySelector('.bc-part')?.textContent || '')
    .filter(Boolean);
  const ellipsis2 = ellipsisNode.querySelector('.bc-ellipsis');
  if (ellipsis2) ellipsis2.title = hidden.length
    ? '已省略目录：' + hidden.join(' / ') + '；点击可编辑完整路径'
    : '点击编辑完整路径';
}

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

fileListEl.addEventListener('click', ev => {
  const tr = ev.target.closest('tr');
  if (!tr) return;
  const noteCell = ev.target.closest('.note-cell');
  if (noteCell) {
    ev.stopPropagation();
    startEditNote(noteCell);
    return;
  }
  if (ev.target.closest('.row-check')) {
    const cb = ev.target;
    tr.classList.toggle('selected', cb.checked);
    updateCheckAll();
    return;
  }
  const now = Date.now();
  const isDbl = (now - lastClickTime < 350) && lastClickRow === tr;
  lastClickTime = now;
  lastClickRow = tr;

  if (isDbl) {
    const path = tr.dataset.path, isDir = tr.dataset.dir === '1';
    if (isDir) loadFiles(path);
    else openEditor(path, tr.dataset.name);
    return;
  }

  const isMulti = ev.ctrlKey || ev.metaKey;
  const cb = tr.querySelector('.row-check');
  if (isMulti) {
    cb.checked = !cb.checked;
    tr.classList.toggle('selected', cb.checked);
  } else {
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

/* Windows 风格快捷键 */
let keyboardAnchorIndex = null;
function fileShortcutsEnabled() {
  if (!$('#view-files').classList.contains('active')) return false;
  if ($$('.modal:not([hidden])').length) return false;
  const active = document.activeElement;
  if (active && (active.matches('input, textarea, select, [contenteditable="true"]') || active.isContentEditable)) return false;
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

  if (mod && !e.shiftKey && !e.altKey && key === 'a') {
    if (!rows.length) return;
    e.preventDefault();
    applyRowSelection(rows.map((_, i) => i));
    keyboardAnchorIndex = 0;
    return;
  }
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
  if (mod && e.altKey && !e.shiftKey && key === 'n') {
    e.preventDefault();
    await createDirectoryFromShortcut();
    return;
  }
  if (mod && !e.shiftKey && !e.altKey && key === 'f') {
    e.preventDefault();
    searchBox.focus();
    searchBox.select();
    return;
  }
  if (e.key === 'Delete' && selected.length) { e.preventDefault(); $('#btn-batch-del').click(); return; }
  if (e.key === 'F2' && selected.length === 1) {
    e.preventDefault();
    const entry = allEntries.find(item => item.path === selected[0]);
    if (entry) await renameEntry(entry.path, entry.name);
    return;
  }
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
  if (e.key === 'F5') { e.preventDefault(); loadFiles(currentPath); return; }
  if (e.altKey && e.key === 'ArrowUp') {
    if (!currentPath) return;
    e.preventDefault();
    const parts = currentPath.split('/').filter(Boolean);
    parts.pop();
    loadFiles(parts.join('/'));
    return;
  }
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
  if (e.key === 'Escape') {
    if (ctxMenu.classList.contains('show')) { ctxMenu.classList.remove('show'); return; }
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
                             relativePath = file.name, index = 1, overwrite = false) {
  return new Promise((resolve) => {
    const url = '/api/files/upload_stream'
      + '?path=' + encodeURIComponent(targetPath)
      + '&name=' + encodeURIComponent(file.name)
      + '&overwrite=' + (overwrite ? '1' : '0');
    const xhr = new XMLHttpRequest();
    const tp = batchProgress ? null : toastProgress(`上传：${file.name}（${humanSize(file.size)}）`);
    if (batchProgress) batchProgress.start(relativePath, index, file.size);
    xhr.upload.addEventListener('progress', e => {
      if (!e.lengthComputable) return;
      if (batchProgress) batchProgress.progress(e.loaded);
      else tp.set(Math.round((e.loaded / e.total) * 100), e.loaded, e.total);
    });
    xhr.addEventListener('load', () => {
      const completeProgress = () => { if (batchProgress) batchProgress.complete(file.size); };
      if (xhr.status === 200) {
        try {
          const res = JSON.parse(xhr.responseText);
          if (res.code === 0) { if (batchProgress) completeProgress(); else tp.done(); resolve({ ok: true }); }
          else {
            if (batchProgress) completeProgress(); else tp.fail(res.msg || '失败');
            if (res.code === 507 && !batchProgress) toast(res.msg, 'error', 6000);
            resolve({ ok: false, msg: res.msg || '上传失败' });
          }
        } catch {
          if (batchProgress) completeProgress(); else tp.fail('响应解析失败');
          resolve({ ok: false, msg: '响应解析失败' });
        }
      } else if (xhr.status === 409) {
        // 保留该项的进度状态，交由队列确认覆盖或跳过，避免重复计数。
        if (!batchProgress) tp.fail('目标名称冲突');
        let msg = '目标位置已存在同名文件';
        try { msg = JSON.parse(xhr.responseText).msg || msg; } catch {}
        resolve({ ok: false, conflict: true, msg });
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
  const parts = safeUploadParts(relativeDir);
  const name = parts.pop();
  const parent = [basePath || '', parts.join('/')].filter(Boolean).join('/');
  const nextPath = [parent, name].filter(Boolean).join('/');
  const res = await api('/api/files/mkdir', { method: 'POST', body: { path: parent, name } });
  if (res.code !== 0) {
    if (res.msg !== '已存在') throw new Error(res.msg || `无法创建目录：${nextPath}`);
    const check = await api('/api/files?path=' + encodeURIComponent(nextPath));
    if (check.code !== 0) throw new Error(`路径已存在但不是目录：${nextPath}`);
  }
  return nextPath;
}
async function confirmUploadConflicts(items, basePath) {
  const dirCache = new Map();
  for (const item of items) {
    item.overwrite = false;
    item.skip = false;
    let parts;
    try { parts = safeUploadParts(item.relativePath); }
    catch (e) { item.skip = true; item.skipReason = e.message; continue; }
    const name = parts.pop();
    const relativeDir = parts.join('/');
    const targetDir = [basePath || '', relativeDir].filter(Boolean).join('/');
    if (!dirCache.has(targetDir)) {
      const res = await api('/api/files?path=' + encodeURIComponent(targetDir));
      if (res.code !== 0) throw new Error(res.msg || `无法检查上传目录：${targetDir || '/'}`);
      dirCache.set(targetDir, new Map((res.data.entries || []).map(entry => [entry.name, entry])));
    }
    const existing = dirCache.get(targetDir).get(name);
    if (!existing) continue;
    if (existing.dir) {
      item.skip = true;
      item.skipReason = '同名目录已存在，不能用文件覆盖';
      continue;
    }
    const where = [targetDir, name].filter(Boolean).join('/');
    const ok = await showConfirm('文件已存在，是否覆盖？',
      `目标位置已存在同名文件：\n${where}\n\n现有文件大小：${humanSize(existing.size)}\n新文件大小：${humanSize(item.file.size)}\n\n选择“覆盖”将替换原文件内容，此操作不可撤销。选择“取消”将跳过该文件。`,
      'alert-triangle');
    if (ok) item.overwrite = true;
    else { item.skip = true; item.skipReason = '用户取消覆盖'; }
  }
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
  const allDirs = new Set(directories);
  try {
    for (const item of items) {
      const parts = safeUploadParts(item.relativePath);
      parts.pop();
      for (let i = 1; i <= parts.length; i++) allDirs.add(parts.slice(0, i).join('/'));
    }
  } catch (e) { toast('无法上传：' + e.message, 'error', 5000); return; }
  const orderedDirs = Array.from(allDirs).filter(Boolean).sort((a, b) => {
    const depth = a.split('/').length - b.split('/').length;
    return depth || a.localeCompare(b);
  });
  try {
    for (const dir of orderedDirs) await ensureUploadDirectory(basePath, dir);
  } catch (e) { toast('创建上传目录失败：' + e.message, 'error', 5000); return; }

  try {
    await confirmUploadConflicts(items, basePath);
  } catch (e) { toast('检查同名文件失败：' + e.message, 'error', 6000); return; }

  let okCount = 0, failCount = 0, skipCount = 0;
  const uploadProgress = items.length ? toastBatchUpload(items.length, totalSize) : null;
  const failureDetails = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    let targetPath = basePath || '';
    try {
      if (item.skip) {
        skipCount++;
        if (uploadProgress) uploadProgress.skip(item.relativePath, i + 1);
        if (item.skipReason && failureDetails.length < 3) failureDetails.push(`${item.relativePath}: ${item.skipReason}`);
        continue;
      }
      const parts = safeUploadParts(item.relativePath);
      parts.pop();
      if (parts.length) targetPath = [basePath, parts.join('/')].filter(Boolean).join('/');
      let result = await uploadOneFile(item.file, targetPath, uploadProgress, item.relativePath, i + 1, item.overwrite);
      if (result.conflict && !item.overwrite) {
        const retry = await showConfirm('文件已存在，是否覆盖？',
          `${result.msg}

确认覆盖将替换原文件内容，此操作不可撤销。`, 'alert-triangle');
        if (retry) result = await uploadOneFile(item.file, targetPath, uploadProgress, item.relativePath, i + 1, true);
        else { skipCount++; if (uploadProgress) uploadProgress.skip(item.relativePath, i + 1); continue; }
      }
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
  if (uploadProgress) uploadProgress.finish(okCount, failCount, skipCount);
  else toast(`目录创建完成：${orderedDirs.length} 个目录`, 'ok');
  if (failCount || skipCount) {
    const detail = failureDetails.length ? '；' + failureDetails.join('；') : '';
    toast(`上传完成：成功 ${okCount} 个，失败 ${failCount} 个，跳过 ${skipCount} 个${detail}`, 'warn', 7000);
  }
}

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
  let completed = 0, bytesDone = 0, currentLoaded = 0, currentFileSize = 0;
  function update() {
    const sent = Math.min(totalSize, bytesDone + currentLoaded);
    let pct = totalSize > 0 ? Math.round(sent / totalSize * 100)
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
    progress(loaded) { currentLoaded = Math.min(currentFileSize, Math.max(0, Number(loaded) || 0)); update(); },
    complete(sentBytes = currentLoaded) {
      const sent = Math.min(currentFileSize, Math.max(currentLoaded, Number(sentBytes) || 0));
      bytesDone = Math.min(totalSize, bytesDone + sent);
      completed = Math.min(totalFiles, completed + 1);
      currentLoaded = 0; currentFileSize = 0;
      titleEl.textContent = `已处理 ${completed}/${totalFiles} 个文件`;
      update();
    },
    skip(relativePath, index) {
      titleEl.textContent = `跳过 ${index}/${totalFiles}：${relativePath}`;
      completed = Math.min(totalFiles, completed + 1);
      currentLoaded = 0; currentFileSize = 0;
      update();
    },
    finish(okCount, failCount, skipCount = 0) {
      el.classList.add(failCount ? 'error' : 'ok');
      titleEl.textContent = (failCount || skipCount)
        ? `上传结束：成功 ${okCount} 个，失败 ${failCount} 个，跳过 ${skipCount} 个`
        : `上传完成：${okCount} 个文件`;
      barEl.style.width = '100%';
      pctEl.textContent = (failCount || skipCount) ? '已结束' : '完成';
      totalEl.textContent = `${okCount} 成功 · ${failCount} 失败 · ${skipCount} 跳过 · 共 ${totalFiles} 个文件`;
      setTimeout(() => {
        el.style.transition = 'opacity .3s, transform .3s';
        el.style.opacity = '0'; el.style.transform = 'translateY(-16px)';
        setTimeout(() => el.remove(), 320);
      }, failCount ? 5000 : 1400);
    }
  };
}

$('#file-input').addEventListener('change', async ev => {
  const files = Array.from(ev.target.files || []);
  if (!files.length) return;
  const basePath = currentPath;
  await runUploadQueue(files.map(file => ({ file, relativePath: file.name })), [], basePath);
  ev.target.value = '';
});

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
  ev.preventDefault(); ev.stopPropagation();
  fileDragDepth = 0;
  fileDropZone.classList.remove('drag-over');
  const basePath = currentPath;
  const transfer = ev.dataTransfer;
  const result = { files: [], directories: new Set() };
  const items = Array.from(transfer.items || []).filter(item => item.kind === 'file');
  let usedEntries = false;
  try {
    const entries = [];
    for (const item of items) {
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) entries.push(entry);
    }
    usedEntries = entries.length > 0;
    for (const entry of entries) await collectDropEntry(entry, '', result);
  } catch (e) { toast('读取拖入的文件/文件夹失败：' + e.message, 'error', 5000); return; }
  if (!usedEntries) {
    result.files = Array.from(transfer.files || []).map(file => ({
      file, relativePath: file.webkitRelativePath || file.name
    }));
  }
  if (!result.files.length && !result.directories.size) {
    toast('没有识别到可上传的文件或文件夹', 'warn'); return;
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
   计划任务
   ============================================================ */
let cronCache = [];
let currentCronId = null;
let currentLogCronId = null;

async function loadCronTasks() {
  try {
    const res = await api('/api/cron/tasks');
    if (res.code !== 0) { toast(res.msg, 'error'); return; }
    cronCache = res.data || [];
    $('#cron-count').textContent = `共 ${cronCache.length} 个任务`;
    const list = $('#cron-list'); list.innerHTML = '';
    $('#cron-empty').hidden = cronCache.length > 0;
    cronCache.forEach(t => {
      const tr = document.createElement('tr');
      tr.dataset.id = t.id;
      const isPy = t.task_type === 'python';
      const typeTag = isPy
        ? `<span class="cron-type-tag py">PY</span>`
        : `<span class="cron-type-tag">SH</span>`;
      // 状态列
      const statusCol = `<label class="cron-toggle" title="${t.enabled ? '点击停用' : '点击启用'}">
        <input type="checkbox" class="cron-enabled" ${t.enabled ? 'checked' : ''}>
        <span class="slider"></span>
      </label>`;
      // 上次结果
      let lastRes = '<span style="color:var(--muted)">-</span>';
      if (t.last_status === 'running') lastRes = '<span style="color:var(--warn)">运行中</span>';
      else if (t.last_status === 'success') lastRes = '<span style="color:var(--ok)">成功</span>';
      else if (t.last_status === 'failed') lastRes = '<span style="color:var(--danger)">失败</span>';
      const lastRun = t.last_run ? fmtTime(t.last_run) : '从未';
      tr.innerHTML = `
        <td>${typeTag}</td>
        <td><div class="name-cell"><span class="name" title="${esc(t.name)}">${esc(t.name)}</span></div></td>
        <td>${statusCol}</td>
        <td>${esc(t.schedule_desc || '-')}</td>
        <td class="w-time">${esc(lastRun)}</td>
        <td>${lastRes}</td>
        <td><div style="display:flex;gap:4px;flex-wrap:nowrap;justify-content:center">
          <button class="btn tiny primary" data-act="run">立即执行</button>
          <button class="btn tiny" data-act="edit">编辑</button>
          <button class="btn tiny" data-act="log">日志</button>
          <button class="btn tiny danger" data-act="delete">删除</button>
        </div></td>`;
      list.appendChild(tr);
    });
  } catch (e) { toast(e.message, 'error'); }
}

$('#btn-refresh-cron').addEventListener('click', loadCronTasks);
$('#btn-add-cron').addEventListener('click', () => openCronModal(null));

async function openCronModal(task) {
  // 加载系统用户列表
  const ug = await api('/api/system/users_groups');
  const userSel = $('#cron-user');
  userSel.innerHTML = '';
  if (ug.code === 0) {
    ug.data.users.forEach(u => {
      const o = document.createElement('option');
      o.value = u.name; o.textContent = u.name + (u.uid === 0 ? '（root）' : '');
      userSel.appendChild(o);
    });
  } else {
    const o = document.createElement('option'); o.value = 'root'; o.textContent = 'root';
    userSel.appendChild(o);
  }

  if (task) {
    currentCronId = task.id;
    $('#cron-modal-title').textContent = '编辑计划任务';
    $('#cron-type').value = task.task_type || 'shell';
    $('#cron-name').value = task.name || '';
    $('#cron-use-lock').checked = !!task.use_lock;
    $('#cron-script').value = task.script || '';
    userSel.value = task.run_user || 'root';
    const sched = task.schedule || {};
    $('#cron-sched-type').value = sched.type || 'daily';
    renderScheduleParams(sched.type || 'daily', sched);
  } else {
    currentCronId = null;
    $('#cron-modal-title').textContent = '添加计划任务';
    $('#cron-type').value = 'shell';
    $('#cron-name').value = '';
    $('#cron-use-lock').checked = true;
    $('#cron-script').value = '';
    userSel.value = 'root';
    $('#cron-sched-type').value = 'daily';
    renderScheduleParams('daily', { hour: 1, minute: 30 });
  }
  $('#cron-modal').hidden = false;
}

function _opts(min, max, pad = true) {
  let html = '';
  for (let i = min; i <= max; i++) {
    const v = pad ? String(i).padStart(2, '0') : String(i);
    html += `<option value="${i}">${v}</option>`;
  }
  return html;
}

function renderScheduleParams(type, values = {}) {
  const box = $('#cron-sched-params');
  const v = values || {};
  const hoursOpts  = _opts(0, 23);
  const minsOpts   = _opts(0, 59);
  const weekOpts   = ['周日','周一','周二','周三','周四','周五','周六']
    .map((n, i) => `<option value="${i}">${n}</option>`).join('');
  const mdOpts     = _opts(1, 31, false);

  if (type === 'daily') {
    box.innerHTML = `
      <select class="mini" id="sched-hour">${hoursOpts}</select><span>时</span>
      <select class="mini" id="sched-minute">${minsOpts}</select><span>分</span>`;
    $('#sched-hour').value   = Number(v.hour   ?? 1);
    $('#sched-minute').value = Number(v.minute ?? 30);
  } else if (type === 'hourly') {
    box.innerHTML = `
      <select class="mini" id="sched-minute">${minsOpts}</select><span>分</span>`;
    $('#sched-minute').value = Number(v.minute ?? 0);
  } else if (type === 'n_minutes') {
    box.innerHTML = `每 <input type="number" class="mini" id="sched-n" value="${Number(v.n ?? 5)}" min="1" max="59"><span>分钟</span>`;
  } else if (type === 'n_hours') {
    box.innerHTML = `每 <input type="number" class="mini" id="sched-n" value="${Number(v.n ?? 1)}" min="1" max="23"><span>小时</span>`;
  } else if (type === 'weekly') {
    box.innerHTML = `
      <select class="mini" id="sched-weekday">${weekOpts}</select>
      <select class="mini" id="sched-hour">${hoursOpts}</select><span>时</span>
      <select class="mini" id="sched-minute">${minsOpts}</select><span>分</span>`;
    $('#sched-weekday').value = Number(v.weekday ?? 1);
    $('#sched-hour').value    = Number(v.hour ?? 1);
    $('#sched-minute').value  = Number(v.minute ?? 30);
  } else if (type === 'monthly') {
    box.innerHTML = `
      每月 <select class="mini" id="sched-monthday">${mdOpts}</select><span>号</span>
      <select class="mini" id="sched-hour">${hoursOpts}</select><span>时</span>
      <select class="mini" id="sched-minute">${minsOpts}</select><span>分</span>`;
    $('#sched-monthday').value = Number(v.monthday ?? 1);
    $('#sched-hour').value     = Number(v.hour ?? 1);
    $('#sched-minute').value   = Number(v.minute ?? 30);
  } else if (type === 'custom') {
    box.innerHTML = `<input type="text" id="sched-cron" value="${esc(v.cron || '0 1 * * *')}" style="min-width:220px;font-family:ui-monospace,monospace;font-size:13px" placeholder="0 1 * * *">`;
  }
  updateCronSchedDesc();
}

function collectCronSchedule() {
  const t = $('#cron-sched-type').value;
  const s = { type: t };
  const v = id => { const el = $('#' + id); return el ? el.value : ''; };
  const toI = (x, d) => { const n = parseInt(x, 10); return isNaN(n) ? d : n; };
  if (t === 'daily') {
    s.hour = toI(v('sched-hour'), 0);
    s.minute = toI(v('sched-minute'), 0);
  } else if (t === 'hourly') {
    s.minute = toI(v('sched-minute'), 0);
  } else if (t === 'n_minutes' || t === 'n_hours') {
    s.n = toI(v('sched-n'), 1);
  } else if (t === 'weekly') {
    s.weekday = toI(v('sched-weekday'), 1);
    s.hour = toI(v('sched-hour'), 0);
    s.minute = toI(v('sched-minute'), 0);
  } else if (t === 'monthly') {
    s.monthday = toI(v('sched-monthday'), 1);
    s.hour = toI(v('sched-hour'), 0);
    s.minute = toI(v('sched-minute'), 0);
  } else if (t === 'custom') {
    s.cron = (v('sched-cron') || '').trim();
  }
  return s;
}

function updateCronSchedDesc() {
  const s = collectCronSchedule();
  const pad = n => String(n).padStart(2, '0');
  const weekNames = ['周日','周一','周二','周三','周四','周五','周六'];
  let desc = '';
  switch (s.type) {
    case 'daily':    desc = `每天的 ${pad(s.hour)}:${pad(s.minute)} 执行一次`; break;
    case 'hourly':   desc = `每小时的 ${pad(s.minute)} 分执行一次`; break;
    case 'n_minutes':desc = `每 ${s.n} 分钟执行一次`; break;
    case 'n_hours':  desc = `每 ${s.n} 小时执行一次`; break;
    case 'weekly':   desc = `每${weekNames[s.weekday]} ${pad(s.hour)}:${pad(s.minute)} 执行一次`; break;
    case 'monthly':  desc = `每月 ${s.monthday} 号 ${pad(s.hour)}:${pad(s.minute)} 执行一次`; break;
    case 'custom':   desc = `cron 表达式：${s.cron || '(未填写)'}`; break;
  }
  $('#cron-sched-desc').textContent = desc;
}

$('#cron-sched-type').addEventListener('change', () => {
  const t = $('#cron-sched-type').value;
  const defaults = { hour: 1, minute: 30, n: 5, weekday: 1, monthday: 1, cron: '0 1 * * *' };
  renderScheduleParams(t, defaults);
});

// 给周期参数里的所有控件挂 change/input 事件
$('#cron-sched-params').addEventListener('input', updateCronSchedDesc);
$('#cron-sched-params').addEventListener('change', updateCronSchedDesc);

$('#cron-save').addEventListener('click', async () => {
  const name = $('#cron-name').value.trim();
  const task_type = $('#cron-type').value;
  const run_user = $('#cron-user').value || 'root';
  const schedule = collectCronSchedule();
  const script = $('#cron-script').value;
  const use_lock = $('#cron-use-lock').checked;

  if (!name) { toast('请填写任务名称', 'error'); return; }
  if (!script.trim()) { toast('请填写脚本内容', 'error'); return; }
  if (schedule.type === 'custom' && !schedule.cron) {
    toast('请填写自定义 cron 表达式', 'error'); return;
  }

  const payload = {
    name, task_type, run_user, schedule, script,
    use_lock, enabled: true,
  };
  const btn = $('#cron-save'); btn.disabled = true; btn.textContent = '保存中…';
  try {
    let res;
    if (currentCronId) {
      res = await api('/api/cron/tasks/' + currentCronId, { method: 'PUT', body: payload });
    } else {
      res = await api('/api/cron/tasks', { method: 'POST', body: payload });
    }
    if (res.code === 0) {
      toast(res.msg || '已保存', 'ok');
      $('#cron-modal').hidden = true;
      loadCronTasks();
    } else {
      toast(res.msg, 'error', 4000);
    }
  } finally {
    btn.disabled = false; btn.textContent = '确定';
  }
});

$('#cron-list').addEventListener('click', async ev => {
  const tr = ev.target.closest('tr');
  if (!tr) return;
  const id = parseInt(tr.dataset.id, 10);
  const task = cronCache.find(t => t.id === id);
  if (!task) return;

  // 滑块切换
  if (ev.target.classList.contains('cron-enabled')) {
    const newState = ev.target.checked;
    const res = await api(`/api/cron/tasks/${id}/toggle`, {
      method: 'POST', body: { enabled: newState }
    });
    if (res.code === 0) {
      toast(res.msg || '已切换', 'ok');
      loadCronTasks();
    } else {
      toast(res.msg, 'error');
      ev.target.checked = !newState;
    }
    return;
  }

  const btn = ev.target.closest('button[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;

  if (act === 'run') {
    btn.disabled = true;
    const res = await api(`/api/cron/tasks/${id}/run`, { method: 'POST' });
    if (res.code === 0) {
      toast(res.msg || '已启动', 'ok');
      setTimeout(loadCronTasks, 500);
    } else {
      toast(res.msg, 'error', 4000);
    }
    btn.disabled = false;
  } else if (act === 'edit') {
    openCronModal(task);
  } else if (act === 'log') {
    openCronLog(task);
  } else if (act === 'delete') {
    const ok = await showConfirm('删除计划任务',
      `确定要删除「${task.name}」吗？\n该任务的 crontab 与脚本会被同时清除。`, 'trash-2');
    if (!ok) return;
    const res = await api(`/api/cron/tasks/${id}`, { method: 'DELETE' });
    if (res.code === 0) { toast('已删除', 'ok'); loadCronTasks(); }
    else toast(res.msg, 'error');
  }
});

async function openCronLog(task) {
  currentLogCronId = task.id;
  $('#cron-log-title').textContent = '任务日志：' + task.name;
  $('#cron-log-meta').textContent = '正在加载…';
  $('#cron-log-area').value = '';
  $('#cron-log-modal').hidden = false;
  try {
    const res = await api(`/api/cron/tasks/${task.id}/log`);
    if (res.code !== 0) {
      $('#cron-log-meta').textContent = res.msg;
      return;
    }
    const d = res.data;
    $('#cron-log-area').value = d.content || '(暂无日志)';
    const sizeTxt = d.size ? humanSize(d.size) : '0 B';
    $('#cron-log-meta').textContent =
      `日志大小 ${sizeTxt}` + (d.truncated ? ' · 只显示最后 512KB' : '');
    // 滚动到最底部
    const ta = $('#cron-log-area');
    ta.scrollTop = ta.scrollHeight;
  } catch (e) {
    $('#cron-log-meta').textContent = e.message;
  }
}

$('#cron-log-clear').addEventListener('click', async () => {
  if (!currentLogCronId) return;
  const ok = await showConfirm('清空日志', '确定清空该任务的日志文件吗？', 'trash-2');
  if (!ok) return;
  const res = await api(`/api/cron/tasks/${currentLogCronId}/log`, { method: 'DELETE' });
  if (res.code === 0) {
    toast('已清空', 'ok');
    $('#cron-log-area').value = '';
    $('#cron-log-meta').textContent = '日志大小 0 B';
  } else toast(res.msg, 'error');
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
   Docker 管理
   ============================================================ */
let dockerCurrentTab = 'containers';
let dockerCurrentLogId = '';
let dockerCurrentLogName = '';
let dockerStatusData = { installed: false, running: false };
let dockerContainersCache = [];

function dockerEsc(v) { return esc(v == null ? '' : String(v)); }
function dockerStateLabel(state) {
  const s = String(state || '').toLowerCase();
  if (s === 'installing') return '<span class="badge" style="background:rgba(245,158,11,.15);color:var(--warn)">安装中</span>';
  if (s === 'failed') return '<span class="badge off">创建失败</span>';
  if (s === 'running') return '<span class="badge on">运行中</span>';
  if (s === 'paused') return '<span class="badge" style="background:rgba(245,158,11,.15);color:var(--warn)">已暂停</span>';
  if (s === 'restarting') return '<span class="badge" style="background:rgba(245,158,11,.15);color:var(--warn)">重启中</span>';
  if (s === 'created') return '<span class="badge">已创建</span>';
  return '<span class="badge off">已停止</span>';
}
function dockerStateDot(state) {
  const s = String(state || '').toLowerCase();
  let cls = 'stopped', label = '已停止';
  if (s === 'running') { cls = 'running'; label = '运行中'; }
  else if (['installing', 'paused', 'restarting', 'created', 'starting'].includes(s)) { cls = 'installing'; label = s === 'installing' ? '安装中' : (s === 'paused' ? '已暂停' : (s === 'restarting' ? '重启中' : '启动中')); }
  else if (s === 'failed' || s === 'dead' || s === 'exited') { cls = 'stopped'; label = s === 'failed' ? '创建失败' : '已停止'; }
  return `<span class="docker-state-dot is-${cls}" role="img" aria-label="${label}" title="${label}"></span>`;
}
function dockerShortId(v) {
  const s = String(v || '').trim();
  const value = s.startsWith('sha256:') ? s.slice(7) : s;
  return value.length > 20 ? value.slice(0, 12) + '…' : value;
}
function dockerDurationZh(v) {
  return String(v || '—').replace(/\byears?\b/gi, '年').replace(/\bmonths?\b/gi, '个月')
    .replace(/\bweeks?\b/gi, '周').replace(/\bdays?\b/gi, '天')
    .replace(/\bhours?\b/gi, '小时').replace(/\bminutes?\b/gi, '分钟')
    .replace(/\bseconds?\b/gi, '秒').replace(/\s+ago$/i, '').replace(/\s+/g, '');
}
function dockerShowUnavailable(message) {
  $('#docker-unavailable').hidden = false;
  $('#docker-unavailable-msg').textContent = message || 'Docker 当前不可用。';
  $('#docker-status-dot').style.background = 'var(--danger)';
  $('#docker-status-title').textContent = dockerStatusData.installed ? 'Docker 服务未运行' : '未安装 Docker';
  $('#docker-version').textContent = '';
}
function dockerHideUnavailable() { $('#docker-unavailable').hidden = true; }

async function loadDockerStatus() {
  try {
    const r = await api('/api/docker/status');
    if (r.code !== 0) throw new Error(r.msg || '无法检测 Docker');
    dockerStatusData = r.data || {};
    if (!dockerStatusData.installed || !dockerStatusData.running) {
      dockerShowUnavailable(dockerStatusData.message);
      return false;
    }
    dockerHideUnavailable();
    $('#docker-status-dot').style.background = 'var(--ok)';
    $('#docker-status-title').textContent = 'Docker 运行正常';
    $('#docker-version').textContent = 'Engine ' + (dockerStatusData.version || '版本未知');
    return true;
  } catch (e) {
    dockerStatusData = { installed: false, running: false };
    dockerShowUnavailable(e.message);
    return false;
  }
}

async function dockerLoadJson(path) {
  const r = await api(path);
  if (r.code !== 0) throw new Error(r.msg || 'Docker 请求失败');
  return Array.isArray(r.data) ? r.data : [];
}

async function loadDockerContainers(silent = false) {
  try {
    dockerContainersCache = await dockerLoadJson('/api/docker/containers');
    renderDockerContainers();
    $('#docker-stat-running').textContent = dockerContainersCache.filter(x => !x.Pending && String(x.State).toLowerCase() === 'running').length;
    $('#docker-stat-stopped').textContent = dockerContainersCache.filter(x => !x.Pending && String(x.State).toLowerCase() !== 'running').length;
  } catch (e) {
    $('#docker-container-list').innerHTML = '';
    $('#docker-container-empty').hidden = false;
    $('#docker-container-empty').textContent = e.message;
    $('#docker-container-count').textContent = '';
    if (!silent) toast(e.message, 'error', 4200);
  }
}

function renderDockerContainers() {
  const query = ($('#docker-container-search').value || '').trim().toLowerCase();
  const filtered = dockerContainersCache.filter(x =>
    [x.Names, x.Image, x.Ports, x.Status, x.ID].some(v => String(v || '').toLowerCase().includes(query)));
  const body = $('#docker-container-list');
  body.innerHTML = filtered.map(x => {
    if (x.PendingTaskId) {
      const taskId = String(x.PendingTaskId);
      const name = String(x.Names || '新容器');
      const image = String(x.Image || '未知镜像');
      const acr = (name.replace(/^\//, '').split(/[^A-Za-z0-9]+/).filter(Boolean).map(part => part[0]).join('').toUpperCase().slice(0, 4)) || 'DOCK';
      const pct = Math.max(0, Math.min(100, Number(x.PendingPercent) || 0));
      const failed = String(x.State).toLowerCase() === 'failed';
      const message = String(x.PendingMessage || x.Status || (failed ? '创建失败' : '正在处理镜像并创建容器'));
      return `<article class="docker-container-card docker-pending-card">
        <div class="docker-container-main"><div class="docker-app-icon">${dockerEsc(acr)}</div>
          <div class="docker-container-copy"><div class="docker-container-title"><span class="docker-container-name" title="${dockerEsc(name)}">${dockerEsc(name)}</span>${dockerStateLabel(failed ? 'failed' : 'installing')}</div>
            <div class="docker-container-meta"><span class="docker-meta-chip">${dockerEsc(image)}</span>${failed ? '' : `<span class="docker-meta-chip">进度：${pct}%</span>`}</div>
            <div class="docker-pending-message">${dockerEsc(message)}</div>
          </div>
        </div>
        <div class="docker-container-footer"><button class="btn tiny" data-docker-task-view="${dockerEsc(taskId)}">查看日志</button>${failed ? `<button class="btn tiny danger" data-docker-pending-dismiss="${dockerEsc(taskId)}">清除</button>` : ''}</div>
      </article>`;
    }
    const id = String(x.ID || '').replace(/[^a-fA-F0-9]/g, '');
    const state = String(x.State || '').toLowerCase();
    const running = state === 'running';
    const name = String(x.Names || id || '未知容器');
    const image = String(x.Image || '未知镜像');
    const imageNoDigest = image.split('@')[0];
    const imageLeaf = imageNoDigest.split('/').pop() || imageNoDigest;
    const imageColon = imageLeaf.lastIndexOf(':');
    const version = imageColon > -1 ? imageLeaf.slice(imageColon + 1) : 'latest';
    const imageShort = imageColon > -1 ? imageLeaf.slice(0, imageColon) : imageLeaf;
    const compactDockerText = value => { const text = String(value || ''); return text.length > 10 ? `${text.slice(0, 4)}...${text.slice(-3)}` : text; };
    const versionDisplay = compactDockerText(version);
    const imageDisplay = compactDockerText(imageShort);
    const acr = (name.replace(/^\//, '').split(/[^A-Za-z0-9]+/).filter(Boolean).map(part => part[0]).join('').toUpperCase().slice(0, 4)) || 'DOCK';
    const publishedPorts = [];
    const rawPorts = String(x.Ports || '');
    // Docker CLI compresses consecutive mappings as e.g. 9876-9879->9876-9879/tcp.
    // Expand both ranges so every host port appears in the dropdown; IPv4/IPv6 duplicates are deduplicated below.
    for (const item of rawPorts.split(',')) {
      const m = item.trim().match(/(?:(?<addr>[^,\s]+):)?(?<hostStart>\d+)(?:-(?<hostEnd>\d+))?->(?<containerStart>\d+)(?:-(?<containerEnd>\d+))?\/(?<proto>tcp|udp)/i);
      if (!m) continue;
      const addr = String(m.groups.addr || '').replace(/:+$/, '');
      const hostStart = Number(m.groups.hostStart);
      const hostEnd = Number(m.groups.hostEnd || hostStart);
      const containerStart = Number(m.groups.containerStart);
      const containerEnd = Number(m.groups.containerEnd || containerStart);
      const hostCount = hostEnd - hostStart + 1;
      const containerCount = containerEnd - containerStart + 1;
      if (!Number.isInteger(hostStart) || !Number.isInteger(containerStart) || hostCount < 1 || containerCount < 1) continue;
      const count = hostCount === containerCount ? hostCount : Math.min(hostCount, containerCount);
      const protocol = m.groups.proto.toLowerCase();
      const domain = String(x.AccessDomain || '').trim();
      const domainPort = String(x.AccessPort || '').trim();
      const localOnly = /^(127\.0\.0\.1|localhost|\[?::1\]?)$/i.test(addr);
      for (let offset = 0; offset < count; offset++) {
        const hostPort = String(hostStart + offset);
        const containerPort = String(containerStart + offset);
        const key = hostPort + '/' + protocol;
        if (publishedPorts.some(p => p.key === key)) continue;
        let href = '';
        if (domain && (!domainPort || domainPort === hostPort)) {
          href = /^(https?:\/\/)/i.test(domain) ? domain : 'http://' + domain;
        } else if (!localOnly && protocol === 'tcp') {
          const hostname = window.location.hostname || 'localhost';
          href = 'http://' + (hostname.includes(':') && !hostname.startsWith('[') ? '[' + hostname + ']' : hostname) + ':' + hostPort;
        }
        publishedPorts.push({ key, hostPort, containerPort, protocol, href, addr });
      }
    }
    let actionButtons = '';
    if (running) actionButtons += `<button class="btn tiny" data-docker-act="stop" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">停止</button>`;
    else actionButtons += `<button class="btn tiny ok" data-docker-act="start" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">启动</button>`;
    actionButtons += `<button class="btn tiny" data-docker-act="restart" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">重启</button>`;
    actionButtons += `<button class="btn tiny danger" data-docker-act="remove" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">卸载</button>`;
    const renderPortChip = p => {
      const label = `${p.hostPort}/${p.protocol.toUpperCase()}`;
      // 精简显示为宿主机端口/协议；完整映射放在 title 悬停提示中。
      // 所有已发布端口都提供可点击入口；UDP 无法由普通浏览器直接访问，会在提示中说明协议限制。
      const hostname = window.location.hostname || 'localhost';
      const safeHost = hostname.includes(':') && !hostname.startsWith('[') ? '[' + hostname + ']' : hostname;
      const loopback = p.addr && /^(127\.0\.0\.1|localhost|\[?::1\]?)$/i.test(p.addr);
      const fallbackHref = loopback ? `http://127.0.0.1:${p.hostPort}` : `http://${safeHost}:${p.hostPort}`;
      const href = p.href || fallbackHref;
      const protocolNote = p.protocol === 'udp' ? '；UDP 服务不能通过普通浏览器直接访问，请使用对应客户端' : '';
      const localNote = loopback ? '；该端口只绑定到服务器本机地址' : '';
      return `<a class="docker-meta-chip docker-port-link" href="${dockerEsc(href)}" target="_blank" rel="noopener noreferrer" aria-label="打开端口 ${dockerEsc(p.hostPort)}，容器端口 ${dockerEsc(p.containerPort + '/' + p.protocol)}" title="${dockerEsc('宿主机 ' + p.hostPort + '/' + p.protocol.toUpperCase() + ' → 容器 ' + p.containerPort + '/' + p.protocol + '；打开 ' + href + protocolNote + localNote)}">${dockerEsc(label)} ↗</a>`;
    };
    const portChips = publishedPorts.length ? `<div class="docker-port-dropdown" data-docker-port-toggle tabindex="0" aria-expanded="false" title="悬停查看端口映射；菜单中的端口均可直接访问">
      <div class="docker-port-trigger">${renderPortChip(publishedPorts[0])}${publishedPorts.length > 1 ? `<span class="docker-port-more" aria-hidden="true">+${publishedPorts.length - 1}</span>` : ''}</div>
      <div class="docker-port-menu" role="menu" aria-label="容器端口列表">${publishedPorts.map(p => {
        const targetLabel = `${p.containerPort}/${p.protocol.toUpperCase()}`;
        return `<div class="docker-port-menu-item" role="none"><a class="docker-port-link" role="menuitem" href="${dockerEsc(p.href || (p.protocol === 'tcp' ? `http://${window.location.hostname || 'localhost'}:${p.hostPort}` : '#'))}" ${p.protocol === 'tcp' ? 'target="_blank" rel="noopener noreferrer"' : 'aria-disabled="true"'} title="宿主机 ${dockerEsc(p.hostPort + '/' + p.protocol.toUpperCase())} → 容器 ${dockerEsc(targetLabel)}"><span>${dockerEsc(p.hostPort + '/' + p.protocol.toUpperCase())}</span><small>→ ${dockerEsc(targetLabel)}${p.protocol === 'udp' ? ' · UDP' : ' ↗'}</small></a></div>`;
      }).join('')}</div>
    </div>` : `<span class="docker-meta-chip">无端口</span>`;
    return `<article class="docker-container-card">
      <div class="docker-container-main">
        <div class="docker-app-icon" title="${dockerEsc(image)}">${dockerEsc(acr)}</div>
        <div class="docker-container-copy">
          <div class="docker-container-title">
            <div class="docker-container-title-left">
              <span class="docker-container-name" title="${dockerEsc(name)}">${dockerEsc(name)}</span>
              <span class="docker-container-shortcuts docker-directory-shortcuts">
                <button type="button" title="打开运行/项目目录${x.WorkDirDisplay ? '：' + dockerEsc(x.WorkDirDisplay) : '（当前容器没有可访问的宿主机运行目录）'}" aria-label="打开运行目录" data-docker-path="workdir" data-path="${dockerEsc(x.WorkDirPanelPath || '')}" ${x.WorkDirPanelPath ? '' : 'disabled'}><svg viewBox="0 0 24 24"><path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v2M2 12h20l-2 7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 11v6m-3-3 3-3 3 3"/></svg></button>
                <button type="button" title="打开第一个挂载目录${x.MountDisplay ? '：' + dockerEsc(x.MountDisplay) : '（没有挂载目录）'}${Number(x.MountCount || 0) > 1 ? '，另有 ' + (Number(x.MountCount) - 1) + ' 个挂载' : ''}" aria-label="打开挂载目录" data-docker-path="mount" data-path="${dockerEsc(x.MountPanelPath || '')}" ${x.MountPanelPath ? '' : 'disabled'}><svg viewBox="0 0 24 24"><path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v2M2 12h20l-2 7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M8 15h8M12 12v6"/></svg></button>
              </span>
            </div>
          </div>
        </div>
        <div class="docker-container-header-actions" aria-label="容器状态与快捷操作">
          ${dockerStateDot(state)}
          <span class="docker-container-shortcuts">
            <button type="button" title="容器详情" aria-label="容器详情" data-docker-act="details" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7h.01"/></svg></button>
            <button type="button" title="查看日志" aria-label="查看日志" data-docker-act="logs" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}"><svg viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12M3 6h.01M3 12h.01M3 18h.01"/></svg></button>
          </span>
        </div>
      </div>
      <div class="docker-container-meta">
        <span class="docker-meta-chip docker-image-tag-chip" title="完整版本：${dockerEsc(version)}">${dockerEsc(versionDisplay)}</span>
        ${portChips}
        <span class="docker-meta-chip docker-image-ref-chip" title="完整镜像：${dockerEsc(image)}">${dockerEsc(imageDisplay)}</span>
      </div>
      <div class="docker-container-footer">
        <button class="btn tiny" data-docker-act="details" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">详情</button>
        <button class="btn tiny" data-docker-act="edit" data-id="${dockerEsc(id)}" data-name="${dockerEsc(name)}">编辑</button>
        ${actionButtons}
      </div>
    </article>`;
  }).join('');
  $('#docker-container-empty').hidden = filtered.length > 0;
  $('#docker-container-count').textContent = `共 ${filtered.length} / ${dockerContainersCache.length} 个容器`;
}

async function loadDockerImages(silent = false) {
  try {
    const rows = await dockerLoadJson('/api/docker/images');
    $('#docker-image-list').innerHTML = rows.map(x => {
      const id = String(x.ID || '').trim(); // 保留 sha256: 前缀，不能用十六进制白名单清洗，否则会破坏 ID。
      const repo = String(x.Repository || ''); const tag = String(x.Tag || '');
      const ref = repo && tag && repo !== '<none>' && tag !== '<none>' ? `${repo}:${tag}` : '';
      const name = ref || id;
      return `<tr><td>${dockerEsc(repo)}</td><td>${dockerEsc(tag)}</td><td title="${dockerEsc(id)}"><code>${dockerEsc(dockerShortId(id))}</code></td><td>${dockerEsc(x.Size || '')}</td><td>${dockerEsc(x.CreatedAt || x.CreatedSince || '')}</td><td class="docker-image-actions"><button class="btn tiny" data-docker-image-deploy="${dockerEsc(ref)}" data-image-name="${dockerEsc(ref)}" ${ref ? '' : 'disabled title="未标记的镜像不能直接部署，请先重新打标签"'}>部署</button><button class="btn tiny danger" data-docker-image-del="${dockerEsc(id)}" data-image-name="${dockerEsc(name)}">删除</button></td></tr>`;
    }).join('');
    $('#docker-image-empty').hidden = rows.length > 0;
    $('#docker-image-count').textContent = `共 ${rows.length} 个镜像`;
    $('#docker-stat-images').textContent = rows.length;
  } catch (e) { if (!silent) toast(e.message, 'error', 4200); }
}

async function loadDockerNetworks(silent = false) {
  try {
    const rows = await dockerLoadJson('/api/docker/networks');
    $('#docker-network-list').innerHTML = rows.map(x => {
      const id = String(x.ID || '');
      const name = String(x.Name || '');
      const builtin = ['bridge', 'host', 'none'].includes(name);
      return `<tr><td>${dockerEsc(name)}${builtin ? ' <span class="hint">内置</span>' : ''}</td><td><code>${dockerEsc(dockerShortId(id))}</code></td><td>${dockerEsc(x.Driver || '')}</td><td>${dockerEsc(x.Scope || '')}</td><td>${builtin ? '—' : `<button class="btn tiny danger" data-docker-network-del="${dockerEsc(name)}">删除</button>`}</td></tr>`;
    }).join('');
    $('#docker-network-empty').hidden = rows.length > 0;
    $('#docker-network-count').textContent = `共 ${rows.length} 个网络`;
  } catch (e) { if (!silent) toast(e.message, 'error', 4200); }
}

async function loadDockerVolumes(silent = false) {
  try {
    const rows = await dockerLoadJson('/api/docker/volumes');
    $('#docker-volume-list').innerHTML = rows.map(x => {
      const name = String(x.Name || '');
      return `<tr><td style="overflow-wrap:anywhere">${dockerEsc(name)}</td><td>${dockerEsc(x.Driver || '')}</td><td style="max-width:380px;overflow-wrap:anywhere">${dockerEsc(x.Mountpoint || '')}</td><td><button class="btn tiny danger" data-docker-volume-del="${dockerEsc(name)}">删除</button></td></tr>`;
    }).join('');
    $('#docker-volume-empty').hidden = rows.length > 0;
    $('#docker-volume-count').textContent = `共 ${rows.length} 个数据卷`;
    $('#docker-stat-volumes').textContent = rows.length;
  } catch (e) { if (!silent) toast(e.message, 'error', 4200); }
}

async function loadDocker() {
  const available = await loadDockerStatus();
  if (!available) {
    ['docker-stat-running', 'docker-stat-stopped', 'docker-stat-images', 'docker-stat-volumes'].forEach(id => { $('#' + id).textContent = '—'; });
    return;
  }
  await Promise.all([loadDockerContainers(true), loadDockerImages(true), loadDockerNetworks(true), loadDockerVolumes(true)]);
  await loadDockerTaskHistory();
}

async function dockerPost(url, body = {}) {
  const r = await api(url, { method: 'POST', body });
  if (r.code !== 0) throw new Error(r.msg || '操作失败');
  return r;
}

$('#docker-tabs').addEventListener('click', ev => {
  const btn = ev.target.closest('[data-docker-tab]');
  if (!btn) return;
  dockerCurrentTab = btn.dataset.dockerTab;
  $$('#docker-tabs .subtab').forEach(x => x.classList.toggle('active', x === btn));
  $$('.subpanel[id^="docker-panel-"]').forEach(x => x.classList.toggle('active', x.id === 'docker-panel-' + dockerCurrentTab));
  if (dockerCurrentTab === 'settings') loadDockerSettings();
});
$('#btn-docker-refresh').addEventListener('click', loadDocker);
let dockerInstallPolling = false;
function renderDockerInstallProgress(data) {
  const percent = Math.max(0, Math.min(100, Number(data.percent) || 0));
  $('#docker-install-stage').textContent = data.stage || (data.running ? '正在安装…' : '安装状态');
  $('#docker-install-percent').textContent = `${percent}%`;
  $('#docker-install-bar').style.width = `${percent}%`;
  $('#docker-install-message').textContent = data.message || '';
  const logs = Array.isArray(data.logs) ? data.logs : [];
  $('#docker-install-log').textContent = logs.join('\n');
  $('#docker-install-log').scrollTop = $('#docker-install-log').scrollHeight;
  $('#docker-install-footnote').textContent = data.done
    ? (data.success ? '安装完成' : '安装失败，请查看上方日志')
    : `当前阶段：${data.stage || '准备中'} · 请保持此窗口打开`;
  $('#docker-install-close').disabled = !data.done;
  $('#docker-install-close').textContent = data.done ? '关闭' : '安装中…';
  $('#docker-install-bar').style.background = data.done && !data.success ? 'var(--danger)' : 'var(--accent)';
}

$('#docker-install-close').addEventListener('click', () => {
  if ($('#docker-install-close').disabled) return;
  $('#docker-install-modal').hidden = true;
});

async function monitorDockerInstall() {
  dockerInstallPolling = true;
  $('#docker-install-modal').hidden = false;
  $('#docker-install-log').textContent = '';
  renderDockerInstallProgress({ percent: 1, stage: '准备安装', message: '安装任务已启动，正在读取实时进度', logs: [] });
  let lastData = null;
  try {
    while (true) {
      try {
        const r = await api('/api/docker/install/status');
        if (r.code !== 0) throw new Error(r.msg || '读取安装进度失败');
        lastData = r.data || {};
        if (!lastData.task_id && !lastData.done && !lastData.running) {
          lastData = { ...lastData, done: true, success: false,
            stage: '安装进度丢失', message: lastData.message || '安装任务状态不存在，可能是面板重启导致。',
            result: lastData.message || '安装任务状态不存在，可能是面板重启导致。' };
        }
        renderDockerInstallProgress(lastData);
        if (lastData.done) return lastData;
      } catch (e) {
        $('#docker-install-message').textContent = '读取安装进度暂时失败，将自动重试：' + e.message;
      }
      await new Promise(resolve => setTimeout(resolve, 900));
    }
  } finally { dockerInstallPolling = false; }
}

$('#btn-docker-install').addEventListener('click', async () => {
  const ok = await showConfirm('安装 Docker Engine', '将通过 Ubuntu/Debian 系统软件源执行 apt-get update、安装 docker.io，并启用 Docker 服务。安装进度和命令输出会在弹窗中实时显示，此操作会修改系统软件包并启动后台服务。确定继续吗？', 'download');
  if (!ok) return;
  const btn = $('#btn-docker-install');
  btn.disabled = true; btn.textContent = '正在准备…';
  try {
    const r = await dockerPost('/api/docker/install', {});
    if (r.data && r.data.already_running) {
      toast(r.data.message || r.msg || 'Docker 已经运行', 'ok', 5000);
      await loadDocker();
      return;
    }
    btn.textContent = '正在安装…';
    const result = await monitorDockerInstall();
    if (result.success) {
      toast(result.result || result.message || 'Docker 安装成功', 'ok', 6500);
      await loadDocker();
    } else {
      toast(result.result || result.message || 'Docker 安装失败，请检查 apt 软件源和服务器网络', 'error', 9000);
      await loadDockerStatus();
    }
  } catch (e) {
    toast(e.message || 'Docker 安装失败，请检查 apt 软件源和服务器网络', 'error', 8000);
    await loadDockerStatus();
  } finally { btn.disabled = false; btn.textContent = '安装 Docker Engine'; }
});
let dockerSettingsCache = null;
function setDockerMirrorCustomVisibility() {
  const source = $('#docker-mirror-source').value;
  const needsUrl = ['aliyun', 'custom', 'school-custom'].includes(source);
  $('#docker-mirror-custom-wrap').hidden = !needsUrl;
  const note = {
    official: '官方源不配置 registry-mirrors，直接连接 Docker Hub。你当前服务器访问官方仓库超时，选择此项可能仍会拉取失败。',
    aliyun: '阿里云加速器需要从阿里云容器镜像服务控制台获取账号专属地址。阿里云官方文档提示其 Docker Hub 加速目前已停止同步最新镜像，latest 标签可能不新或无法拉取。',
    ustc: '该高校源目前已暂停 Docker Hub 缓存服务，因此不可选。可选择“自定义高校 / 单位镜像源”自行填写有效地址。',
    'school-custom': '请填写学校或单位运维方提供的 Docker Hub 镜像加速地址，必须是 HTTPS 域名地址。',
    custom: '仅填写可信服务商提供的 HTTPS 镜像加速器根地址。公共地址可能随时失效，请先测试后应用。',
    '1panel': '公共镜像服务，可能有地区/网络限制。若无法拉取目标镜像，请测试或更换其他源。',
    daocloud: 'DaoCloud 公共镜像服务。公共镜像并不保证所有镜像和标签始终可用。',
    '1ms': '社区公共镜像服务，稳定性和覆盖范围可能变化。',
    dockerproxy: '社区公共镜像服务，稳定性和覆盖范围可能变化。',
    'dockerproxy-link': '社区公共镜像服务，稳定性和覆盖范围可能变化。',
    'dockerproxy-cool': '社区公共镜像服务，稳定性和覆盖范围可能变化；应用前建议先测试。',
    cnix: 'CNIX 公共镜像候选，服务可用性取决于你所在地区的线路和当前维护情况；应用前请先测试。',
    rat: '社区公共镜像候选，服务可用性和覆盖范围可能变化；应用前请先测试。',
    jiaxin: '社区公共镜像候选，服务可用性和覆盖范围可能变化；应用前请先测试。',
    'tencent-internal': '腾讯云内网加速地址，仅适用于符合条件的腾讯云内网主机，普通公网主机通常无法使用。'
  };
  $('#docker-mirror-note').textContent = note[source] || '';
}
$('#docker-mirror-source').addEventListener('change', setDockerMirrorCustomVisibility);

async function loadDockerSettings() {
  try {
    const r = await api('/api/docker/settings');
    if (r.code !== 0) throw new Error(r.msg || '无法读取 Docker 设置');
    dockerSettingsCache = r.data || {};
    const state = dockerSettingsCache.service || {};
    const badge = $('#docker-service-state');
    badge.textContent = state.active ? '服务运行中' : `服务${state.active_state === 'inactive' ? '已停止' : '不可用'}`;
    badge.className = state.active ? 'badge on' : 'badge off';
    $('#btn-docker-service-start').disabled = !dockerSettingsCache.installed || !!state.active;
    $('#btn-docker-service-stop').disabled = !dockerSettingsCache.installed || !state.active;
    $('#btn-docker-service-restart').disabled = !dockerSettingsCache.installed;
    $('#btn-docker-service-enable').disabled = !dockerSettingsCache.installed || !!state.enabled;
    $('#btn-docker-service-disable').disabled = !dockerSettingsCache.installed || !state.enabled;
    const mirrors = Array.isArray(dockerSettingsCache.mirrors) ? dockerSettingsCache.mirrors : [];
    $('#docker-mirror-current').textContent = mirrors.length ? ('当前配置：' + mirrors.join('、')) : '当前配置：未设置加速器（Docker Hub 官方源）';
    if (dockerSettingsCache.config_error) $('#docker-mirror-current').textContent += '；注意：' + dockerSettingsCache.config_error;
    const mirrorToKey = Object.fromEntries(Object.entries(dockerSettingsCache.presets || {}).map(([k, v]) => [v.replace(/\/$/, ''), k]));
    let source = mirrors.length === 0 ? 'official' : (mirrors.length === 1 ? (mirrorToKey[mirrors[0].replace(/\/$/, '')] || '') : '');
    if (!source && mirrors.length === 1) {
      const m = mirrors[0];
      if (/\.mirror\.aliyuncs\.com\/?$/i.test(m)) source = 'aliyun';
    }
    if (!source) source = mirrors.length ? 'custom' : 'official';
    const sourceOption = $('#docker-mirror-source').querySelector(`option[value="${source}"]`);
    if (sourceOption && !sourceOption.disabled) {
      $('#docker-mirror-source').value = source;
      if (source === 'aliyun' || source === 'custom' || source === 'school-custom') $('#docker-mirror-custom-url').value = mirrors[0] || '';
    }
    setDockerMirrorCustomVisibility();
  } catch (e) {
    $('#docker-service-state').textContent = '读取失败';
    $('#docker-service-state').className = 'badge off';
    $('#docker-mirror-current').textContent = e.message;
  }
}

async function dockerServiceAction(action, label) {
  const warnings = {
    stop: '停止 Docker 将影响这台主机上所有正在运行的容器服务。确定继续吗？',
    restart: '重启 Docker 可能短暂中断运行中的容器网络或管理操作。确定继续吗？',
    disable: '取消开机自启后，服务器重启时 Docker 不会自动启动。确定继续吗？'
  };
  if (warnings[action] && !(await showConfirm(label, warnings[action], 'alert-triangle'))) return;
  const btn = $('#btn-docker-service-' + action);
  const old = btn.textContent; btn.disabled = true; btn.textContent = '处理中…';
  try {
    const r = await dockerPost('/api/docker/service', { action });
    toast(r.msg || `${label}成功`, 'ok', 5000);
    await loadDockerSettings();
    if (action === 'start' || action === 'restart') await loadDocker();
  } catch (e) { toast(e.message, 'error', 6000); }
  finally { btn.textContent = old; await loadDockerSettings(); }
}
$('#btn-docker-service-start').addEventListener('click', () => dockerServiceAction('start', '启动 Docker'));
$('#btn-docker-service-stop').addEventListener('click', () => dockerServiceAction('stop', '停止 Docker'));
$('#btn-docker-service-restart').addEventListener('click', () => dockerServiceAction('restart', '重启 Docker'));
$('#btn-docker-service-enable').addEventListener('click', () => dockerServiceAction('enable', '设置开机自启'));
$('#btn-docker-service-disable').addEventListener('click', () => dockerServiceAction('disable', '取消开机自启'));

$('#btn-docker-apply-mirror').addEventListener('click', async () => {
  const source = $('#docker-mirror-source').value;
  const url = $('#docker-mirror-custom-url').value.trim();
  if (['aliyun', 'custom', 'school-custom'].includes(source) && !url) { toast('请先填写镜像源地址', 'error'); return; }
  const labels = { official: '官方源', aliyun: '阿里云专属源', '1panel': '1Panel 公共源', daocloud: 'DaoCloud 公共源', '1ms': '毫秒镜像源', dockerproxy: 'Docker Proxy', 'dockerproxy-link': 'Docker Proxy', 'dockerproxy-cool': 'Docker Proxy', cnix: 'CNIX 公共源', rat: '耗子面板公共源', jiaxin: '简行公共源', 'tencent-internal': '腾讯云内网源', 'school-custom': '自定义高校/单位源', custom: '自定义源' };
  const ok = await showConfirm('应用 Docker 镜像源', `即将配置：${labels[source] || source}${url ? '\n' + url : ''}\n\n若 Docker 当前正在运行，系统会重启 Docker 服务；未启用 live-restore 时，运行中的容器可能中断或停止。`, 'refresh-cw');
  if (!ok) return;
  const btn = $('#btn-docker-apply-mirror'); const old = btn.textContent; btn.disabled = true; btn.textContent = '正在应用…';
  try {
    const r = await dockerPost('/api/docker/mirror', { source, url });
    toast(r.msg || 'Docker 镜像源已更新', 'ok', 8000);
    await loadDockerSettings(); await loadDockerStatus();
  } catch (e) { toast(e.message, 'error', 8000); await loadDockerSettings(); }
  finally { btn.disabled = false; btn.textContent = old; }
});

$('#btn-docker-test-mirror').addEventListener('click', async () => {
  const source = $('#docker-mirror-source').value;
  const url = $('#docker-mirror-custom-url').value.trim();
  const presets = (dockerSettingsCache && dockerSettingsCache.presets) || {};
  let endpoint = '';
  if (source === 'official') endpoint = 'https://registry-1.docker.io';
  else if (source === 'aliyun' || source === 'custom' || source === 'school-custom') endpoint = url;
  else endpoint = presets[source] || '';
  if (!endpoint) { toast('该镜像源当前不可测试，请先填写地址', 'error'); return; }
  const btn = $('#btn-docker-test-mirror'); const old = btn.textContent; btn.disabled = true; btn.textContent = '测试中…';
  try {
    const r = await dockerPost('/api/docker/mirror/test', { url: endpoint });
    toast(r.msg || '测试完成', r.data && r.data.ok ? 'ok' : 'error', 7000);
  } catch (e) { toast(e.message, 'error', 7000); }
  finally { btn.disabled = false; btn.textContent = old; }
});

async function openDockerConfigEditor() {
  const r = await api('/api/docker/config');
  if (r.code !== 0) throw new Error(r.msg || '无法打开配置文件');
  $('#docker-config-path').textContent = r.data.path + (r.data.exists ? '' : '（文件不存在，保存时将新建）');
  $('#docker-config-content').value = r.data.content || '{}\n';
  $('#docker-config-msg').textContent = '';
  $('#docker-config-modal').hidden = false;
}
$('#btn-docker-open-config').addEventListener('click', async () => {
  try { await openDockerConfigEditor(); }
  catch (e) { toast(e.message, 'error', 6000); }
});
$('#btn-docker-config-reload').addEventListener('click', async () => {
  try { await openDockerConfigEditor(); }
  catch (e) { $('#docker-config-msg').textContent = e.message; }
});
$('#btn-docker-config-save').addEventListener('click', async () => {
  const btn = $('#btn-docker-config-save'); const old = btn.textContent;
  btn.disabled = true; btn.textContent = '保存并应用中…'; $('#docker-config-msg').textContent = '';
  try {
    const r = await dockerPost('/api/docker/config', { content: $('#docker-config-content').value });
    $('#docker-config-content').value = r.data.content || $('#docker-config-content').value;
    $('#docker-config-msg').textContent = r.msg || '保存成功';
    toast(r.msg || 'Docker 配置已保存', 'ok', 8000);
    await loadDockerSettings(); await loadDockerStatus();
  } catch (e) { $('#docker-config-msg').textContent = e.message; toast(e.message, 'error', 8000); }
  finally { btn.disabled = false; btn.textContent = old; }
});

$('#btn-docker-uninstall').addEventListener('click', async () => {
  const ok = await showConfirm('卸载 Docker Engine', '确定卸载 Docker 软件包吗？\n\n这会停止 Docker 服务并移除 apt/dpkg 安装的 Docker 组件；容器、镜像和数据卷所在的 /var/lib/docker 不会被自动删除。已运行的面板如果依赖 Docker，相关功能将不可用。', 'alert-triangle');
  if (!ok) return;
  const btn = $('#btn-docker-uninstall'); const old = btn.textContent; btn.disabled = true; btn.textContent = '卸载中…';
  try {
    const r = await dockerPost('/api/docker/uninstall', {});
    toast(r.msg || 'Docker 已卸载', 'ok', 9000);
    await loadDockerStatus(); await loadDockerSettings();
  } catch (e) { toast(e.message, 'error', 9000); }
  finally { btn.disabled = false; btn.textContent = old; }
});

$('#docker-container-search').addEventListener('input', renderDockerContainers);
$('#btn-docker-create').addEventListener('click', () => {
  $('#docker-run-name').value = ''; $('#docker-run-image').value = '';
  $('#docker-run-ports').value = ''; $('#docker-run-volumes').value = ''; $('#docker-run-env').value = '';
  $('#docker-run-restart').value = 'unless-stopped';
  $('#docker-create-modal').hidden = false;
  setTimeout(() => $('#docker-run-name').focus(), 50);
});

$('#btn-docker-run-submit').addEventListener('click', async () => {
  const body = {
    name: $('#docker-run-name').value.trim(), image: $('#docker-run-image').value.trim(),
    ports: $('#docker-run-ports').value, volumes: $('#docker-run-volumes').value,
    env: $('#docker-run-env').value, restart: $('#docker-run-restart').value
  };
  if (!body.name || !body.image) { toast('请填写容器名称和镜像名称', 'error'); return; }
  const btn = $('#btn-docker-run-submit'); const old = btn.textContent; btn.disabled = true; btn.textContent = '提交中…';
  try {
    const r = await dockerPost('/api/docker/containers/run', body);
    $('#docker-create-modal').hidden = true;
    const task = r.data || {};
    rememberDockerTask(task);
    // Switch to container cards immediately: the placeholder remains visible while the image pulls.
    dockerCurrentTab = 'containers';
    $$('#docker-tabs .subtab').forEach(x => x.classList.toggle('active', x.dataset.dockerTab === 'containers'));
    $$('.subpanel[id^="docker-panel-"]').forEach(x => x.classList.toggle('active', x.id === 'docker-panel-containers'));
    renderDockerContainers();
    toast(`容器卡片「${body.name}」已创建，正在后台检查镜像并安装；可点击日志图标查看进度。`, 'ok', 5000);
    if (task.task_id) pollDockerTask(task.task_id);
  } catch (e) { toast(e.message, 'error', 6000); }
  finally { btn.disabled = false; btn.textContent = old; }
});

const dockerTaskCache = new Map();
const dockerTaskPolling = new Set();
let dockerSelectedTaskId = '';
let dockerTaskNoticeShown = new Set();
function renderDockerPullProgress(data) {
  const pct = Math.max(0, Math.min(100, Number(data.percent) || 0));
  const kindLabel = data.kind === 'container-create' ? '创建容器' : '拉取镜像';
  $('#docker-pull-progress-title').textContent = data.container_name ? `Docker 任务 · ${data.container_name}` : `Docker 任务 · ${data.image || kindLabel}`;
  $('#docker-pull-progress-stage').textContent = data.stage || '正在处理…';
  $('#docker-pull-progress-percent').textContent = pct + '%';
  $('#docker-pull-progress-bar').style.width = pct + '%';
  $('#docker-pull-progress-bar').style.background = data.done && !data.success ? 'var(--danger)' : 'var(--accent)';
  $('#docker-pull-progress-message').textContent = data.message || '';
  $('#docker-pull-progress-log').textContent = (Array.isArray(data.logs) ? data.logs : []).join('\n');
  $('#docker-pull-progress-log').scrollTop = $('#docker-pull-progress-log').scrollHeight;
  $('#docker-pull-progress-footnote').textContent = data.done
    ? (data.success ? '任务已完成' : (data.cancelled ? '任务已停止' : '任务失败，请查看日志'))
    : '任务在后台运行；关闭此窗口不会中断任务。';
  const cancelBtn = $('#docker-pull-progress-cancel');
  cancelBtn.hidden = !data.running || data.kind === 'container-create';
  cancelBtn.disabled = !!data.cancel_requested;
  cancelBtn.textContent = data.cancel_requested ? '正在停止…' : '停止拉取';
}
function refreshDockerTaskSelector() {
  const select = $('#docker-pull-task-select');
  const tasks = [...dockerTaskCache.values()].sort((a, b) => (Number(b.updated_at) || 0) - (Number(a.updated_at) || 0));
  const wanted = dockerSelectedTaskId || (tasks[0] && tasks[0].task_id) || '';
  const optionRows = tasks.map(t => {
    const title = t.container_name ? `${t.container_name} · 创建容器` : `${t.image || '镜像'} · 拉取镜像`;
    const status = t.running ? '进行中' : (t.success ? '完成' : '失败');
    return {id: t.task_id, label: status + ' · ' + title};
  });
  const signature = optionRows.map(o => `${o.id}|${o.label}`).join('\n');
  if (select.dataset.signature !== signature) {
    select.innerHTML = optionRows.map(o => `<option value="${dockerEsc(o.id)}">${dockerEsc(o.label)}</option>`).join('');
    select.dataset.signature = signature;
  }
  if (tasks.some(t => t.task_id === wanted)) dockerSelectedTaskId = wanted;
  else dockerSelectedTaskId = tasks[0]?.task_id || '';
  select.value = dockerSelectedTaskId;
  const selected = dockerTaskCache.get(dockerSelectedTaskId);
  if (selected && !$('#docker-pull-progress-modal').hidden) renderDockerPullProgress(selected);
}
function updateDockerTaskIndicator() {
  const tasks = [...dockerTaskCache.values()];
  const active = tasks.filter(t => t.running).length;
  const badge = $('#docker-task-count');
  badge.textContent = String(active);
  badge.hidden = active === 0;
  $('#btn-docker-task-logs').title = active ? `${active} 个 Docker 后台任务正在运行，点击查看日志` : '查看 Docker 任务日志';
  refreshDockerTaskSelector();
}
function showDockerTaskLogs(taskId = '') {
  if (taskId && dockerTaskCache.has(taskId)) dockerSelectedTaskId = taskId;
  refreshDockerTaskSelector();
  $('#docker-pull-progress-modal').hidden = false;
  const selected = dockerTaskCache.get(dockerSelectedTaskId);
  if (selected) renderDockerPullProgress(selected);
  else {
    $('#docker-pull-progress-title').textContent = 'Docker 任务日志';
    $('#docker-pull-progress-stage').textContent = '暂无任务';
    $('#docker-pull-progress-percent').textContent = '0%';
    $('#docker-pull-progress-bar').style.width = '0%';
    $('#docker-pull-progress-message').textContent = '拉取镜像或创建容器后，任务日志会显示在这里。';
    $('#docker-pull-progress-log').textContent = '';
    $('#docker-pull-progress-footnote').textContent = '你可以关闭此窗口，后台任务不会中断。';
  }
}
$('#btn-docker-task-logs').addEventListener('click', () => showDockerTaskLogs());
$('#docker-pull-progress-cancel').addEventListener('click', async () => {
  const task = dockerTaskCache.get(dockerSelectedTaskId);
  if (!task || !task.running || task.kind === 'container-create') return;
  const ok = await showConfirm('停止镜像拉取', `确定停止拉取镜像「${task.image || ''}」吗？`, 'square');
  if (!ok) return;
  const btn = $('#docker-pull-progress-cancel'); btn.disabled = true; btn.textContent = '正在停止…';
  try {
    const r = await dockerPost(`/api/docker/tasks/${encodeURIComponent(task.task_id)}/cancel`, {});
    toast(r.msg || '已发送停止请求', 'ok', 3000);
    task.cancel_requested = true; task.stage = '正在停止'; task.message = '正在终止 Docker 拉取进程…';
    dockerTaskCache.set(task.task_id, task); renderDockerPullProgress(task);
  } catch (e) { btn.disabled = false; toast(e.message, 'error', 5000); }
});
$('#docker-pull-progress-close').addEventListener('click', () => { $('#docker-pull-progress-modal').hidden = true; });
$('#docker-pull-progress-close-top').addEventListener('click', () => { $('#docker-pull-progress-modal').hidden = true; });
$('#docker-pull-task-select').addEventListener('change', ev => {
  dockerSelectedTaskId = ev.target.value;
  const selected = dockerTaskCache.get(dockerSelectedTaskId);
  if (selected) renderDockerPullProgress(selected);
});

function updatePendingContainerCard(task) {
  if (!task || task.kind !== 'container-create' || !task.container_name) return;
  const existing = dockerContainersCache.find(x => x.PendingTaskId === task.task_id);
  if (task.done && task.success) {
    dockerContainersCache = dockerContainersCache.filter(x => x.PendingTaskId !== task.task_id);
    renderDockerContainers();
    return;
  }
  const placeholder = {
    ID: '', Names: task.container_name, Image: task.container_image || task.image,
    Ports: task.container_ports || '', State: task.done && !task.success ? 'failed' : 'installing',
    Status: task.message || '', Pending: true, PendingTaskId: task.task_id,
    PendingPercent: task.percent || 0, PendingStage: task.stage || '', PendingMessage: task.message || ''
  };
  if (existing) Object.assign(existing, placeholder);
  else dockerContainersCache.unshift(placeholder);
  renderDockerContainers();
  $('#docker-stat-running').textContent = dockerContainersCache.filter(x => !x.Pending && String(x.State).toLowerCase() === 'running').length;
  $('#docker-stat-stopped').textContent = dockerContainersCache.filter(x => !x.Pending && String(x.State).toLowerCase() !== 'running').length;
}
function rememberDockerTask(data) {
  if (!data || !data.task_id) return;
  const existing = dockerTaskCache.get(data.task_id) || {};
  const task = {...existing, ...data};
  dockerTaskCache.set(task.task_id, task);
  if (!dockerSelectedTaskId || (task.running && Number(task.updated_at || 0) >= Number(dockerTaskCache.get(dockerSelectedTaskId)?.updated_at || 0))) dockerSelectedTaskId = task.task_id;
  updatePendingContainerCard(task);
  updateDockerTaskIndicator();
}
async function pollDockerTask(taskId, notify = true) {
  if (dockerTaskPolling.has(taskId)) return;
  dockerTaskPolling.add(taskId);
  try {
    while (true) {
      const r = await api('/api/docker/images/pull/status?task_id=' + encodeURIComponent(taskId));
      if (r.code !== 0) throw new Error(r.msg || '读取任务进度失败');
      const data = r.data || {};
      rememberDockerTask(data);
      if (data.done) {
        if (!dockerTaskNoticeShown.has(taskId)) {
          dockerTaskNoticeShown.add(taskId);
          if (data.success) {
            toast(data.result || 'Docker 后台任务完成', 'ok', 5000);
            if (data.kind === 'container-create') {
              await loadDockerContainers(true);
            } else {
              await loadDockerImages(true);
            }
            // Successful task logs are transient: remove them immediately so the next task is selected automatically.
            try { await dockerPost(`/api/docker/tasks/${encodeURIComponent(taskId)}/dismiss`, {}); } catch (_) {}
            dockerTaskCache.delete(taskId);
            if (dockerSelectedTaskId === taskId) dockerSelectedTaskId = '';
            refreshDockerTaskSelector();
          } else if (data.cancelled) {
            toast('镜像拉取已停止', 'ok', 3500);
            try { await dockerPost(`/api/docker/tasks/${encodeURIComponent(taskId)}/dismiss`, {}); } catch (_) {}
            dockerTaskCache.delete(taskId);
            if (dockerSelectedTaskId === taskId) dockerSelectedTaskId = '';
            refreshDockerTaskSelector();
          } else {
            toast((data.container_name ? `容器 ${data.container_name} 创建失败：` : 'Docker 任务失败：') + (data.result || data.message || '未知错误'), 'error', 8000);
          }
        }
        return data;
      }
      await new Promise(resolve => setTimeout(resolve, 850));
    }
  } catch (e) {
    const prior = dockerTaskCache.get(taskId) || {task_id: taskId};
    rememberDockerTask({...prior, running: false, done: true, success: false, stage: '读取任务失败', message: e.message, result: e.message});
    if (!dockerTaskNoticeShown.has(taskId)) { dockerTaskNoticeShown.add(taskId); toast(e.message, 'error', 7000); }
    return null;
  } finally {
    dockerTaskPolling.delete(taskId);
    updateDockerTaskIndicator();
  }
}
async function loadDockerTaskHistory() {
  try {
    const r = await api('/api/docker/tasks');
    if (r.code !== 0 || !Array.isArray(r.data)) return;
    r.data.forEach(task => rememberDockerTask(task));
    updateDockerTaskIndicator();
    r.data.filter(task => task.running && task.task_id).forEach(task => pollDockerTask(task.task_id, false));
  } catch (e) { /* Task log history is optional; keep the Docker page usable. */ }
}
async function startDockerPullTask(image) {
  const r = await dockerPost('/api/docker/images/pull', {image});
  rememberDockerTask(r.data || {});
  toast(`已开始后台拉取 ${image}，可点击右上角日志图标查看进度。`, 'ok', 4500);
  pollDockerTask(r.data.task_id);
  return r.data;
}
$('#btn-docker-pull').addEventListener('click', async () => {
  const image = $('#docker-pull-image').value.trim();
  if (!image) { toast('请填写要拉取的镜像名称', 'error'); return; }
  const ok = await showConfirm('拉取 Docker 镜像', `将后台拉取镜像：${image}\n\n提交后会立即返回，你可以继续使用面板，并通过任务日志图标查看进度。继续吗？`, 'download');
  if (!ok) return;
  const btn = $('#btn-docker-pull'); const old = btn.textContent; btn.disabled = true; btn.textContent = '提交中…';
  try {
    await startDockerPullTask(image);
    $('#docker-pull-image').value = '';
  } catch (e) { toast(e.message, 'error', 8000); }
  finally { btn.disabled = false; btn.textContent = old; }
});

$('#docker-container-list').addEventListener('click', async ev => {
  const pathBtn = ev.target.closest('[data-docker-path]');
  if (pathBtn) { ev.stopPropagation(); openDockerHostDirectory(pathBtn.dataset.path || '', pathBtn.dataset.dockerPath === 'mount' ? '挂载目录' : '运行目录'); return; }
  const portGroup = ev.target.closest('[data-docker-port-toggle]');
  if (portGroup && !ev.target.closest('a')) {
    const expanded = !portGroup.classList.contains('expanded');
    document.querySelectorAll('.docker-port-dropdown.expanded').forEach(el => { el.classList.remove('expanded'); el.setAttribute('aria-expanded', 'false'); });
    if (expanded) { portGroup.classList.add('expanded'); portGroup.setAttribute('aria-expanded', 'true'); }
    return;
  }
  const btn = ev.target.closest('[data-docker-act]'); if (!btn) return;
  const action = btn.dataset.dockerAct, id = btn.dataset.id, name = btn.dataset.name || id;
  if (!id) { toast('容器 ID 不可用，请刷新后重试', 'error'); return; }
  if (action === 'edit') {
    try { await openDockerContainerEditor(id, name); }
    catch (e) { toast(e.message, 'error', 7000); }
    return;
  }
  if (action === 'logs') {
    dockerCurrentLogId = id; dockerCurrentLogName = name;
    $('#docker-logs-title').textContent = '容器日志 · ' + name;
    $('#docker-log-content').textContent = '正在加载…'; $('#docker-logs-modal').hidden = false;
    await loadDockerLogs(); return;
  }
  if (action === 'details') {
    try {
      const r = await api(`/api/docker/containers/${encodeURIComponent(id)}/inspect`);
      if (r.code !== 0) throw new Error(r.msg || '读取容器详情失败');
      const info = Array.isArray(r.data) ? (r.data[0] || {}) : (r.data || {});
      const cfg = info.Config || {}, state = info.State || {}, host = info.HostConfig || {};
      const network = info.NetworkSettings || {};
      const ports = [];
      const seenPortMappings = new Set();
      Object.entries(network.Ports || {}).forEach(([containerPort, bindings]) => {
        const parsed = String(containerPort).match(/^(\d+)\/(tcp|udp)$/i);
        if (!parsed) return;
        const internalPort = parsed[1];
        const protocol = parsed[2].toUpperCase();
        (bindings || []).forEach(b => {
          const hostPort = String((b || {}).HostPort || '').trim();
          if (!/^\d+$/.test(hostPort)) return;
          // IPv4 and IPv6 bindings for the same mapping are displayed once; HostIp is intentionally omitted.
          const mapping = `${hostPort}:${internalPort}/${protocol}`;
          if (seenPortMappings.has(mapping)) return;
          seenPortMappings.add(mapping);
          ports.push(mapping);
        });
      });
      const mounts = (info.Mounts || []).map(m => `${m.Source || ''} → ${m.Destination || ''}${m.RW === false ? '（只读）' : ''}`);
      const restart = (host.RestartPolicy || {}).Name || 'no';
      const memoryMb = host.Memory ? (host.Memory / 1024 / 1024).toFixed(0) + ' MB' : '不限制';
      const cpus = host.NanoCpus ? (host.NanoCpus / 1e9).toFixed(2) + ' 核' : '不限制';
      const command = [cfg.Entrypoint, cfg.Cmd].flat().filter(Boolean).join(' ');
      const rows = [
        ['容器名称', String(info.Name || name).replace(/^\//, '')], ['状态', `${state.Status || '未知'}${state.Running && state.StartedAt ? ' · 启动于 ' + state.StartedAt : ''}`],
        ['镜像', cfg.Image || '—'], ['容器 ID', info.Id || id],
        // Keep creation time paired with restart policy, so the full-width port block does not leave an empty grid cell.
        ['创建时间', info.Created || '—'], ['重启策略', restart],
        ['端口映射', ports.join('\n') || '无端口映射'], ['资源限制', `CPU：${cpus}\n内存：${memoryMb}`],
        ['工作目录', cfg.WorkingDir || '—'], ['启动命令', command || '使用镜像默认命令'],
        ['网络', Object.keys(network.Networks || {}).join(', ') || '—'], ['目录挂载', mounts.join('\n') || '无挂载目录']
      ];
      $('#docker-details-title').textContent = '容器详情 · ' + name;
      $('#docker-details-content').innerHTML = rows.map(([label, value]) => {
        const extraClass = (label === '端口映射' ? ' docker-detail-port-map' : '') + (label === '创建时间' ? ' docker-detail-created-time' : '');
        return `<div class="docker-detail-item${extraClass}"><div class="docker-detail-label">${dockerEsc(label)}</div><div class="docker-detail-value" title="${dockerEsc(value)}">${dockerEsc(value)}</div></div>`;
      }).join('');
      $('#docker-details-modal').hidden = false;
    } catch (e) { toast(e.message, 'error', 5000); }
    return;
  }
  if (action === 'backup') {
    const ok = await showConfirm('备份容器文件系统', `将导出容器「${name}」的文件系统为 TAR 文件。\n\n注意：docker export 不会包含挂载目录和数据卷中的内容，也不会备份启动参数。要备份持久化数据，请另外备份宿主机挂载目录/数据卷。继续吗？`, 'archive');
    if (!ok) return;
    const a = document.createElement('a');
    a.href = `/api/docker/containers/${encodeURIComponent(id)}/backup?name=${encodeURIComponent(name)}`;
    a.download = `${name}-filesystem.tar`; document.body.appendChild(a); a.click(); a.remove();
    toast('已开始生成并下载容器文件系统备份；大容器可能需要等待一段时间。', 'ok', 5000);
    return;
  }
  if (action === 'remove') {
    const ok = await showConfirm('卸载容器', `确定卸载容器「${name}」吗？\n\n如果容器正在运行，Docker 会先停止再删除。容器可写层会丢失；绑定目录和命名数据卷不会自动删除。`, 'trash-2');
    if (!ok) return;
  }
  if (action === 'rebuild') {
    const ok = await showConfirm('重建容器', `将尝试读取「${name}」的 Docker Compose 标签，并在原工作目录执行强制重建。\n\n若它不是由 Docker Compose 创建的，面板会拒绝重建，不会删除容器。继续吗？`, 'refresh-cw');
    if (!ok) return;
  }
  const labels = { start: '启动', stop: '停止', restart: '重启', pause: '暂停', unpause: '恢复', remove: '卸载', rebuild: '重建' };
  const oldText = btn.textContent; btn.disabled = true;
  try {
    let r;
    if (action === 'rebuild') r = await dockerPost(`/api/docker/containers/${encodeURIComponent(id)}/rebuild`, {});
    else r = await dockerPost(`/api/docker/containers/${encodeURIComponent(id)}/action`, { action });
    toast(r.msg || `${labels[action]}成功`, 'ok', 5000); await loadDockerContainers(true);
  } catch (e) { toast(e.message, 'error', 7000); }
  finally { btn.disabled = false; btn.textContent = oldText; }
});

// Keep the port menu open while the pointer moves from the port chip into the menu.
const dockerPortHoverRoot = $('#docker-container-list');
dockerPortHoverRoot?.addEventListener('pointerover', ev => {
  const dropdown = ev.target.closest('.docker-port-dropdown');
  if (!dropdown || !dockerPortHoverRoot.contains(dropdown)) return;
  dropdown.classList.add('expanded');
  dropdown.setAttribute('aria-expanded', 'true');
});
dockerPortHoverRoot?.addEventListener('pointerout', ev => {
  const dropdown = ev.target.closest('.docker-port-dropdown');
  if (!dropdown || !dockerPortHoverRoot.contains(dropdown)) return;
  if (ev.relatedTarget && dropdown.contains(ev.relatedTarget)) return;
  dropdown.classList.remove('expanded');
  dropdown.setAttribute('aria-expanded', 'false');
});

document.addEventListener('click', ev => {
  if (ev.target.closest('.docker-port-dropdown')) return;
  document.querySelectorAll('.docker-port-dropdown.expanded').forEach(el => {
    el.classList.remove('expanded');
    el.setAttribute('aria-expanded', 'false');
  });
});

document.querySelector('#docker-container-list')?.addEventListener('keydown', ev => {
  const dropdown = ev.target.closest('.docker-port-dropdown');
  if (!dropdown || ev.target.closest('a') || !['Enter', ' '].includes(ev.key)) return;
  if (ev.target.closest('button') && ev.key === 'Enter') return;
  ev.preventDefault();
  const expanded = !dropdown.classList.contains('expanded');
  document.querySelectorAll('.docker-port-dropdown.expanded').forEach(el => { el.classList.remove('expanded'); el.setAttribute('aria-expanded', 'false'); });
  if (expanded) { dropdown.classList.add('expanded'); dropdown.setAttribute('aria-expanded', 'true'); }
});

let dockerEditOriginalPorts = '';
function dockerPortLinesFromInspect(info) {
  const out = [];
  const ports = ((info || {}).HostConfig || {}).PortBindings || {};
  Object.entries(ports).forEach(([target, bindings]) => {
    const bits = String(target).split('/');
    const cport = bits[0], proto = (bits[1] || 'tcp').toLowerCase();
    (bindings || []).forEach(binding => {
      const hport = String((binding || {}).HostPort || '').trim();
      const hostIp = String((binding || {}).HostIp || '').trim();
      if (hport && /^\d+$/.test(hport) && /^\d+$/.test(cport)) {
        const host = hostIp ? (hostIp.includes(':') ? `[${hostIp}]` : hostIp) + ':' : '';
        out.push(`${host}${hport}:${cport}/${proto}`);
      }
    });
  });
  return [...new Set(out)].sort().join('\n');
}
function normalizedDockerPortLines(value) {
  return String(value || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean).map(x => {
    const m = x.match(/^(?:(\[[0-9a-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):)?(\d+):(\d+)(?:\/(tcp|udp))?$/i);
    let ip = m ? (m[1] || '').replace(/^\[|\]$/g, '').toLowerCase() : '';
    if (ip === '0.0.0.0') ip = '0.0.0.0';
    return m ? `${ip ? (ip.includes(':') ? `[${ip}]` : ip) + ':' : ''}${Number(m[2])}:${Number(m[3])}/${(m[4] || 'tcp').toLowerCase()}` : x;
  }).sort().join('\n');
}
async function openDockerContainerEditor(id, name) {
  const r = await api(`/api/docker/containers/${encodeURIComponent(id)}/inspect`);
  if (r.code !== 0) throw new Error(r.msg || '读取容器配置失败');
  const info = Array.isArray(r.data) ? (r.data[0] || {}) : (r.data || {});
  const host = info.HostConfig || {};
  const cfg = info.Config || {};
  $('#docker-edit-id').value = id;
  $('#docker-edit-title').textContent = '编辑容器 · ' + name;
  $('#docker-edit-image').textContent = `镜像：${cfg.Image || '未知'} · 容器：${String(info.Id || id).slice(0, 12)}`;
  $('#docker-edit-cpus').value = host.NanoCpus ? (host.NanoCpus / 1e9).toString() : (host.CpuQuota > 0 && host.CpuPeriod > 0 ? (host.CpuQuota / host.CpuPeriod).toString() : (host.CpuShares ? '0' : '0'));
  $('#docker-edit-memory').value = host.Memory ? String(Math.round(host.Memory / 1048576)) : '0';
  dockerEditOriginalPorts = normalizedDockerPortLines(dockerPortLinesFromInspect(info));
  $('#docker-edit-ports').value = dockerPortLinesFromInspect(info);
  $('#docker-edit-port-warning').hidden = true;
  $('#docker-edit-message').textContent = '';
  $('#docker-edit-modal').hidden = false;
}
$('#docker-edit-ports').addEventListener('input', () => {
  $('#docker-edit-port-warning').hidden = normalizedDockerPortLines($('#docker-edit-ports').value) === dockerEditOriginalPorts;
});
$('#btn-docker-edit-save').addEventListener('click', async () => {
  const id = $('#docker-edit-id').value;
  const cpu = $('#docker-edit-cpus').value;
  const memory = $('#docker-edit-memory').value;
  const ports = $('#docker-edit-ports').value;
  if (!Number.isFinite(Number(cpu)) || Number(cpu) < 0) { toast('CPU 限制无效', 'error'); return; }
  if (!Number.isInteger(Number(memory)) || Number(memory) < 0) { toast('RAM 限制必须是非负整数 MiB', 'error'); return; }
  const changedPorts = normalizedDockerPortLines(ports) !== dockerEditOriginalPorts;
  if (changedPorts) {
    const ok = await showConfirm('确认修改端口', '修改容器端口需要短暂停止并重建容器。面板会尝试保存旧容器可写层快照；挂载目录和数据卷会保留，快照镜像也会留在本地。继续吗？', 'refresh-cw');
    if (!ok) return;
  }
  const btn = $('#btn-docker-edit-save'), old = btn.textContent;
  btn.disabled = true; btn.textContent = changedPorts ? '正在重建…' : '保存中…';
  $('#docker-edit-message').textContent = '正在应用配置，请稍候…';
  try {
    const r = await dockerPost(`/api/docker/containers/${encodeURIComponent(id)}/edit`, {cpus: cpu, memory_mb: memory, ports});
    $('#docker-edit-message').textContent = r.msg || '配置已保存';
    toast(r.msg || '容器配置已更新', 'ok', 9000);
    $('#docker-edit-modal').hidden = true;
    await loadDockerContainers(true);
  } catch (e) {
    $('#docker-edit-message').textContent = e.message;
    toast(e.message, 'error', 9000);
  } finally { btn.disabled = false; btn.textContent = old; }
});
function openDockerHostDirectory(path, label) {
  if (!path) { toast(`${label}不在文件管理允许访问的根目录内，或该目录不存在`, 'error', 5000); return; }
  const nav = $('.nav-item[data-view="files"]');
  if (nav) nav.click();
  loadFiles(path);
}

async function loadDockerLogs() {
  if (!dockerCurrentLogId) return;
  $('#docker-log-content').textContent = '正在加载…';
  try {
    const r = await api(`/api/docker/containers/${encodeURIComponent(dockerCurrentLogId)}/logs?tail=200`);
    if (r.code !== 0) throw new Error(r.msg || '读取日志失败');
    $('#docker-log-content').textContent = r.data.logs || '暂无日志输出';
    const pre = $('#docker-log-content'); pre.scrollTop = pre.scrollHeight;
  } catch (e) { $('#docker-log-content').textContent = '读取失败：' + e.message; }
}
$('#btn-docker-logs-refresh').addEventListener('click', loadDockerLogs);

$('#docker-image-list').addEventListener('click', async ev => {
  const deployBtn = ev.target.closest('[data-docker-image-deploy]');
  if (deployBtn) {
    const image = deployBtn.dataset.dockerImageDeploy;
    if (!image) return;
    $('#docker-run-image').value = image;
    const tail = image.split('/').pop().split(':')[0];
    const suggested = tail.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 100) || 'container';
    $('#docker-run-name').value = suggested;
    $('#docker-run-ports').value = ''; $('#docker-run-volumes').value = ''; $('#docker-run-env').value = '';
    $('#docker-run-restart').value = 'unless-stopped';
    $('#docker-create-modal').hidden = false;
    setTimeout(() => $('#docker-run-name').focus(), 50);
    return;
  }
  const btn = ev.target.closest('[data-docker-image-del]'); if (!btn) return;
  const id = btn.dataset.dockerImageDel, name = btn.dataset.imageName || id;
  const ok = await showConfirm('删除镜像', `确定删除镜像「${name}」吗？\n\n如果仍有容器引用该镜像，Docker 可能拒绝删除。`, 'trash-2');
  if (!ok) return;
  try { const r = await dockerPost(`/api/docker/images/${encodeURIComponent(id)}/delete`); toast(r.msg || '镜像已删除', 'ok'); await loadDockerImages(true); }
  catch (e) { toast(e.message, 'error', 5000); }
});

$('#docker-container-list').addEventListener('click', async ev => {
  const taskBtn = ev.target.closest('[data-docker-task-view]');
  if (taskBtn) { showDockerTaskLogs(taskBtn.dataset.dockerTaskView); return; }
  const dismissBtn = ev.target.closest('[data-docker-pending-dismiss]');
  if (dismissBtn) {
    try {
      await dockerPost(`/api/docker/tasks/${encodeURIComponent(dismissBtn.dataset.dockerPendingDismiss)}/dismiss`, {});
      dockerContainersCache = dockerContainersCache.filter(x => x.PendingTaskId !== dismissBtn.dataset.dockerPendingDismiss);
      renderDockerContainers();
      toast('失败任务卡片已清除', 'ok');
    } catch (e) { toast(e.message, 'error', 5000); }
  }
});
$('#docker-network-list').addEventListener('click', async ev => {
  const btn = ev.target.closest('[data-docker-network-del]'); if (!btn) return;
  const name = btn.dataset.dockerNetworkDel;
  const ok = await showConfirm('删除 Docker 网络', `确定删除网络「${name}」吗？\n\n正在使用该网络的容器可能导致删除失败。`, 'trash-2');
  if (!ok) return;
  try { const r = await dockerPost(`/api/docker/networks/${encodeURIComponent(name)}/delete`); toast(r.msg || '网络已删除', 'ok'); await loadDockerNetworks(true); }
  catch (e) { toast(e.message, 'error', 5000); }
});
$('#docker-volume-list').addEventListener('click', async ev => {
  const btn = ev.target.closest('[data-docker-volume-del]'); if (!btn) return;
  const name = btn.dataset.dockerVolumeDel;
  const ok = await showConfirm('删除 Docker 数据卷', `警告：确定永久删除数据卷「${name}」吗？\n\n数据卷中的持久化数据将丢失，且无法从面板撤销。`, 'alert-triangle');
  if (!ok) return;
  try { const r = await dockerPost(`/api/docker/volumes/${encodeURIComponent(name)}/delete`); toast(r.msg || '数据卷已删除', 'ok'); await loadDockerVolumes(true); }
  catch (e) { toast(e.message, 'error', 5000); }
});

/* ============================================================
   初始化
   ============================================================ */
loadFiles('');
loadKeys(true);
loadSshService();
loadCronTasks();
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

def check_cron_d():
    """检查 /etc/cron.d 是否存在，不存在则提示（某些精简系统可能没有 cron）"""
    if not os.path.isdir(CRON_DIR):
        print(f"⚠️  未检测到 {CRON_DIR} 目录，计划任务可能无法工作")
        print("   安装 cron：sudo apt install -y cron && sudo systemctl enable --now cron\n")

if __name__ == "__main__":
    require_root()
    print("\n面板启动中…")
    check_ufw()
    check_cron_d()
    # 启动时重建所有已启用任务的 cron 文件
    try:
        sync_all_cron_files()
    except Exception as e:
        print(f"⚠️  同步计划任务失败：{e}")
    print(f"📡 http://{HOST}:{PORT}")
    print(f"📂 文件根目录: {FILE_ROOT}")
    print(f"📄 日志: {LOG_FILE}")
    print(f"⏰ 计划任务: {TASK_DIR}")
    socketio.run(app, host=HOST, port=PORT, debug=False,
                 allow_unsafe_werkzeug=True)