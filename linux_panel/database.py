import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime
from .config import DB_PATH, LOG_FILE, PORT

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
            CREATE TABLE IF NOT EXISTS dns_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL
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
            print(f"  访问 : https://<服务器IP>:{PORT}")
            print(f"  用户 : hia1321")
            print(f"  密  码 : {pw}")
            print(f"  日志 : {LOG_FILE}")
            print(f"  ⚠️  请登录后立即修改密码\n{bar}\n")
    finally: c.close()

__all__ = [name for name in globals() if not name.startswith("__")]
