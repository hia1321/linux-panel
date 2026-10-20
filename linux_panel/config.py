import logging
import os
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

__all__ = [name for name in globals() if not name.startswith("__")]
