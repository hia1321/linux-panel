import json
import os
import re
import shlex
from .config import CRON_DIR, CRON_PREFIX, LOG_DIR, TASK_DIR, log
from .database import db_all, db_one

WEEKDAYS_CN = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]

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
    tid = int(task["id"])
    task_type = task["task_type"] or "shell"
    use_lock = int(task["use_lock"] or 0)
    run_user = (task["run_user"] or "root").strip()
    name = task["name"] or f"task-{tid}"

    script_path = _task_script_path(tid, task_type)
    runner_path = _task_runner_path(tid)
    log_path = _task_log_path(tid)

    with open(script_path, "w", encoding="utf-8") as f:
        f.write(task["script"] or "")
    os.chmod(script_path, 0o700)

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

__all__ = [name for name in globals() if not name.startswith("__")]
