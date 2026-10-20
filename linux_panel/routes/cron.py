from flask import Blueprint
from ..core import *


bp = Blueprint("cron", __name__)

@bp.route("/api/cron/tasks", methods=["GET", "POST"])
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


@bp.route("/api/cron/tasks/<int:tid>", methods=["PUT", "DELETE"])
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


@bp.route("/api/cron/tasks/<int:tid>/toggle", methods=["POST"])
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


@bp.route("/api/cron/tasks/<int:tid>/run", methods=["POST"])
@login_required
def api_cron_task_run(tid):
    task = db_one("SELECT * FROM cron_tasks WHERE id=?", (tid,))
    if not task: return jsonify(code=404, msg="任务不存在")
    runner = _task_runner_path(tid)
    try:
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


@bp.route("/api/cron/tasks/<int:tid>/log", methods=["GET", "DELETE"])
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
