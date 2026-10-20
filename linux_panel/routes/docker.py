from flask import Blueprint
from ..core import *


bp = Blueprint("docker", __name__)

# ============================================================================
# Docker 管理
# ============================================================================
DOCKER_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
DOCKER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DOCKER_ID_RE = re.compile(r"^(?:[a-fA-F0-9]{12,64}|sha256:[a-fA-F0-9]{64})$")


def docker_command(args, timeout=20):
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


@bp.route("/api/docker/status")
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
                        status_msg = line.split(":")[-1].strip() if ":" in line else line
                        latest_detail = status_msg[:240] or label
                        _docker_install_state_update(task_id, message=f"{label}：{latest_detail}",
                                                     log_line=f"[{label}] {latest_detail}")
                    else:
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


@bp.route("/api/docker/install", methods=["POST"])
@login_required
def api_docker_install():
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


@bp.route("/api/docker/install/status")
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


@bp.route("/api/docker/settings")
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


@bp.route("/api/docker/service", methods=["POST"])
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


@bp.route("/api/docker/mirror", methods=["POST"])
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


@bp.route("/api/docker/mirror/test", methods=["POST"])
@login_required
def api_docker_mirror_test():
    from urllib.parse import urlparse
    d = request.get_json(silent=True) or {}
    try:
        raw_url = _docker_validate_mirror_url(d.get("url"), "镜像源")
        parsed = urlparse(raw_url)
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


@bp.route("/api/docker/config", methods=["GET", "POST"])
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


@bp.route("/api/docker/uninstall", methods=["POST"])
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


@bp.route("/api/docker/containers/<container_id>/inspect")
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


@bp.route("/api/docker/containers/<container_id>/edit", methods=["POST"])
@login_required
def api_docker_container_edit(container_id):
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
            docker_require_ok(["rm", "-f", backup_name], timeout=60)
            renamed_old = False
            log.warning("Docker 容器 %s 因端口修改而重建；可写层快照保留为 %s", old_name, snapshot_tag)
            return jsonify(code=0, msg=f"容器已重建并应用端口配置。为保护原容器可写层，已保留快照镜像 {snapshot_tag}；挂载目录/数据卷保持不变。", data={"recreated": True, "snapshot_image": snapshot_tag})
        except Exception:
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


@bp.route("/api/docker/containers/<container_id>/backup")
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


@bp.route("/api/docker/containers/<container_id>/rebuild", methods=["POST"])
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


@bp.route("/api/docker/containers")
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


@bp.route("/api/docker/containers/<container_id>/action", methods=["POST"])
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


@bp.route("/api/docker/containers/<container_id>/logs")
@login_required
def api_docker_container_logs(container_id):
    try:
        cid = docker_validate_container_id(container_id)
        tail = _safe_int(request.args.get("tail"), 200, 1, 1000)
        code, out, err = docker_command(["logs", "--timestamps", "--tail", str(tail), cid], timeout=20)
        text = out + (("\n" if out and err else "") + err)
        if code != 0:
            return jsonify(code=500, msg=(text or "读取容器日志失败")[-5000:])
        return jsonify(code=0, data={"logs": text[-200000:], "tail": tail})
    except ValueError as e:
        return jsonify(code=400, msg=str(e))
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@bp.route("/api/docker/containers/run", methods=["POST"])
@login_required
def api_docker_container_run():
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


@bp.route("/api/docker/images")
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
        return {k: (list(v) if k == "logs" else v) for k, v in state.items()
                if k not in ("container_args", "_process")}


@bp.route("/api/docker/tasks")
@login_required
def api_docker_tasks():
    with _docker_pull_state_lock:
        rows = sorted(_docker_pull_tasks.values(), key=lambda item: item.get("updated_at", 0), reverse=True)
        safe_rows = [{k: (list(v) if k == "logs" else v) for k, v in row.items()
                      if k not in ("container_args", "_process")} for row in rows[:24] if not row.get("dismissed")]
    return jsonify(code=0, data=safe_rows)


@bp.route("/api/docker/tasks/<task_id>/dismiss", methods=["POST"])
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


@bp.route("/api/docker/tasks/<task_id>/cancel", methods=["POST"])
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


@bp.route("/api/docker/images/pull", methods=["POST"])
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


@bp.route("/api/docker/images/pull/status")
@login_required
def api_docker_image_pull_status():
    task_id = str(request.args.get("task_id", "")).strip()
    if not re.fullmatch(r"[a-f0-9]{32}", task_id):
        return jsonify(code=400, msg="拉取任务 ID 不正确")
    state = _docker_pull_snapshot(task_id)
    if not state:
        return jsonify(code=404, msg="拉取任务不存在或已过期，请重新操作")
    return jsonify(code=0, data=state)


@bp.route("/api/docker/images/<path:image_id>/delete", methods=["POST"])
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


@bp.route("/api/docker/networks")
@login_required
def api_docker_networks():
    try:
        rows = docker_json_lines(["network", "ls", "--no-trunc", "--format", "{{json .}}"])
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@bp.route("/api/docker/networks/<name>/delete", methods=["POST"])
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


@bp.route("/api/docker/volumes")
@login_required
def api_docker_volumes():
    try:
        rows = docker_json_lines(["volume", "ls", "--format", "{{json .}}"])
        return jsonify(code=0, data=rows)
    except Exception as e:
        return jsonify(code=500, msg=str(e))


@bp.route("/api/docker/volumes/<name>/delete", methods=["POST"])
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
