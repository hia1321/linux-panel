from ..core import *

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
