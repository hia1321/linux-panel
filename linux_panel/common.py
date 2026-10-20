import errno
import os
import re
from functools import wraps
from flask import jsonify, redirect, request, session, url_for
from .config import FILE_ROOT

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify(code=401, msg="未登录")
            return redirect(url_for("auth.login_page"))
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

__all__ = [name for name in globals() if not name.startswith("__")]
