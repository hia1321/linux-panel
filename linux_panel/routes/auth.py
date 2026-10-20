from flask import Blueprint
from ..core import *
from flask import render_template


bp = Blueprint("auth", __name__)

@bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("user"): return redirect("/files")
        return render_template("login.html")
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

@bp.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear(); return jsonify(code=0)

@bp.route("/api/account", methods=["GET", "POST"])
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
