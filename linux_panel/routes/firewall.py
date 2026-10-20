from flask import Blueprint
from ..core import *


bp = Blueprint("firewall", __name__)

@bp.route("/api/firewall", methods=["GET"])
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

@bp.route("/api/firewall/switch", methods=["POST"])
@login_required
def api_fw_switch():
    if not ufw_available(): return jsonify(code=500, msg="未安装 ufw")
    d = request.get_json() or {}
    ok, msg = ufw_switch(bool(d.get("enable")))
    if ok: return jsonify(code=0, msg="已开启" if d.get("enable") else "已关闭")
    return jsonify(code=500, msg=msg)

@bp.route("/api/firewall/add", methods=["POST"])
@login_required
def api_fw_add():
    if not ufw_available(): return jsonify(code=500, msg="未安装 ufw")
    d = request.get_json() or {}
    try: ok, msg = ufw_add(d.get("port", ""), d.get("proto", "tcp"), d.get("source", ""))
    except PathError as e: return jsonify(code=400, msg=str(e))
    if not ok: return jsonify(code=500, msg=msg)
    return jsonify(code=0, msg=msg or "放行成功")

@bp.route("/api/firewall/delete", methods=["POST"])
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
