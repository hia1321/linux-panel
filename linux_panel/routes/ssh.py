from flask import Blueprint
from ..core import *


bp = Blueprint("ssh", __name__)

@bp.route("/api/ssh/service", methods=["GET"])
@login_required
def api_ssh_service():
    return jsonify(code=0, data={
        "config": read_sshd_config(),
        "status": ssh_service_status(),
        "stats": ssh_login_stats(),
        "authorized_keys": read_authorized_keys(),
    })

@bp.route("/api/ssh/service", methods=["POST"])
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

@bp.route("/api/ssh/authorized_keys/add", methods=["POST"])
@login_required
def api_authorized_add():
    d = request.get_json() or {}
    pub = (d.get("public_key") or "").strip()
    try:
        added = add_authorized_key(pub)
        return jsonify(code=0, msg="已添加" if added else "该密钥已存在")
    except Exception as e:
        return jsonify(code=500, msg=str(e))

@bp.route("/api/ssh/authorized_keys/remove", methods=["POST"])
@login_required
def api_authorized_remove():
    d = request.get_json() or {}
    idx = int(d.get("index", -1))
    ok = remove_authorized_key(idx)
    return jsonify(code=0 if ok else 500, msg="已删除" if ok else "删除失败")

@bp.route("/api/ssh/keys", methods=["GET"])
@login_required
def api_keys_list():
    rows = db_all("""SELECT id, name, key_type, bits, public_key,
                            fingerprint, comment, created_at
                     FROM ssh_keys ORDER BY id DESC""")
    return jsonify(code=0, data=rows)

@bp.route("/api/ssh/keys/generate", methods=["POST"])
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

@bp.route("/api/ssh/keys/import", methods=["POST"])
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

@bp.route("/api/ssh/keys/<int:kid>", methods=["DELETE"])
@login_required
def api_keys_del(kid):
    if not db_one("SELECT id FROM ssh_keys WHERE id=?", (kid,)):
        return jsonify(code=404, msg="密钥不存在")
    db_exec("DELETE FROM ssh_keys WHERE id=?", (kid,))
    return jsonify(code=0)

@bp.route("/api/ssh/keys/<int:kid>/private")
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

@bp.route("/api/ssh/keys/<int:kid>/authorize", methods=["POST"])
@login_required
def api_keys_authorize(kid):
    row = db_one("SELECT * FROM ssh_keys WHERE id=?", (kid,))
    if not row: return jsonify(code=404, msg="密钥不存在")
    try:
        added = add_authorized_key(row["public_key"])
        return jsonify(code=0, msg="已添加到本机" if added else "该密钥已在 authorized_keys")
    except Exception as e:
        return jsonify(code=500, msg=str(e))
