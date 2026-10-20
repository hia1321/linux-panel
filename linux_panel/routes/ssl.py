from flask import Blueprint, jsonify, request, session

from ..common import login_required
from ..config import log
from ..ssl_service import (
    DEFAULT_HTTPS_PORT,
    commit_and_activate,
    disable_https,
    inspect_certificate_files,
    issue_letsencrypt,
    load_ssl_config,
    save_uploaded_certificate,
    set_http_redirect,
    service_state,
    ssl_status,
    validate_https_port,
    _read_upload,
)

bp = Blueprint("ssl", __name__)


@bp.route("/api/ssl/status", methods=["GET"])
@login_required
def api_ssl_status():
    try:
        return jsonify(code=0, data=ssl_status())
    except Exception as exc:
        log.exception("读取 SSL 状态失败")
        return jsonify(code=500, msg=f"读取 SSL 状态失败：{exc}")


@bp.route("/api/ssl/upload", methods=["POST"])
@login_required
def api_ssl_upload():
    if request.content_length and request.content_length > 5 * 1024 * 1024:
        return jsonify(code=413, msg="上传内容过大，证书和私钥合计不能超过 5 MiB")
    cert_file = request.files.get("certificate")
    key_file = request.files.get("private_key")
    try:
        cert_bytes = _read_upload(cert_file, "证书")
        key_bytes = _read_upload(key_file, "私钥")
        port = validate_https_port(request.form.get("https_port", DEFAULT_HTTPS_PORT))
        server_name = request.form.get("server_name", "")
        info, message = save_uploaded_certificate(cert_bytes, key_bytes, port, server_name)
        session.modified = True
        return jsonify(code=0, msg=message, data={"certificate": info, "status": ssl_status()})
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("上传 SSL 证书失败")
        return jsonify(code=500, msg=f"上传证书失败：{exc}")


@bp.route("/api/ssl/letsencrypt", methods=["POST"])
@login_required
def api_ssl_letsencrypt():
    d = request.get_json(silent=True) or {}
    try:
        info, message, details = issue_letsencrypt(
            d.get("domains", ""), d.get("email", ""),
            d.get("https_port", DEFAULT_HTTPS_PORT),
        )
        session.modified = True
        return jsonify(code=0, msg=message, data={"certificate": info, "details": details, "status": ssl_status()})
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("Let’s Encrypt 申请失败")
        return jsonify(code=500, msg=f"Let’s Encrypt 申请失败：{exc}")


@bp.route("/api/ssl/enable", methods=["POST"])
@login_required
def api_ssl_enable():
    cfg = load_ssl_config()
    try:
        if not cfg.get("cert_path") or not cfg.get("key_path"):
            return jsonify(code=400, msg="没有可用证书，请先上传证书或申请 Let’s Encrypt 证书")
        inspect_certificate_files(cfg["cert_path"], cfg["key_path"])
        message = commit_and_activate(cfg)
        session.modified = True
        return jsonify(code=0, msg=message, data=ssl_status())
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("重新启用 HTTPS 失败")
        return jsonify(code=500, msg=f"重新启用 HTTPS 失败：{exc}")


@bp.route("/api/ssl/disable", methods=["POST"])
@login_required
def api_ssl_disable():
    try:
        message = disable_https()
        session.modified = True
        return jsonify(code=0, msg=message, data=ssl_status())
    except Exception as exc:
        log.exception("停用 HTTPS 失败")
        return jsonify(code=500, msg=f"停用 HTTPS 失败：{exc}")


@bp.route("/api/ssl/redirect", methods=["POST"])
@login_required
def api_ssl_redirect():
    d = request.get_json(silent=True) or {}
    cfg = load_ssl_config()
    if d.get("enabled") and not cfg.get("enabled"):
        return jsonify(code=400, msg="请先申请或上传证书并启用 HTTPS")
    if d.get("enabled") and service_state() != "active":
        return jsonify(code=400, msg="HTTPS 服务当前未运行，请先检查 HTTPS 服务状态和日志")
    try:
        message = set_http_redirect(bool(d.get("enabled")))
        session.modified = True
        return jsonify(code=0, msg=message)
    except Exception as exc:
        log.exception("修改 HTTP 跳转设置失败")
        return jsonify(code=500, msg=f"修改设置失败：{exc}")
