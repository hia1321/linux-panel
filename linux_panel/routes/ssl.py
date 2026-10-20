from flask import Blueprint, jsonify, request, session, send_file
from io import BytesIO

from ..common import login_required
from ..config import log
from ..ssl_service import (
    DEFAULT_HTTPS_PORT,
    activate_stored_certificate,
    certificate_download_details,
    certificate_download_bundle,
    delete_stored_certificate,
    commit_and_activate,
    disable_https,
    inspect_certificate_files,
    issue_letsencrypt,
    load_ssl_config,
    save_ssl_config,
    save_uploaded_certificate,
    set_http_redirect,
    service_state,
    ssl_status,
    validate_https_port,
    _read_upload,
)

bp = Blueprint("ssl", __name__)

def _read_pem_text(value, label):
    text = (value or "").strip()
    if not text:
        raise ValueError(f"请粘贴{label} PEM 内容")
    data = text.encode("utf-8")
    if len(data) > 2 * 1024 * 1024:
        raise ValueError(f"{label}内容不能超过 2 MiB")
    return data



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
        # Accept both older file-upload clients and the current multiline PEM form.
        cert_text = request.form.get("certificate_pem") or request.form.get("certificate") or ""
        key_text = request.form.get("private_key_pem") or request.form.get("private_key") or ""
        cert_bytes = _read_upload(cert_file, "证书") if cert_file and cert_file.filename else _read_pem_text(cert_text, "证书")
        key_bytes = _read_upload(key_file, "私钥") if key_file and key_file.filename else _read_pem_text(key_text, "私钥")
        port = validate_https_port(load_ssl_config().get("port", DEFAULT_HTTPS_PORT))
        server_name = request.form.get("server_name", "")
        info, message = save_uploaded_certificate(cert_bytes, key_bytes, port, server_name)
        session.modified = True
        return jsonify(code=0, msg=message, data={"certificate": info, "status": ssl_status()})
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("上传 SSL 证书失败")
        return jsonify(code=500, msg=f"上传证书失败：{exc}")


@bp.route("/api/ssl/certificates/activate", methods=["POST"])
@login_required
def api_ssl_activate_certificate():
    d = request.get_json(silent=True) or {}
    try:
        message = activate_stored_certificate(d.get("id", ""))
        session.modified = True
        return jsonify(code=0, msg=message, data=ssl_status())
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("启用已保存证书失败")
        return jsonify(code=500, msg=f"启用证书失败：{exc}")


@bp.route("/api/ssl/certificates/<certificate_id>/download", methods=["GET"])
@login_required
def api_ssl_download_certificate(certificate_id):
    try:
        cert_path, download_name = certificate_download_details(certificate_id)
        response = send_file(
            cert_path, mimetype="application/x-pem-file", as_attachment=True,
            download_name=download_name, conditional=True, max_age=0,
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    except ValueError as exc:
        return jsonify(code=400, msg=str(exc)), 400
    except OSError as exc:
        log.exception("下载 SSL 证书失败")
        return jsonify(code=500, msg=f"下载证书失败：{exc}"), 500
    except Exception as exc:
        log.exception("下载 SSL 证书失败")
        return jsonify(code=500, msg=f"下载证书失败：{exc}"), 500


@bp.route("/api/ssl/certificates/<certificate_id>/download-bundle", methods=["GET"])
@login_required
def api_ssl_download_certificate_bundle(certificate_id):
    """Download fullchain.pem and privkey.key as ZIP; private key export is sensitive."""
    try:
        archive_bytes, download_name = certificate_download_bundle(certificate_id)
        response = send_file(
            BytesIO(archive_bytes), mimetype="application/zip", as_attachment=True,
            download_name=download_name, conditional=False, max_age=0,
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        log.warning("SSL private-key bundle downloaded by user=%s certificate_id=%s",
                    session.get("user", "unknown"), certificate_id)
        return response
    except ValueError as exc:
        return jsonify(code=400, msg=str(exc)), 400
    except OSError as exc:
        log.exception("打包下载 SSL 证书失败")
        return jsonify(code=500, msg=f"打包下载证书失败：{exc}"), 500
    except Exception as exc:
        log.exception("打包下载 SSL 证书失败")
        return jsonify(code=500, msg=f"打包下载证书失败：{exc}"), 500


@bp.route("/api/ssl/certificates/delete", methods=["POST"])
@login_required
def api_ssl_delete_certificate():
    d = request.get_json(silent=True) or {}
    try:
        message = delete_stored_certificate(d.get("id", ""))
        return jsonify(code=0, msg=message, data=ssl_status())
    except ValueError as exc:
        return jsonify(code=400, msg=str(exc))
    except (OSError, RuntimeError) as exc:
        log.exception("删除 SSL 证书失败")
        return jsonify(code=500, msg=f"删除证书失败：{exc}")
    except Exception as exc:
        log.exception("删除 SSL 证书失败")
        return jsonify(code=500, msg=f"删除证书失败：{exc}")


@bp.route("/api/ssl/port", methods=["POST"])
@login_required
def api_ssl_save_port():
    d = request.get_json(silent=True) or {}
    try:
        port = validate_https_port(d.get("port", DEFAULT_HTTPS_PORT))
        cfg = load_ssl_config()
        old_port = int(cfg.get("port") or DEFAULT_HTTPS_PORT)
        if port == old_port:
            return jsonify(code=0, msg=f"HTTPS 端口未变化，仍为 {port}", data=ssl_status())

        cfg["port"] = port
        if cfg.get("pending_cert_path"):
            cfg["pending_port"] = port
        has_pair = bool(cfg.get("cert_path") and cfg.get("key_path"))
        if cfg.get("enabled") and has_pair:
            # Do not save a new active port unless the current cert/key pair is valid.
            inspect_certificate_files(cfg["cert_path"], cfg["key_path"])
            message = commit_and_activate(cfg)
        else:
            # Allow configuring a future port before a certificate is installed,
            # without unexpectedly starting HTTPS or changing the enabled state.
            save_ssl_config(cfg)
            message = f"HTTPS 端口已保存为 {port}；启用证书时将使用该端口"
        session.modified = True
        return jsonify(code=0, msg=message, data=ssl_status(), previous_port=old_port)
    except (ValueError, RuntimeError, OSError) as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("保存 HTTPS 端口失败")
        return jsonify(code=500, msg=f"保存 HTTPS 端口失败：{exc}")


@bp.route("/api/ssl/letsencrypt", methods=["POST"])
@login_required
def api_ssl_letsencrypt():
    d = request.get_json(silent=True) or {}
    try:
        info, message, details = issue_letsencrypt(
            d.get("domains", ""), d.get("email", ""),
            load_ssl_config().get("port", DEFAULT_HTTPS_PORT),
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
        # If a new manual certificate was staged, activate it only after this
        # explicit user action. The old active cert remains untouched until now.
        if cfg.get("pending_cert_path") and cfg.get("pending_key_path"):
            inspect_certificate_files(cfg["pending_cert_path"], cfg["pending_key_path"])
            cfg.update({
                "source": cfg.get("pending_source") or "upload",
                "domains": cfg.get("pending_domains") or [],
                "server_name": cfg.get("pending_server_name") or "",
                "cert_path": cfg["pending_cert_path"],
                "key_path": cfg["pending_key_path"],
                "cert_name": cfg.get("pending_cert_name") or "",
                "port": cfg.get("pending_port") or cfg.get("port") or DEFAULT_HTTPS_PORT,
                "pending_cert_path": "",
                "pending_key_path": "",
                "pending_cert_name": "",
                "pending_source": "",
                "pending_domains": [],
                "pending_server_name": "",
            })
            cfg["pending_port"] = cfg["port"]
        elif not cfg.get("cert_path") or not cfg.get("key_path"):
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
    except ValueError as exc:
        return jsonify(code=400, msg=str(exc))
    except Exception as exc:
        log.exception("停用 HTTPS 失败")
        return jsonify(code=500, msg=f"停用 HTTPS 失败：{exc}")


@bp.route("/api/ssl/redirect", methods=["POST"])
@login_required
def api_ssl_redirect():
    d = request.get_json(silent=True) or {}
    enabled = bool(d.get("enabled", True))
    message = set_http_redirect(enabled)
    return jsonify(code=0, msg=message, data=ssl_status())
