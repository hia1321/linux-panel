"""Linux-Panel Flask application factory."""
import os

from flask import Flask, redirect, request, session

from .core import MAX_UPLOAD_SIZE, fernet, init_db, socketio
from .ssl_service import load_ssl_config, redirect_target_for_request


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = fernet._signing_key
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(load_ssl_config().get("enabled") and load_ssl_config().get("redirect_http", True)),
        JSON_AS_ASCII=False,
    )

    socketio.init_app(
        app,
        async_mode="threading",
        cors_allowed_origins="*",
        max_http_buffer_size=64 * 1024 * 1024,
        ping_timeout=60,
        ping_interval=25,
    )

    @app.before_request
    def redirect_http_to_https_when_enabled():
        # Keep the original HTTP listener available for recovery, but send ordinary
        # HTTP requests to TLS after SSL has been explicitly enabled. The dedicated
        # HTTPS process sets PANEL_SSL_SERVER=1 and must never redirect itself.
        ssl_cfg = load_ssl_config()
        app.config["SESSION_COOKIE_SECURE"] = bool(ssl_cfg.get("enabled") and ssl_cfg.get("redirect_http", True))
        if request.is_secure and session.get("user") and ssl_cfg.get("enabled") and ssl_cfg.get("redirect_http", True) and not session.get("_ssl_cookie"):
            session["_ssl_cookie"] = True
        if os.environ.get("PANEL_SSL_SERVER") == "1":
            return None
        target = redirect_target_for_request(request)
        if target:
            return redirect(target, code=307)
        return None

    @app.after_request
    def refresh_secure_cookie_policy(response):
        # A certificate can be enabled by the current request; update the cookie
        # policy before Flask serializes the session cookie in that response.
        ssl_cfg = load_ssl_config()
        app.config["SESSION_COOKIE_SECURE"] = bool(ssl_cfg.get("enabled") and ssl_cfg.get("redirect_http", True))
        return response

    # Import modules here so their blueprints and Socket.IO handlers are registered
    # once the shared app/extensions are configured.
    from .routes.auth import bp as auth_bp
    from .routes.pages import bp as pages_bp
    from .routes.files import bp as files_bp
    from .routes.cron import bp as cron_bp
    from .routes.ssh import bp as ssh_bp
    from .routes.firewall import bp as firewall_bp
    from .routes.docker import bp as docker_bp
    from .routes.dns import bp as dns_bp
    from .routes.ssl import bp as ssl_bp
    from .routes import terminal as _terminal  # noqa: F401

    for blueprint in (
        auth_bp, pages_bp, files_bp, cron_bp, ssh_bp,
        firewall_bp, docker_bp, dns_bp, ssl_bp,
    ):
        app.register_blueprint(blueprint)

    init_db()
    return app
