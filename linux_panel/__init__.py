"""Linux-Panel Flask application factory."""
import os

from flask import Flask

from .core import MAX_UPLOAD_SIZE, fernet, init_db, socketio


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = fernet._signing_key
    is_https_server = (os.environ.get("PANEL_SSL_SERVER") == "1" or os.environ.get("PANEL_FORCE_HTTPS") == "1")
    # This installed service is HTTPS-only; the Secure cookie flag is enabled
    # whenever the installer sets either TLS/forced-HTTPS environment variable.
    session_cookie_name = "panel_https_session" if is_https_server else "panel_http_session"
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE,
        SESSION_COOKIE_NAME=session_cookie_name,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=is_https_server,
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

    # The installer sets PANEL_FORCE_HTTPS=1 and runs only the TLS listener.
    # There is intentionally no HTTP-to-HTTPS redirect middleware: plaintext
    # HTTP is not served on the panel port at all.

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
