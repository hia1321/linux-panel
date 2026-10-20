from flask import Blueprint, make_response, redirect
from ..core import *
from flask import render_template


bp = Blueprint("pages", __name__)


@bp.route("/")
@login_required
def home():
    # The SPA determines its initial section from the URL path. Always route the
    # bare root to the canonical file-manager path so a fresh login never opens
    # an empty/unknown section at "/".
    return redirect("/files", code=302)

@bp.route("/files")
@bp.route("/ssh")
@bp.route("/terminal")
@bp.route("/cron")
@bp.route("/firewall")
@bp.route("/docker")
@bp.route("/dns")
@bp.route("/ssl")
@login_required
def index():
    # The panel is updated through GitHub/install.sh. Avoid stale HTML/JS from
    # the browser cache after deploying a new version of the UI.
    response = make_response(render_template("index.html"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
