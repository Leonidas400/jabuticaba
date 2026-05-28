"""
app.py — CIS Analyzer v4 — API-only (FortiGate, pfSense, SonicWall)
"""
import os
from datetime import timedelta

from flask import Flask, render_template

from database import init_db

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "cis-v4-api-only-2025")
app.permanent_session_lifetime = timedelta(hours=8)
init_db()

# ── BLUEPRINTS ───────────────────────────────────────────────
from routes.public import bp as public_bp
from routes.admin  import bp as admin_bp

app.register_blueprint(public_bp)
app.register_blueprint(admin_bp)

# ── PAGES ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
