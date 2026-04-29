from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets
import os

app = Flask(__name__)

# ================== DATABASE ==================
# Render Environment cần có:
# SUPABASE_DB=postgresql+psycopg2://postgres.xxx:YOUR_PASSWORD@aws-xxx.pooler.supabase.com:6543/postgres
# hoặc DATABASE_URL=...
DATABASE_URL = os.environ.get("SUPABASE_DB") or os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("Missing SUPABASE_DB or DATABASE_URL environment variable")

# Fix URL nếu platform trả về postgres://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_size": 5,
    "max_overflow": 10,
}

db = SQLAlchemy(app)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


class LicenseKey(db.Model):
    __tablename__ = "licenses"

    id = db.Column(db.Integer, primary_key=True)

    # Supabase table của bạn dùng cột license_key, nhưng trong code vẫn gọi là k.key
    key = db.Column("license_key", db.String(64), unique=True, nullable=False)

    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    note = db.Column(db.String(255), default="")
    device_id = db.Column(db.String(128), nullable=True)
    max_devices = db.Column(db.Integer, default=1)


def require_admin():
    return (
        request.args.get("password") == ADMIN_PASSWORD
        or request.form.get("password") == ADMIN_PASSWORD
    )


@app.route("/")
def index():
    if not require_admin():
        return render_template_string(LOGIN_HTML)

    keys = LicenseKey.query.order_by(LicenseKey.id.desc()).all()
    return render_template_string(ADMIN_HTML, keys=keys, password=ADMIN_PASSWORD)


@app.route("/create", methods=["POST"])
def create_key():
    if not require_admin():
        return "Unauthorized", 401

    try:
        days = int(request.form.get("days", 30))
    except Exception:
        days = 30

    try:
        max_devices = int(request.form.get("max_devices", 1))
    except Exception:
        max_devices = 1

    note = request.form.get("note", "")
    key = "SRT-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:20].upper()
    expires_at = datetime.utcnow() + timedelta(days=days)

    item = LicenseKey(
        key=key,
        active=True,
        expires_at=expires_at,
        note=note,
        max_devices=max_devices,
    )

    db.session.add(item)
    db.session.commit()

    return redirect(url_for("index", password=ADMIN_PASSWORD))


@app.route("/toggle/<int:key_id>")
def toggle_key(key_id):
    if not require_admin():
        return "Unauthorized", 401

    item = LicenseKey.query.get_or_404(key_id)
    item.active = not item.active
    db.session.commit()

    return redirect(url_for("index", password=ADMIN_PASSWORD))


@app.route("/reset_device/<int:key_id>")
def reset_device(key_id):
    if not require_admin():
        return "Unauthorized", 401

    item = LicenseKey.query.get_or_404(key_id)
    item.device_id = None
    db.session.commit()

    return redirect(url_for("index", password=ADMIN_PASSWORD))


@app.route("/delete/<int:key_id>")
def delete_key(key_id):
    if not require_admin():
        return "Unauthorized", 401

    item = LicenseKey.query.get_or_404(key_id)
    db.session.delete(item)
    db.session.commit()

    return redirect(url_for("index", password=ADMIN_PASSWORD))


@app.route("/extend/<int:key_id>", methods=["POST"])
def extend_key(key_id):
    if not require_admin():
        return "Unauthorized", 401

    try:
        days = int(request.form.get("days", 30))
    except Exception:
        days = 30

    item = LicenseKey.query.get_or_404(key_id)
    item.expires_at = item.expires_at + timedelta(days=days)
    db.session.commit()

    return redirect(url_for("index", password=ADMIN_PASSWORD))


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(force=True) or {}

    key = str(data.get("key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()

    if not key:
        return jsonify({"valid": False, "reason": "EMPTY_KEY"})

    if not device_id:
        return jsonify({"valid": False, "reason": "EMPTY_DEVICE_ID"})

    item = LicenseKey.query.filter_by(key=key).first()

    if not item:
        return jsonify({"valid": False, "reason": "KEY_NOT_FOUND"})

    if not item.active:
        return jsonify({"valid": False, "reason": "KEY_DISABLED"})

    now = datetime.utcnow()

    if now > item.expires_at:
        return jsonify({"valid": False, "reason": "KEY_EXPIRED"})

    # Hiện tại max_devices=1 sẽ khóa theo 1 máy.
    # Nếu sau này muốn nhiều máy thật sự, cần thêm bảng devices riêng.
    if item.max_devices <= 1:
        if item.device_id and item.device_id != device_id:
            return jsonify({"valid": False, "reason": "DEVICE_LOCKED"})

        if not item.device_id:
            item.device_id = device_id
            db.session.commit()

    remaining_days = max(0, (item.expires_at - now).days)

    return jsonify({
        "valid": True,
        "reason": "OK",
        "expires_at": item.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
        "remaining_days": remaining_days,
        "active": item.active,
    })


LOGIN_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>License Admin Login</title>
</head>
<body style="font-family:Arial; padding:40px;">
    <h2>License Admin</h2>
    <form method="get" action="/">
        <input name="password" placeholder="Admin password" style="padding:10px; width:260px;">
        <button type="submit" style="padding:10px;">Login</button>
    </form>
    <p>Mật khẩu mặc định: <b>admin123</b></p>
</body>
</html>
"""

ADMIN_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>License Admin</title>
</head>
<body style="font-family:Arial; padding:30px;">
    <h1>SRT License Admin</h1>

    <h2>Tạo key mới</h2>
    <form method="post" action="/create">
        <input type="hidden" name="password" value="{{ password }}">
        Số ngày:
        <input name="days" value="30" type="number" style="padding:8px; width:90px;">
        Số máy:
        <input name="max_devices" value="1" type="number" style="padding:8px; width:70px;">
        Ghi chú:
        <input name="note" placeholder="Tên khách / đơn hàng" style="padding:8px; width:260px;">
        <button type="submit" style="padding:8px 14px;">Tạo key</button>
    </form>

    <h2>Danh sách key</h2>
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse; width:100%;">
        <tr>
            <th>ID</th>
            <th>Key</th>
            <th>Trạng thái</th>
            <th>Hết hạn</th>
            <th>Device</th>
            <th>Ghi chú</th>
            <th>Thao tác</th>
        </tr>
        {% for k in keys %}
        <tr>
            <td>{{ k.id }}</td>
            <td><b>{{ k.key }}</b></td>
            <td>{{ "ACTIVE" if k.active else "DISABLED" }}</td>
            <td>{{ k.expires_at }}</td>
            <td>{{ k.device_id or "" }}</td>
            <td>{{ k.note }}</td>
            <td>
                <a href="/toggle/{{ k.id }}?password={{ password }}">
                    {{ "Tắt key" if k.active else "Bật key" }}
                </a>
                |
                <a href="/reset_device/{{ k.id }}?password={{ password }}" onclick="return confirm('Reset máy cho key này?')">Reset máy</a>
                |
                <a href="/delete/{{ k.id }}?password={{ password }}" onclick="return confirm('Xóa key?')">Xóa</a>
                <form method="post" action="/extend/{{ k.id }}" style="display:inline;">
                    <input type="hidden" name="password" value="{{ password }}">
                    <input name="days" type="number" value="30" style="width:60px;">
                    <button type="submit">Gia hạn</button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
