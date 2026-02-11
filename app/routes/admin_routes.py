from functools import wraps

from flask import Blueprint, abort, render_template
from flask_login import current_user, login_required

from app.models import ActivityLog, ScanHistory, User

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


@admin_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    users = User.query.order_by(User.created_at.desc()).limit(10).all()
    scans = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).limit(10).all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(15).all()
    return render_template("admin_dashboard.html", users=users, scans=scans, logs=logs)
