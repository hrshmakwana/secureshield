from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.models import FileMonitoring, ScanHistory

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    file_count = FileMonitoring.query.filter_by(user_id=current_user.id).count()
    modified_count = FileMonitoring.query.filter_by(user_id=current_user.id, status="Modified").count()
    scan_count = ScanHistory.query.filter_by(user_id=current_user.id).count()
    recent_scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scan_date.desc())
        .limit(5)
        .all()
    )
    return render_template(
        "dashboard.html",
        file_count=file_count,
        modified_count=modified_count,
        scan_count=scan_count,
        recent_scans=recent_scans,
    )
