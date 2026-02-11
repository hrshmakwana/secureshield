from datetime import datetime, timedelta

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, send_file, session, url_for)
from flask_login import current_user, login_required

from app import db
from app.models import ScanHistory, ScanEvidenceArchive
from app.services.report_service import generate_scan_report
from app.services.scan_service import is_valid_url, run_scan

scan_bp = Blueprint("scan", __name__, url_prefix="/scan")


def _within_cooldown() -> bool:
    last_scan = session.get("last_scan_at")
    if not last_scan:
        return False
    try:
        last_dt = datetime.fromisoformat(last_scan)
    except ValueError:
        return False
    cooldown = timedelta(seconds=current_app.config["SCAN_COOLDOWN_SECONDS"])
    return datetime.utcnow() - last_dt < cooldown


@scan_bp.route("/", methods=["GET", "POST"])
@login_required
def scan_url():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        cookie_header = request.form.get("cookie_header", "").strip()
        dom_scan = bool(request.form.get("dom_scan", True))

        if _within_cooldown():
            flash("Rate limit: please wait before scanning again.", "warning")
            return redirect(url_for("scan.scan_url"))

        if not is_valid_url(target_url):
            flash("Invalid URL. Include http/https and hostname.", "danger")
            return render_template("scan_url.html")

        try:
            cookies = None
            if cookie_header:
                cookies = {
                    item.split("=", 1)[0].strip(): item.split("=", 1)[1].strip()
                    for item in cookie_header.split(";")
                    if "=" in item
                }
            result = run_scan(
                target_url,
                allowed_hosts=current_app.config.get("ALLOWED_SCAN_HOSTS"),
                use_dom=dom_scan,
                evidence_folder=current_app.config.get("EVIDENCE_FOLDER"),
                cookies=cookies,
            )
            history = ScanHistory(
                user_id=current_user.id,
                target_url=target_url,
                sqli_result=result["sqli"],
                xss_result=result["xss"],
                severity=result["severity"],
                scan_date=datetime.utcnow(),
            )
            db.session.add(history)
            db.session.commit()
            for ev in result.get("evidence", []):
                rec = ScanEvidenceArchive(
                    scan_id=history.id,
                    kind=ev.get("type"),
                    target_url=ev.get("url"),
                    param=ev.get("param"),
                    header=ev.get("header"),
                    payload=ev.get("payload"),
                    status_code=ev.get("status_code"),
                    elapsed_ms=ev.get("elapsed_ms"),
                    snippet=ev.get("snippet"),
                )
                db.session.add(rec)
            db.session.commit()
            session["last_scan_at"] = datetime.utcnow().isoformat()
            current_app.log_action(f"scanned {target_url} (severity {result['severity']})")

            flash("Scan complete.", "success")
            return render_template("scan_result.html", result=result, target_url=target_url)
        except Exception as exc:  # noqa: BLE001
            flash(f"Scan failed: {exc}", "danger")

    return render_template("scan_url.html")


@scan_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "").strip()
    query = ScanHistory.query.filter_by(user_id=current_user.id)
    if search:
        query = query.filter(ScanHistory.target_url.contains(search))
    pagination = query.order_by(ScanHistory.scan_date.desc()).paginate(
        page=page,
        per_page=current_app.config["PAGE_SIZE"],
        error_out=False,
    )
    return render_template("scan_history.html", pagination=pagination, search=search)


@scan_bp.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id: int):
    record = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    scan_data = {
        "scan_date": record.scan_date.strftime("%Y-%m-%d %H:%M UTC"),
        "target_url": record.target_url,
        "severity": record.severity,
        "sqli": record.sqli_result,
        "xss": record.xss_result,
    }
    path = generate_scan_report(current_app.config["REPORT_FOLDER"], scan_data)
    current_app.log_action(f"downloaded report for scan {record.id}")
    return send_file(path, as_attachment=True)
