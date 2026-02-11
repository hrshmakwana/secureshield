from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.models import FileMonitoring
from app.services.hash_service import allowed_file, compute_sha256, sanitize_filename

file_bp = Blueprint("file", __name__, url_prefix="/files")


def _validate_file(upload):
    if not upload or upload.filename == "":
        raise ValueError("No file selected")
    if not allowed_file(upload.filename, set(current_app.config["ALLOWED_EXTENSIONS"])):
        raise ValueError("File type not allowed")


@file_bp.route("/", methods=["GET"])
@login_required
def list_files():
    records = FileMonitoring.query.filter_by(user_id=current_user.id).order_by(FileMonitoring.uploaded_at.desc()).all()
    return render_template("file_list.html", records=records)


@file_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        upload = request.files.get("file")
        try:
            _validate_file(upload)
            filename = sanitize_filename(upload.filename)
            file_hash = compute_sha256(upload.stream)

            existing = FileMonitoring.query.filter_by(user_id=current_user.id, filename=filename).first()
            if existing:
                existing.original_hash = file_hash
                existing.status = "Safe"
                existing.uploaded_at = datetime.utcnow()
            else:
                record = FileMonitoring(
                    user_id=current_user.id,
                    filename=filename,
                    original_hash=file_hash,
                    status="Safe",
                    uploaded_at=datetime.utcnow(),
                )
                db.session.add(record)

            db.session.commit()
            current_app.log_action(f"uploaded baseline for {filename}")
            flash("File baseline stored.", "success")
            return redirect(url_for("file.list_files"))
        except ValueError as exc:
            flash(str(exc), "danger")

    return render_template("upload_file.html")


@file_bp.route("/recheck/<int:file_id>", methods=["POST"])
@login_required
def recheck_file(file_id: int):
    record = FileMonitoring.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    upload = request.files.get("file")
    try:
        _validate_file(upload)
        filename = sanitize_filename(upload.filename)
        if filename != record.filename:
            raise ValueError("Filename must match the stored baseline")

        new_hash = compute_sha256(upload.stream)
        record.last_checked_hash = new_hash
        record.last_checked_at = datetime.utcnow()
        record.status = "Safe" if new_hash == record.original_hash else "Modified"
        db.session.commit()
        current_app.log_action(f"rechecked file {filename} ({record.status})")
        if record.status == "Modified":
            flash("File has been modified!", "danger")
        else:
            flash("File remains unchanged.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")

    return redirect(url_for("file.list_files"))
