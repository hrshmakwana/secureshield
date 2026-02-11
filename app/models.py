from datetime import datetime

import bcrypt
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    file_monitorings = db.relationship("FileMonitoring", backref="user", lazy=True)
    scans = db.relationship("ScanHistory", backref="user", lazy=True)
    activities = db.relationship("ActivityLog", backref="user", lazy=True)

    def set_password(self, password: str):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    def is_admin(self) -> bool:
        return self.role.lower() == "admin"


class FileMonitoring(db.Model):
    __tablename__ = "file_monitoring"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_hash = db.Column(db.String(64), nullable=False)
    last_checked_hash = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), default="Safe")
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked_at = db.Column(db.DateTime, nullable=True)


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    sqli_result = db.Column(db.Boolean, default=False)
    xss_result = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String(20), default="Low")
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(64))


class ScanEvidenceArchive(db.Model):
    __tablename__ = 'scan_evidence'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)
    kind = db.Column(db.String(50), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    param = db.Column(db.String(120))
    header = db.Column(db.String(120))
    payload = db.Column(db.Text)
    status_code = db.Column(db.Integer)
    elapsed_ms = db.Column(db.Integer)
    snippet = db.Column(db.Text)

    scan = db.relationship('ScanHistory', backref=db.backref('evidence', lazy=True))
