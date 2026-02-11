import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secureshield-key")
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'secureshield.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # File uploads
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "json", "xml"}

    # Basic rate limiting (per-user cooldown in seconds for scans)
    SCAN_COOLDOWN_SECONDS = int(os.environ.get("SCAN_COOLDOWN_SECONDS", 15))
    ALLOWED_SCAN_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_SCAN_HOSTS", "").split(",") if h.strip()]

    # Report output folder
    REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
    EVIDENCE_FOLDER = os.path.join(BASE_DIR, "evidence")

    # Pagination
    PAGE_SIZE = 10


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
