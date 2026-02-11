import os
from datetime import datetime

from flask import Flask, g, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf import CSRFProtect

from config import DevelopmentConfig


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required folders exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)
    os.makedirs(app.config.get("EVIDENCE_FOLDER", app.config["REPORT_FOLDER"]), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    from app.routes.auth_routes import auth_bp
    from app.routes.file_routes import file_bp
    from app.routes.scan_routes import scan_bp
    from app.routes.admin_routes import admin_bp
    from app.routes.main_routes import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)

    @app.before_request
    def inject_user():
        g.user = current_user

    @app.after_request
    def set_secure_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        return response

    @app.context_processor
    def inject_config():
        return {"app_config": app.config}

    from flask import render_template  # noqa: WPS433

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("403.html"), 403

    from app.models import ActivityLog  # noqa: WPS433

    def log_action(action: str, user_id: int | None = None):
        target_user_id = user_id or (current_user.id if current_user.is_authenticated else None)
        if not target_user_id:
            return
        entry = ActivityLog(
            user_id=target_user_id,
            action=action,
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()

    app.log_action = log_action  # type: ignore[attr-defined]

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models import User  # noqa: WPS433

    return User.query.get(int(user_id))
