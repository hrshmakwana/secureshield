import re
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for, current_app
from flask_login import current_user, login_required, login_user, logout_user

from app import db
from app.models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-]).{8,}")


def password_strong(password: str) -> bool:
    return bool(PASSWORD_REGEX.match(password))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if not password_strong(password):
            flash("Password must be 8+ chars with upper, lower, digit, symbol.", "warning")
            return render_template("register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("User with that username or email already exists.", "danger")
            return render_template("register.html")

        user = User(username=username, email=email, role="user", created_at=datetime.utcnow())
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        current_app.log_action("registered account", user_id=user.id)
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username_or_email = request.form.get("username", "")
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email.lower())
        ).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            current_app.log_action("logged in")
            flash("Welcome back!", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    current_app.log_action("logged out")
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))
