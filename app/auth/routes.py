from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g
from app.models import db, User, SecurityEvent
from app.auth.utils import (
    login_required,
    validate_csrf_token,
    validate_password_strength,
    validate_username,
    validate_email,
    get_current_user
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("core.dashboard"))

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Invalid or expired session security token. Please try again.", "danger")
            return render_template("auth/login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "warning")
            return render_template("auth/login.html", username=username)

        user = User.query.filter_by(username=username).first()

        # Secure constant-time-like check and generic error to prevent enumeration
        if not user or not user.check_password(password):
            # Log failed auth event
            sec_event = SecurityEvent(
                user_id=user.id if user else None,
                event_type="AUTH_LOGIN_FAILED",
                severity="MEDIUM",
                title="Failed Authentication Attempt",
                description=f"Failed login attempt for username '{username}'.",
                ip_address=request.remote_addr,
            )
            db.session.add(sec_event)
            db.session.commit()
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", username=username)

        # Successful login
        session.clear()
        session["user_id"] = user.id
        session.permanent = True
        user.last_login = datetime.now(timezone.utc)

        sec_event = SecurityEvent(
            user_id=user.id,
            event_type="AUTH_LOGIN_SUCCESS",
            severity="INFO",
            title="User Session Authenticated",
            description=f"User '{user.username}' successfully authenticated.",
            ip_address=request.remote_addr,
        )
        db.session.add(sec_event)
        db.session.commit()

        flash(f"Welcome back, Analyst {user.username}. Security shield active.", "success")
        next_page = request.args.get("next")
        if next_page and next_page.startswith("/"):
            return redirect(next_page)
        return redirect(url_for("core.dashboard"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("core.dashboard"))

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Invalid or expired session security token. Please try again.", "danger")
            return render_template("auth/register.html")

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Syntax Validation
        valid_u, u_err = validate_username(username)
        if not valid_u:
            flash(u_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        valid_e, e_err = validate_email(email)
        if not valid_e:
            flash(e_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", username=username, email=email)

        valid_p, p_err = validate_password_strength(password)
        if not valid_p:
            flash(p_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        # 2. Duplicate Account Prevention
        if User.query.filter_by(username=username).first():
            flash("Username is already registered. Please choose another username.", "warning")
            return render_template("auth/register.html", username="", email=email)

        if User.query.filter_by(email=email).first():
            flash("Email address is already registered. Please log in or use a different email.", "warning")
            return render_template("auth/register.html", username=username, email="")

        # 3. Create User
        new_user = User(
            username=username,
            email=email,
            role="analyst",
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()

        sec_event = SecurityEvent(
            user_id=new_user.id,
            event_type="AUTH_REGISTER_SUCCESS",
            severity="INFO",
            title="New User Registered",
            description=f"New analyst account registered: {username}.",
            ip_address=request.remote_addr,
        )
        db.session.add(sec_event)
        db.session.commit()

        # Automatic login after registration
        session.clear()
        session["user_id"] = new_user.id
        session.permanent = True

        flash("Account created successfully! Welcome to the Quantum Threat Detection platform.", "success")
        return redirect(url_for("core.dashboard"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
def logout():
    user = get_current_user()
    if user:
        sec_event = SecurityEvent(
            user_id=user.id,
            event_type="AUTH_LOGOUT",
            severity="INFO",
            title="User Logged Out",
            description=f"User '{user.username}' signed out securely.",
            ip_address=request.remote_addr,
        )
        db.session.add(sec_event)
        db.session.commit()

    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Security token validation failed.", "danger")
            return redirect(url_for("auth.profile"))

        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not user.check_password(current_pw):
            flash("Current password verification failed.", "danger")
            return redirect(url_for("auth.profile"))

        if new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("auth.profile"))

        valid_p, p_err = validate_password_strength(new_pw)
        if not valid_p:
            flash(p_err, "danger")
            return redirect(url_for("auth.profile"))

        user.set_password(new_pw)
        
        sec_event = SecurityEvent(
            user_id=user.id,
            event_type="AUTH_PASSWORD_CHANGED",
            severity="MEDIUM",
            title="Password Changed",
            description=f"Password updated for user '{user.username}'.",
            ip_address=request.remote_addr,
        )
        db.session.add(sec_event)
        db.session.commit()

        flash("Password successfully updated.", "success")
        return redirect(url_for("auth.profile"))

    # Get recent user verifications
    recent_verifications = user.verifications.order_by(
        db.desc(db.text("timestamp"))
    ).limit(5).all()

    return render_template("auth/profile.html", user=user, recent_verifications=recent_verifications)
