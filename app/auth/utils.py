import re
import secrets
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort, g
from app.models import User

def generate_csrf_token() -> str:
    """Generates or retrieves the session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token(token: str) -> bool:
    """Validates the submitted token against the session token."""
    expected = session.get("_csrf_token")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)

def get_current_user() -> User | None:
    """Retrieves the currently authenticated User instance, cached in flask.g."""
    if not hasattr(g, "_current_user"):
        user_id = session.get("user_id")
        if user_id:
            from app.models import db
            g._current_user = db.session.get(User, user_id)
        else:
            g._current_user = None
    return g._current_user

def login_required(view_func):
    """Decorator to require authenticated session."""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Authentication required to access this console.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view_func(*args, **kwargs)
    return decorated_view

def admin_required(view_func):
    """Decorator to require admin role."""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        user = get_current_user()
        if not user or user.role != "admin":
            flash("Administrative privileges required.", "danger")
            return redirect(url_for("core.dashboard"))
        return view_func(*args, **kwargs)
    return decorated_view

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validates password complexity:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$%^&*...)."
    return True, ""

def validate_username(username: str) -> tuple[bool, str]:
    """Validates username syntax."""
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username may only contain letters, numbers, and underscores."
    return True, ""

def validate_email(email: str) -> tuple[bool, str]:
    """Validates email format."""
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_regex, email):
        return False, "Please enter a valid email address."
    return True, ""
