import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, session, jsonify
from app.config import config_by_name
from app.models import db, User
from app.auth.utils import generate_csrf_token, get_current_user

def create_app(config_name: str = "default") -> Flask:
    """Application factory for the Quantum-Inspired Cyber Threat Detection system."""
    app = Flask(__name__)
    
    # Load configuration
    cfg = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(cfg)

    # Initialize extensions
    db.init_app(app)

    # Register Context Processors
    @app.context_processor
    def inject_global_helpers():
        return {
            "csrf_token": generate_csrf_token,
            "current_user": get_current_user(),
            "current_year": datetime.now(timezone.utc).year,
        }

    # Register Blueprints
    from app.auth import auth_bp
    from app.core import core_bp
    from app.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(core_bp)
    app.register_blueprint(api_bp)

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Resource not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Internal server error"}), 500
        return render_template("errors/500.html"), 500

    @app.errorhandler(413)
    def request_entity_too_large(e):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "File exceeds 2MB upload limit"}), 413
        return render_template("errors/500.html", error_message="Uploaded payload exceeds maximum 2MB size limit."), 413

    # Ensure tables are created
    with app.app_context():
        db.create_all()

    return app
