import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default="analyst", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    verifications = db.relationship("VerificationRecord", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    events = db.relationship("SecurityEvent", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class VerificationRecord(db.Model):
    __tablename__ = "verification_records"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    # Safe metadata: only preview and SHA-256 hash stored (no sensitive payloads stored raw)
    message_preview = db.Column(db.String(120), nullable=False)
    message_hash = db.Column(db.String(64), nullable=False, index=True)
    signature_preview = db.Column(db.String(64), nullable=False)
    key_fingerprint = db.Column(db.String(64), nullable=False, index=True)
    key_size = db.Column(db.Integer, nullable=True)
    algorithm = db.Column(db.String(64), default="RSA-PSS-SHA256", nullable=False)
    
    # Deterministic Cryptographic Verification
    is_crypto_valid = db.Column(db.Boolean, nullable=False, index=True)
    crypto_error = db.Column(db.Text, nullable=True)
    
    # Quantum-Inspired Anomaly Scoring
    threat_score = db.Column(db.Float, nullable=False, index=True)  # 0.0 to 100.0
    risk_level = db.Column(db.String(20), nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    detection_reasons_json = db.Column(db.Text, nullable=False, default="[]")
    feature_breakdown_json = db.Column(db.Text, nullable=False, default="{}")
    
    # Network context
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    # Relationships
    events = db.relationship("SecurityEvent", backref="verification_record", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def detection_reasons(self):
        try:
            return json.loads(self.detection_reasons_json)
        except Exception:
            return []

    @property
    def feature_breakdown(self):
        try:
            return json.loads(self.feature_breakdown_json)
        except Exception:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Anonymous",
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "message_preview": self.message_preview,
            "message_hash": self.message_hash,
            "signature_preview": self.signature_preview,
            "key_fingerprint": self.key_fingerprint,
            "key_size": self.key_size,
            "algorithm": self.algorithm,
            "is_crypto_valid": self.is_crypto_valid,
            "crypto_error": self.crypto_error,
            "threat_score": round(self.threat_score, 2),
            "risk_level": self.risk_level,
            "detection_reasons": self.detection_reasons,
            "feature_breakdown": self.feature_breakdown,
            "ip_address": self.ip_address,
        }


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    verification_id = db.Column(db.Integer, db.ForeignKey("verification_records.id"), nullable=True, index=True)
    
    event_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "verification_id": self.verification_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
        }
