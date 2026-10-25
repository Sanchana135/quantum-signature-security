import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, abort
from app.models import db, User, VerificationRecord, SecurityEvent
from app.auth.utils import login_required, get_current_user, validate_csrf_token
from app.crypto.rsa_engine import (
    generate_rsa_keypair,
    sign_message_rsa_pss,
    verify_signature_rsa_pss,
    tamper_message,
    tamper_signature
)
from app.ml.quantum_engine import QuantumInspiredThreatEngine
from app.ml.anomaly_model import ClassicalAnomalyModel

core_bp = Blueprint("core", __name__)
quantum_engine = QuantumInspiredThreatEngine()
classical_model = ClassicalAnomalyModel()

def get_recent_failures_count(ip_address: str, window_minutes: int = 10) -> int:
    """Calculates number of failed verification attempts from this IP within the rolling window."""
    since_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    count = VerificationRecord.query.filter(
        VerificationRecord.ip_address == ip_address,
        VerificationRecord.is_crypto_valid == False,
        VerificationRecord.timestamp >= since_time
    ).count()
    return count

def get_recent_frequency(ip_address: str, window_minutes: int = 5) -> float:
    """Calculates verification attempts per minute from this IP within the rolling window."""
    since_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    count = VerificationRecord.query.filter(
        VerificationRecord.ip_address == ip_address,
        VerificationRecord.timestamp >= since_time
    ).count()
    # At least 1 min to prevent zero division
    return max(round(count / max(window_minutes, 1), 2), 0.5)


@core_bp.route("/")
def index():
    """Public landing page showcasing system capabilities."""
    if session.get("user_id"):
        return redirect(url_for("core.dashboard"))
    return render_template("index.html")


@core_bp.route("/dashboard")
@login_required
def dashboard():
    """Main security command center with real DB metrics and Chart.js analytics."""
    user = get_current_user()

    # Query real database records
    total_verifications = VerificationRecord.query.count()
    valid_count = VerificationRecord.query.filter_by(is_crypto_valid=True).count()
    invalid_count = VerificationRecord.query.filter_by(is_crypto_valid=False).count()
    
    # Suspicious/anomalous attempts: threat score > 50 or high/critical risk
    anomalous_count = VerificationRecord.query.filter(
        (VerificationRecord.threat_score >= 50.0) | (VerificationRecord.risk_level.in_(["HIGH", "CRITICAL"]))
    ).count()

    valid_percentage = round((valid_count / total_verifications * 100), 1) if total_verifications > 0 else 0.0

    # Risk level counts
    low_risk_count = VerificationRecord.query.filter_by(risk_level="LOW").count()
    med_risk_count = VerificationRecord.query.filter_by(risk_level="MEDIUM").count()
    high_risk_count = VerificationRecord.query.filter_by(risk_level="HIGH").count()
    crit_risk_count = VerificationRecord.query.filter_by(risk_level="CRITICAL").count()

    # Recent verification records
    recent_verifications = VerificationRecord.query.order_by(
        VerificationRecord.timestamp.desc()
    ).limit(8).all()

    # Recent critical/high security events
    recent_alerts = SecurityEvent.query.filter(
        SecurityEvent.severity.in_(["HIGH", "CRITICAL"])
    ).order_by(SecurityEvent.timestamp.desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        user=user,
        total_verifications=total_verifications,
        valid_count=valid_count,
        invalid_count=invalid_count,
        anomalous_count=anomalous_count,
        valid_percentage=valid_percentage,
        low_risk_count=low_risk_count,
        med_risk_count=med_risk_count,
        high_risk_count=high_risk_count,
        crit_risk_count=crit_risk_count,
        recent_verifications=recent_verifications,
        recent_alerts=recent_alerts,
    )


@core_bp.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    """Digital signature verification with Quantum-Inspired Threat Analysis."""
    user = get_current_user()
    verification_result = None
    quantum_result = None
    ml_result = None

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Invalid security token. Please resubmit the verification form.", "danger")
            return render_template("verify.html", user=user)

        # 1. Extract message (direct text or uploaded file)
        message_content = request.form.get("message", "")
        message_file = request.files.get("message_file")
        if message_file and message_file.filename:
            try:
                message_content = message_file.read().decode("utf-8", errors="replace")
            except Exception as e:
                flash(f"Error reading message file: {str(e)}", "danger")

        # 2. Extract public key (direct text or uploaded file)
        public_key_pem = request.form.get("public_key", "")
        key_file = request.files.get("public_key_file")
        if key_file and key_file.filename:
            try:
                public_key_pem = key_file.read().decode("utf-8", errors="replace")
            except Exception as e:
                flash(f"Error reading public key file: {str(e)}", "danger")

        # 3. Extract signature (direct text or uploaded file)
        signature_b64 = request.form.get("signature", "")
        sig_file = request.files.get("signature_file")
        if sig_file and sig_file.filename:
            try:
                signature_b64 = sig_file.read().decode("utf-8", errors="replace")
            except Exception as e:
                flash(f"Error reading signature file: {str(e)}", "danger")

        # Basic presence validation
        if not message_content.strip() or not public_key_pem.strip() or not signature_b64.strip():
            flash("Please provide the message payload, public key PEM, and Base64 signature.", "warning")
            return render_template(
                "verify.html",
                user=user,
                message=message_content,
                public_key=public_key_pem,
                signature=signature_b64
            )

        client_ip = request.remote_addr or "127.0.0.1"
        recent_fails = get_recent_failures_count(client_ip)
        velocity = get_recent_frequency(client_ip)

        # 4. Deterministic RSA-PSS Verification
        verification_result = verify_signature_rsa_pss(
            public_key_pem=public_key_pem,
            message=message_content,
            signature_b64=signature_b64
        )

        # 5. Quantum-Inspired Threat Analysis
        quantum_result = quantum_engine.evaluate(
            is_crypto_valid=verification_result["is_valid"],
            recent_failures_count=recent_fails,
            attempt_frequency_per_min=velocity,
            key_size=verification_result.get("key_size"),
            format_issues_count=len(verification_result.get("format_issues", []))
        )

        # 6. Comparative Classical ML (Isolation Forest)
        ml_result = classical_model.predict_anomaly(quantum_result["features"])

        # 7. Persist Verification Record in SQLite Database
        record = VerificationRecord(
            user_id=user.id if user else None,
            message_preview=verification_result["message_preview"],
            message_hash=verification_result["message_hash"],
            signature_preview=verification_result["signature_preview"],
            key_fingerprint=verification_result.get("key_fingerprint") or "N/A",
            key_size=verification_result.get("key_size"),
            algorithm=verification_result.get("algorithm", "RSA-PSS-SHA256"),
            is_crypto_valid=verification_result["is_valid"],
            crypto_error=verification_result.get("error"),
            threat_score=quantum_result["threat_score"],
            risk_level=quantum_result["risk_level"],
            detection_reasons_json=json.dumps(quantum_result["detection_reasons"]),
            feature_breakdown_json=json.dumps({
                "features": quantum_result["features"],
                "amplitudes": quantum_result["amplitudes"],
                "amplitude_contributions": quantum_result["amplitude_contributions"],
                "ml_benchmark": ml_result,
            }),
            ip_address=client_ip,
            user_agent=request.user_agent.string[:250] if request.user_agent else "Unknown",
        )
        db.session.add(record)
        db.session.flush()

        # 8. Record Security Event
        if not verification_result["is_valid"]:
            event_severity = "HIGH" if quantum_result["threat_score"] >= 60.0 else "MEDIUM"
            if quantum_result["threat_score"] >= 80.0:
                event_severity = "CRITICAL"

            sec_event = SecurityEvent(
                user_id=user.id if user else None,
                verification_id=record.id,
                event_type="CRYPTO_VERIFY_FAILURE",
                severity=event_severity,
                title="Signature Verification Failed",
                description=(
                    f"Cryptographic failure for key fingerprint {record.key_fingerprint[:16]}... "
                    f"Threat Score: {record.threat_score:.1f} ({record.risk_level}). "
                    f"Error: {record.crypto_error or 'Signature mismatch'}"
                ),
                ip_address=client_ip,
            )
            db.session.add(sec_event)

            # Check for burst threshold
            if recent_fails >= 3:
                burst_event = SecurityEvent(
                    user_id=user.id if user else None,
                    verification_id=record.id,
                    event_type="BURST_ATTACK_DETECTED",
                    severity="CRITICAL",
                    title="Repeated Failure Burst Warning",
                    description=f"Rapid failed verification attempts from IP {client_ip} ({recent_fails + 1} attempts in window).",
                    ip_address=client_ip,
                )
                db.session.add(burst_event)
        else:
            sec_event = SecurityEvent(
                user_id=user.id if user else None,
                verification_id=record.id,
                event_type="CRYPTO_VERIFY_SUCCESS",
                severity="INFO",
                title="Digital Signature Verified",
                description=f"Mathematical integrity confirmed for key {record.key_fingerprint[:16]}... Threat Score: {record.threat_score:.1f}.",
                ip_address=client_ip,
            )
            db.session.add(sec_event)

        db.session.commit()

        if verification_result["is_valid"]:
            flash("Digital signature successfully verified. Mathematical integrity intact.", "success")
        else:
            flash(f"Verification failed: {verification_result.get('error', 'Signature mismatch.')}", "danger")

        return render_template(
            "verify.html",
            user=user,
            message=message_content,
            public_key=public_key_pem,
            signature=signature_b64,
            verification_result=verification_result,
            quantum_result=quantum_result,
            ml_result=ml_result,
            record_id=record.id,
        )

    return render_template("verify.html", user=user)


@core_bp.route("/demo-signer")
@login_required
def demo_signer():
    """Interactive laboratory for generating demo keys, signing, and simulating tampering."""
    user = get_current_user()
    return render_template("demo_signer.html", user=user)


@core_bp.route("/analysis")
@login_required
def analysis():
    """Interactive quantum-inspired threat detection laboratory & simulation console."""
    user = get_current_user()
    return render_template("analysis.html", user=user)


@core_bp.route("/analysis/<int:record_id>")
@login_required
def analysis_detail(record_id: int):
    """Detailed forensic drill-down for an individual verification record."""
    user = get_current_user()
    record = VerificationRecord.query.get_or_404(record_id)
    return render_template("analysis_detail.html", user=user, record=record)


@core_bp.route("/events")
@login_required
def events():
    """Security audit event log with filtering, searching, and pagination."""
    user = get_current_user()
    
    # Query parameters
    page = request.args.get("page", 1, type=int)
    severity = request.args.get("severity", "").strip().upper()
    event_type = request.args.get("event_type", "").strip()
    search = request.args.get("q", "").strip()

    query = SecurityEvent.query

    if severity in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        query = query.filter(SecurityEvent.severity == severity)

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    if search:
        query = query.filter(
            (SecurityEvent.title.ilike(f"%{search}%")) |
            (SecurityEvent.description.ilike(f"%{search}%")) |
            (SecurityEvent.ip_address.ilike(f"%{search}%"))
        )

    pagination = query.order_by(SecurityEvent.timestamp.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    return render_template(
        "events.html",
        user=user,
        pagination=pagination,
        severity=severity,
        event_type=event_type,
        search=search,
    )


@core_bp.route("/about")
def about():
    """Academic architecture, quantum-inspired mathematical theory, and college demo guide."""
    user = get_current_user()
    return render_template("about.html", user=user)
