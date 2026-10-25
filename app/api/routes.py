import io
import csv
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify, request, session, make_response
from sqlalchemy import func
from app.models import db, User, VerificationRecord, SecurityEvent
from app.auth.utils import login_required, get_current_user
from app.crypto.rsa_engine import (
    generate_rsa_keypair,
    sign_message_rsa_pss,
    verify_signature_rsa_pss,
    tamper_message,
    tamper_signature
)
from app.ml.quantum_engine import QuantumInspiredThreatEngine
from app.ml.anomaly_model import ClassicalAnomalyModel

api_bp = Blueprint("api", __name__, url_prefix="/api")
quantum_engine = QuantumInspiredThreatEngine()
classical_model = ClassicalAnomalyModel()

@api_bp.route("/dashboard/stats")
@login_required
def dashboard_stats():
    """
    Returns aggregated metrics computed directly from database tables
    for Chart.js dynamic rendering.
    """
    total = VerificationRecord.query.count()
    valid_count = VerificationRecord.query.filter_by(is_crypto_valid=True).count()
    invalid_count = VerificationRecord.query.filter_by(is_crypto_valid=False).count()
    
    # Severity breakdown
    low_count = VerificationRecord.query.filter_by(risk_level="LOW").count()
    med_count = VerificationRecord.query.filter_by(risk_level="MEDIUM").count()
    high_count = VerificationRecord.query.filter_by(risk_level="HIGH").count()
    crit_count = VerificationRecord.query.filter_by(risk_level="CRITICAL").count()

    # Average threat score
    avg_score = db.session.query(func.avg(VerificationRecord.threat_score)).scalar() or 0.0

    # 7-day trend analysis
    labels = []
    valid_trend = []
    invalid_trend = []
    anomaly_trend = []

    now = datetime.now(timezone.utc)
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        labels.append(day_start.strftime("%b %d"))

        day_valid = VerificationRecord.query.filter(
            VerificationRecord.timestamp >= day_start,
            VerificationRecord.timestamp < day_end,
            VerificationRecord.is_crypto_valid == True,
        ).count()
        valid_trend.append(day_valid)

        day_invalid = VerificationRecord.query.filter(
            VerificationRecord.timestamp >= day_start,
            VerificationRecord.timestamp < day_end,
            VerificationRecord.is_crypto_valid == False,
        ).count()
        invalid_trend.append(day_invalid)

        day_anomaly = VerificationRecord.query.filter(
            VerificationRecord.timestamp >= day_start,
            VerificationRecord.timestamp < day_end,
            VerificationRecord.threat_score >= 50.0,
        ).count()
        anomaly_trend.append(day_anomaly)

    # Threat Score Distribution (Buckets: 0-20, 21-40, 41-60, 61-80, 81-100)
    bucket_0_20 = VerificationRecord.query.filter(VerificationRecord.threat_score <= 20).count()
    bucket_21_40 = VerificationRecord.query.filter(VerificationRecord.threat_score > 20, VerificationRecord.threat_score <= 40).count()
    bucket_41_60 = VerificationRecord.query.filter(VerificationRecord.threat_score > 40, VerificationRecord.threat_score <= 60).count()
    bucket_61_80 = VerificationRecord.query.filter(VerificationRecord.threat_score > 60, VerificationRecord.threat_score <= 80).count()
    bucket_81_100 = VerificationRecord.query.filter(VerificationRecord.threat_score > 80).count()

    # Category Breakdown from reasons
    burst_events = SecurityEvent.query.filter_by(event_type="BURST_ATTACK_DETECTED").count()
    crypto_failures = SecurityEvent.query.filter_by(event_type="CRYPTO_VERIFY_FAILURE").count()
    crypto_successes = SecurityEvent.query.filter_by(event_type="CRYPTO_VERIFY_SUCCESS").count()

    return jsonify({
        "status": "success",
        "data": {
            "summary": {
                "total": total,
                "valid": valid_count,
                "invalid": invalid_count,
                "anomalous": high_count + crit_count,
                "average_threat_score": round(float(avg_score), 2),
                "valid_rate": round((valid_count / total * 100), 1) if total > 0 else 0.0,
            },
            "severity_distribution": {
                "low": low_count,
                "medium": med_count,
                "high": high_count,
                "critical": crit_count,
            },
            "score_distribution": {
                "labels": ["0-20 (Low)", "21-40 (Guarded)", "41-60 (Elevated)", "61-80 (High)", "81-100 (Critical)"],
                "counts": [bucket_0_20, bucket_21_40, bucket_41_60, bucket_61_80, bucket_81_100],
            },
            "weekly_trends": {
                "labels": labels,
                "valid": valid_trend,
                "invalid": invalid_trend,
                "anomalies": anomaly_trend,
            },
            "category_breakdown": {
                "labels": ["Cryptographic Success", "Signature Mismatch", "Burst / Rapid Failures", "Key / Format Anomaly"],
                "counts": [
                    crypto_successes,
                    crypto_failures,
                    burst_events,
                    max(invalid_count - crypto_failures, 0) + (1 if crit_count > 0 else 0)
                ]
            }
        }
    })


@api_bp.route("/demo/generate-keys", methods=["POST"])
@login_required
def api_generate_keys():
    """Generates an RSA-2048 key pair for demonstration purposes."""
    data = request.get_json() or {}
    key_size = int(data.get("key_size", 2048))
    if key_size not in (1024, 2048, 3072):
        key_size = 2048

    priv_pem, pub_pem = generate_rsa_keypair(key_size=key_size)
    return jsonify({
        "status": "success",
        "data": {
            "private_key": priv_pem,
            "public_key": pub_pem,
            "key_size": key_size,
            "algorithm": "RSA-PSS-SHA256",
            "warning": "Demonstration Key Only. Do not use in production.",
        }
    })


@api_bp.route("/demo/sign", methods=["POST"])
@login_required
def api_sign_message():
    """Signs message payload with demo private key."""
    data = request.get_json() or {}
    private_key_pem = data.get("private_key", "")
    message = data.get("message", "")

    if not private_key_pem.strip() or not message.strip():
        return jsonify({"status": "error", "message": "Missing private key or message payload."}), 400

    try:
        sig_b64 = sign_message_rsa_pss(private_key_pem, message)
        return jsonify({
            "status": "success",
            "data": {
                "signature": sig_b64,
                "algorithm": "RSA-PSS-SHA256",
                "message_bytes_len": len(message.encode("utf-8")),
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Signing failed: {str(e)}"}), 400


@api_bp.route("/demo/tamper", methods=["POST"])
@login_required
def api_tamper():
    """Simulates payload or signature bit modification."""
    data = request.get_json() or {}
    tamper_type = data.get("type", "message")
    content = data.get("content", "")

    if not content:
        return jsonify({"status": "error", "message": "Content to tamper is required."}), 400

    if tamper_type == "message":
        tampered = tamper_message(content)
    else:
        tampered = tamper_signature(content)

    return jsonify({
        "status": "success",
        "data": {
            "tampered": tampered,
            "tamper_type": tamper_type,
            "notice": "Byte alteration simulated. Mathematical verification will fail.",
        }
    })


@api_bp.route("/analysis/evaluate", methods=["POST"])
@login_required
def api_analysis_evaluate():
    """
    Live simulator endpoint to dynamically compute quantum-inspired amplitudes
    and comparative Isolation Forest inference based on custom slider inputs.
    """
    data = request.get_json() or {}
    is_crypto_valid = bool(data.get("is_crypto_valid", True))
    recent_fails = int(data.get("recent_failures", 0))
    velocity = float(data.get("velocity", 1.0))
    key_size = int(data.get("key_size", 2048))
    format_issues = int(data.get("format_issues", 0))

    quantum_result = quantum_engine.evaluate(
        is_crypto_valid=is_crypto_valid,
        recent_failures_count=recent_fails,
        attempt_frequency_per_min=velocity,
        key_size=key_size,
        format_issues_count=format_issues,
    )

    ml_result = classical_model.predict_anomaly(quantum_result["features"])

    return jsonify({
        "status": "success",
        "data": {
            "quantum": quantum_result,
            "isolation_forest": ml_result,
        }
    })


@api_bp.route("/export/events")
@login_required
def export_events_csv():
    """Exports security audit events as a downloadable CSV report."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp (UTC)", "Event Type", "Severity", "Title", "Description", "IP Address", "User ID"])

    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(1000).all()
    for ev in events:
        writer.writerow([
            ev.id,
            ev.timestamp.isoformat() if ev.timestamp else "",
            ev.event_type,
            ev.severity,
            ev.title,
            ev.description,
            ev.ip_address or "N/A",
            ev.user_id or "Anonymous",
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response
