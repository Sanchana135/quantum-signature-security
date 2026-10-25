from app.models import db, VerificationRecord, SecurityEvent
from app.crypto.rsa_engine import sign_message_rsa_pss

def test_verification_persistence_and_event_logging(auth_client, app, sample_rsa_pair):
    """Verify that submitting a verification request persists both record and event."""
    priv_pem = sample_rsa_pair["private_key"]
    pub_pem = sample_rsa_pair["public_key"]
    message = "FINANCIAL_PAYLOAD_TRANSFER_99182"
    sig_b64 = sign_message_rsa_pss(priv_pem, message)

    with auth_client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    res = auth_client.post("/verify", data={
        "csrf_token": "valid-token",
        "message": message,
        "public_key": pub_pem,
        "signature": sig_b64,
    })

    assert res.status_code == 200
    assert b"MATHEMATICALLY VALID" in res.data

    with app.app_context():
        record = VerificationRecord.query.first()
        assert record is not None
        assert record.is_crypto_valid is True
        assert record.threat_score <= 25.0
        assert record.risk_level == "LOW"

        event = SecurityEvent.query.filter_by(verification_id=record.id).first()
        assert event is not None
        assert event.event_type == "CRYPTO_VERIFY_SUCCESS"


def test_repeated_failure_burst_detection(auth_client, app, sample_rsa_pair):
    """Verify that multiple failed verification attempts trigger a critical burst alert."""
    pub_pem = sample_rsa_pair["public_key"]
    bad_signature = "AAAA" * 64

    with auth_client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    # Execute 4 consecutive failed verification attempts from same client
    for i in range(4):
        auth_client.post("/verify", data={
            "csrf_token": "valid-token",
            "message": f"ATTACK_PROBE_MESSAGE_{i}",
            "public_key": pub_pem,
            "signature": bad_signature,
        })

    with app.app_context():
        failures_count = VerificationRecord.query.filter_by(is_crypto_valid=False).count()
        assert failures_count >= 4

        # Verify burst event was generated
        burst_event = SecurityEvent.query.filter_by(event_type="BURST_ATTACK_DETECTED").first()
        assert burst_event is not None
        assert burst_event.severity == "CRITICAL"


def test_dashboard_stats_api(auth_client, app):
    """Verify that /api/dashboard/stats returns real aggregated DB statistics."""
    res = auth_client.get("/api/dashboard/stats")
    assert res.status_code == 200
    json_data = res.get_json()

    assert json_data["status"] == "success"
    data = json_data["data"]
    assert "summary" in data
    assert "weekly_trends" in data
    assert "severity_distribution" in data
    assert "score_distribution" in data


def test_demo_apis(auth_client):
    """Verify keygen, sign, tamper, and live evaluate APIs."""
    # 1. Keygen
    res_keys = auth_client.post("/api/demo/generate-keys", json={"key_size": 2048})
    assert res_keys.status_code == 200
    keys_data = res_keys.get_json()["data"]
    assert "-----BEGIN PUBLIC KEY-----" in keys_data["public_key"]

    # 2. Sign
    res_sign = auth_client.post("/api/demo/sign", json={
        "private_key": keys_data["private_key"],
        "message": "TEST_MESSAGE_PAYLOAD"
    })
    assert res_sign.status_code == 200
    sig_data = res_sign.get_json()["data"]
    assert "signature" in sig_data

    # 3. Tamper
    res_tamper = auth_client.post("/api/demo/tamper", json={
        "type": "message",
        "content": "HELLO_WORLD"
    })
    assert res_tamper.status_code == 200
    assert res_tamper.get_json()["data"]["tampered"] != "HELLO_WORLD"

    # 4. Evaluate simulator
    res_eval = auth_client.post("/api/analysis/evaluate", json={
        "is_crypto_valid": False,
        "recent_failures": 3,
        "velocity": 5.0,
        "key_size": 2048,
        "format_issues": 1
    })
    assert res_eval.status_code == 200
    eval_data = res_eval.get_json()["data"]
    assert "quantum" in eval_data
    assert "isolation_forest" in eval_data
    assert eval_data["quantum"]["threat_score"] > 30.0


def test_export_events_csv(auth_client):
    """Verify that /api/export/events generates downloadable CSV file."""
    res = auth_client.get("/api/export/events")
    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("text/csv")
    assert "attachment; filename=security_events_" in res.headers["Content-Disposition"]
    assert b"Timestamp (UTC)" in res.data
