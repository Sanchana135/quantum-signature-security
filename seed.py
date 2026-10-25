"""
Database Seeding Script for Quantum-Inspired Cyber Threat Detection System.
Creates the demo analyst account and populates realistic historical telemetry.
"""

import json
from datetime import datetime, timezone, timedelta
from app import create_app
from app.models import db, User, VerificationRecord, SecurityEvent
from app.crypto.rsa_engine import generate_rsa_keypair, sign_message_rsa_pss
from app.ml.quantum_engine import QuantumInspiredThreatEngine

def seed_database():
    app = create_app("development")
    with app.app_context():
        # Ensure all tables exist
        db.create_all()
        print("[INFO] SQLite database schema verified.")

        # 1. Seed Demo Analyst Account
        demo_user = User.query.filter_by(username="demo_analyst").first()
        if not demo_user:
            demo_user = User(
                username="demo_analyst",
                email="analyst@quantum-shield.local",
                role="analyst",
                created_at=datetime.now(timezone.utc) - timedelta(days=14),
                last_login=datetime.now(timezone.utc) - timedelta(minutes=15),
            )
            demo_user.set_password("CyberSec#2026!")
            db.session.add(demo_user)
            db.session.commit()
            print("[INFO] Created demo account: 'demo_analyst' / 'CyberSec#2026!'")
        else:
            print("[INFO] Demo account 'demo_analyst' already exists.")

        # 2. Check if verification records already exist
        existing_records_count = VerificationRecord.query.count()
        if existing_records_count >= 10:
            print(f"[INFO] Database already contains {existing_records_count} verification records. Skipping telemetry seed.")
            return

        print("[INFO] Populating realistic historical verification telemetry and security events...")

        # Generate standard demo keys
        priv_pem, pub_pem = generate_rsa_keypair(key_size=2048)
        quantum_engine = QuantumInspiredThreatEngine()

        sample_cases = [
            # Nominal valid records
            {
                "msg": "TRANSACTION_CLEARING: ACCT_91823 -> ACCT_44120; VAL=$14,250.00; ROUTE=CHATS",
                "valid": True,
                "days_ago": 6,
                "burst": 0,
                "velocity": 1.2,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "192.168.1.105"
            },
            {
                "msg": "PAYROLL_BATCH_OCT_2026; EMP_COUNT=142; CHECKSUM=E58D82A9",
                "valid": True,
                "days_ago": 5,
                "burst": 0,
                "velocity": 0.8,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "192.168.1.110"
            },
            {
                "msg": "ACCESS_TOKEN_GRANT: CLIENT_ID=mobile_ios_app; SCOPE=read_telemetry; EXP=1792983200",
                "valid": True,
                "days_ago": 4,
                "burst": 0,
                "velocity": 2.1,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "10.0.4.88"
            },
            {
                "msg": "CONFIGURATION_POLICY_UPDATE: FIREWALL_RULE_SET_V4; STRICT_EGRESS=TRUE",
                "valid": True,
                "days_ago": 3,
                "burst": 0,
                "velocity": 1.0,
                "key_size": 3072,
                "fmt_issues": 0,
                "ip": "192.168.1.101"
            },
            {
                "msg": "AUDIT_DISPATCH: LOG_ARCHIVE_DIGEST; TIMESTAMP=2026-10-23T14:30:00Z",
                "valid": True,
                "days_ago": 2,
                "burst": 0,
                "velocity": 1.5,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "192.168.1.105"
            },
            {
                "msg": "SECURE_DEVICE_PROVISIONING: TPM_CHIP_ID=908412; ATTESTATION_VERIFIED",
                "valid": True,
                "days_ago": 1,
                "burst": 0,
                "velocity": 1.8,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "10.0.4.92"
            },
            {
                "msg": "SESSION_REVOCATION_BROADCAST: COMPROMISED_TOKEN_LIST_OCT25",
                "valid": True,
                "days_ago": 0,
                "burst": 0,
                "velocity": 2.4,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "192.168.1.101"
            },

            # Anomalous & Invalid records
            {
                "msg": "INVOICE_OVERRIDE_TAMPERED: ROUTING_NUMBER_ALTERED_BY_MITM_PROXY",
                "valid": False,
                "days_ago": 4,
                "burst": 2,
                "velocity": 4.5,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "203.0.113.45"
            },
            {
                "msg": "CREDENTIAL_EXPORT_PAYLOAD: EXFILTRATE_ALL_KEYS; FORCED_PRIVILEGE",
                "valid": False,
                "days_ago": 3,
                "burst": 5,
                "velocity": 18.0,
                "key_size": 1024,
                "fmt_issues": 1,
                "ip": "198.51.100.22"
            },
            {
                "msg": "CORRUPTED_ASN1_PAYLOAD: RANDOM_FUZZING_BYTE_STREAM",
                "valid": False,
                "days_ago": 2,
                "burst": 4,
                "velocity": 22.0,
                "key_size": None,
                "fmt_issues": 2,
                "ip": "198.51.100.22"
            },
            {
                "msg": "BANKING_WIRE_TRANSFER: TARGET=OFFSHORE_UNKNOWN; SUM=$1,200,000",
                "valid": False,
                "days_ago": 1,
                "burst": 1,
                "velocity": 3.0,
                "key_size": 2048,
                "fmt_issues": 0,
                "ip": "203.0.113.88"
            },
            {
                "msg": "BRUTE_FORCE_PROBE_SESSION: ATTEMPT_KEY_SUBSTITUTION_#412",
                "valid": False,
                "days_ago": 0,
                "burst": 6,
                "velocity": 34.0,
                "key_size": 1024,
                "fmt_issues": 1,
                "ip": "198.51.100.22"
            },
        ]

        for item in sample_cases:
            timestamp = datetime.now(timezone.utc) - timedelta(days=item["days_ago"], hours=item["burst"])
            
            # Evaluate quantum threat score
            q_eval = quantum_engine.evaluate(
                is_crypto_valid=item["valid"],
                recent_failures_count=item["burst"],
                attempt_frequency_per_min=item["velocity"],
                key_size=item["key_size"],
                format_issues_count=item["fmt_issues"]
            )

            # Generate signature preview
            try:
                sig_b64 = sign_message_rsa_pss(priv_pem, item["msg"])
            except Exception:
                sig_b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ..."

            import hashlib
            msg_hash = hashlib.sha256(item["msg"].encode("utf-8")).hexdigest()

            rec = VerificationRecord(
                user_id=demo_user.id,
                timestamp=timestamp,
                message_preview=item["msg"][:100],
                message_hash=msg_hash,
                signature_preview=sig_b64[:32] + "...",
                key_fingerprint="8f4b23a9d18e9c02b37492a83e01bc44fa5069a239b03ef8",
                key_size=item["key_size"] or 2048,
                algorithm="RSA-PSS-SHA256",
                is_crypto_valid=item["valid"],
                crypto_error=None if item["valid"] else "Cryptographic signature verification failed (InvalidSignature).",
                threat_score=q_eval["threat_score"],
                risk_level=q_eval["risk_level"],
                detection_reasons_json=json.dumps(q_eval["detection_reasons"]),
                feature_breakdown_json=json.dumps({
                    "features": q_eval["features"],
                    "amplitudes": q_eval["amplitudes"],
                    "amplitude_contributions": q_eval["amplitude_contributions"]
                }),
                ip_address=item["ip"],
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) QuantumTelemetryAgent/2.4",
            )
            db.session.add(rec)
            db.session.flush()

            # Create corresponding security event
            if item["valid"]:
                sec_ev = SecurityEvent(
                    user_id=demo_user.id,
                    verification_id=rec.id,
                    event_type="CRYPTO_VERIFY_SUCCESS",
                    severity="INFO",
                    title="Digital Signature Verified",
                    description=f"Valid RSA-PSS signature for digest {msg_hash[:16]}...",
                    timestamp=timestamp,
                    ip_address=item["ip"]
                )
                db.session.add(sec_ev)
            else:
                sev = "HIGH" if q_eval["threat_score"] >= 55.0 else "MEDIUM"
                if q_eval["threat_score"] >= 80.0:
                    sev = "CRITICAL"

                sec_ev = SecurityEvent(
                    user_id=demo_user.id,
                    verification_id=rec.id,
                    event_type="CRYPTO_VERIFY_FAILURE",
                    severity=sev,
                    title="Cryptographic Signature Failure",
                    description=f"Signature mismatch. Threat Score: {q_eval['threat_score']:.1f} ({q_eval['risk_level']}).",
                    timestamp=timestamp,
                    ip_address=item["ip"]
                )
                db.session.add(sec_ev)

                if item["burst"] >= 4:
                    burst_ev = SecurityEvent(
                        user_id=demo_user.id,
                        verification_id=rec.id,
                        event_type="BURST_ATTACK_DETECTED",
                        severity="CRITICAL",
                        title="Repeated Failure Burst Alert",
                        description=f"High frequency failure burst from IP {item['ip']} ({item['burst']} failures).",
                        timestamp=timestamp + timedelta(seconds=15),
                        ip_address=item["ip"]
                    )
                    db.session.add(burst_ev)

        db.session.commit()
        print(f"[INFO] Successfully seeded {len(sample_cases)} telemetry records and associated audit events.")

if __name__ == "__main__":
    seed_database()
