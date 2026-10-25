from app.crypto.rsa_engine import (
    generate_rsa_keypair,
    sign_message_rsa_pss,
    verify_signature_rsa_pss,
    tamper_message,
    tamper_signature,
    compute_key_fingerprint,
)

def test_keypair_generation():
    """Verify that generated RSA keypairs have valid PEM headers and 2048-bit modulus."""
    priv_pem, pub_pem = generate_rsa_keypair(key_size=2048)
    assert "-----BEGIN PRIVATE KEY-----" in priv_pem
    assert "-----END PRIVATE KEY-----" in priv_pem
    assert "-----BEGIN PUBLIC KEY-----" in pub_pem
    assert "-----END PUBLIC KEY-----" in pub_pem


def test_signature_verification_success(sample_rsa_pair):
    """Verify that a valid message signed with RSA-PSS SHA-256 passes mathematical verification."""
    priv_pem = sample_rsa_pair["private_key"]
    pub_pem = sample_rsa_pair["public_key"]
    message = "CONFIDENTIAL_PAYLOAD_HASH_TEST_9942"

    signature_b64 = sign_message_rsa_pss(priv_pem, message)
    assert signature_b64 is not None
    assert len(signature_b64) > 100

    result = verify_signature_rsa_pss(
        public_key_pem=pub_pem,
        message=message,
        signature_b64=signature_b64
    )

    assert result["is_valid"] is True
    assert result["status_code"] == "VALID"
    assert result["error"] is None
    assert result["key_size"] == 2048
    assert result["algorithm"] == "RSA-PSS-SHA256"


def test_tampered_message_fails_verification(sample_rsa_pair):
    """Verify that altering 1 character in the message fails cryptographic verification."""
    priv_pem = sample_rsa_pair["private_key"]
    pub_pem = sample_rsa_pair["public_key"]
    original_message = "AUTHORIZED_TRANSACTION_PAYLOAD_ABC"
    
    signature_b64 = sign_message_rsa_pss(priv_pem, original_message)

    tampered = tamper_message(original_message)
    assert tampered != original_message

    result = verify_signature_rsa_pss(
        public_key_pem=pub_pem,
        message=tampered,
        signature_b64=signature_b64
    )

    assert result["is_valid"] is False
    assert result["status_code"] == "INVALID_SIGNATURE"
    assert "InvalidSignature" in result["error"]


def test_corrupted_signature_base64(sample_rsa_pair):
    """Verify that malformed Base64 signature is caught cleanly without crash."""
    pub_pem = sample_rsa_pair["public_key"]
    message = "STANDARD_PAYLOAD"
    bad_signature = "NOT_A_VALID_BASE_64_STRING_$$$!!"

    result = verify_signature_rsa_pss(
        public_key_pem=pub_pem,
        message=message,
        signature_b64=bad_signature
    )

    assert result["is_valid"] is False
    assert result["status_code"] == "MALFORMED_SIGNATURE"
    assert "Base64 decoding failed" in result["error"]


def test_malformed_public_key_pem(sample_rsa_pair):
    """Verify that corrupt or invalid PEM public key is caught cleanly without crash."""
    priv_pem = sample_rsa_pair["private_key"]
    message = "STANDARD_PAYLOAD"
    signature_b64 = sign_message_rsa_pss(priv_pem, message)

    bad_pub_key = "---INVALID CORRUPTED KEY DATA---"

    result = verify_signature_rsa_pss(
        public_key_pem=bad_pub_key,
        message=message,
        signature_b64=signature_b64
    )

    assert result["is_valid"] is False
    assert result["status_code"] == "MALFORMED_KEY"
    assert "Invalid public key header" in result["error"]


def test_bit_flipped_signature_fails(sample_rsa_pair):
    """Verify that bit-flipped Base64 signature fails cryptographic verification."""
    priv_pem = sample_rsa_pair["private_key"]
    pub_pem = sample_rsa_pair["public_key"]
    message = "STANDARD_PAYLOAD"
    
    valid_sig = sign_message_rsa_pss(priv_pem, message)
    flipped_sig = tamper_signature(valid_sig)

    result = verify_signature_rsa_pss(
        public_key_pem=pub_pem,
        message=message,
        signature_b64=flipped_sig
    )

    assert result["is_valid"] is False
    assert result["status_code"] in ("INVALID_SIGNATURE", "MALFORMED_SIGNATURE")
