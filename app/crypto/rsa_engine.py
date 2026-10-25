import base64
import hashlib
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate an RSA key pair for demonstration purposes.
    Warning: In production, private keys must be stored in Hardware Security Modules (HSM)
    or encrypted secure keystores and never exposed via web applications.
    """
    if key_size not in (1024, 2048, 3072, 4096):
        key_size = 2048
        
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    
    return private_pem, public_pem


def sign_message_rsa_pss(private_key_pem: str, message: str | bytes) -> str:
    """
    Signs a message using RSA-PSS with SHA-256 and maximum salt length.
    Returns Base64-encoded signature.
    """
    if isinstance(message, str):
        msg_bytes = message.encode("utf-8")
    else:
        msg_bytes = message
        
    private_key = serialization.load_pem_private_key(
        private_key_pem.strip().encode("utf-8"),
        password=None,
    )
    
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Provided key is not an RSA private key.")
        
    signature = private_key.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    
    return base64.b64encode(signature).decode("utf-8")


def compute_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Computes SHA-256 fingerprint of SubjectPublicKeyInfo DER."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


def verify_signature_rsa_pss(
    public_key_pem: str,
    message: str | bytes,
    signature_b64: str
) -> Dict[str, Any]:
    """
    Deterministically verifies an RSA-PSS SHA-256 signature against the provided public key.
    
    Returns a comprehensive diagnostic dictionary separating cryptographic truth
    from threat heuristics.
    """
    if isinstance(message, str):
        msg_bytes = message.encode("utf-8")
        preview = message[:100] + ("..." if len(message) > 100 else "")
    else:
        msg_bytes = message
        try:
            preview = message[:100].decode("utf-8", errors="replace") + "..."
        except Exception:
            preview = f"<binary data: {len(message)} bytes>"

    message_hash = hashlib.sha256(msg_bytes).hexdigest()
    clean_sig = "".join(signature_b64.split())
    sig_preview = clean_sig[:32] + "..." if len(clean_sig) > 32 else clean_sig

    result: Dict[str, Any] = {
        "is_valid": False,
        "status_code": "PENDING",
        "error": None,
        "key_size": None,
        "key_fingerprint": "N/A",
        "algorithm": "RSA-PSS-SHA256",
        "message_hash": message_hash,
        "message_preview": preview,
        "signature_preview": sig_preview,
        "explanation": "",
        "format_issues": [],
    }

    # 1. Parse signature Base64
    try:
        sig_bytes = base64.b64decode(clean_sig, validate=True)
    except Exception as e:
        result["status_code"] = "MALFORMED_SIGNATURE"
        result["error"] = f"Base64 decoding failed: {str(e)}"
        result["explanation"] = "The signature is not a valid Base64-encoded byte sequence."
        result["format_issues"].append("Invalid Base64 signature encoding")
        return result

    # 2. Parse Public Key PEM
    try:
        clean_pem = public_key_pem.strip()
        if not ("BEGIN PUBLIC KEY" in clean_pem or "BEGIN RSA PUBLIC KEY" in clean_pem):
            result["status_code"] = "MALFORMED_KEY"
            result["error"] = "Invalid public key header. Expected PEM format with 'BEGIN PUBLIC KEY'."
            result["explanation"] = "The public key missing standard X.509/PKCS#1 PEM delimiters."
            result["format_issues"].append("Missing or invalid PEM header")
            return result

        public_key = serialization.load_pem_public_key(clean_pem.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey):
            result["status_code"] = "UNSUPPORTED_KEY_TYPE"
            result["error"] = f"Unsupported key type: {type(public_key).__name__}. Expected RSA key."
            result["explanation"] = "The supplied key is not an RSA key (e.g. ECDSA or Ed25519 provided)."
            result["format_issues"].append("Non-RSA key algorithm")
            return result

        result["key_size"] = public_key.key_size
        result["key_fingerprint"] = compute_key_fingerprint(public_key)

        if public_key.key_size < 2048:
            result["format_issues"].append(f"Sub-standard key length ({public_key.key_size}-bit < 2048-bit)")

    except Exception as e:
        result["status_code"] = "MALFORMED_KEY"
        result["error"] = f"Public key parsing error: {str(e)}"
        result["explanation"] = "Failed to deserialize the public key. Check PEM syntax and line breaks."
        result["format_issues"].append("Unparseable public key PEM")
        return result

    # 3. Perform Cryptographic Verification
    try:
        public_key.verify(
            sig_bytes,
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        result["is_valid"] = True
        result["status_code"] = "VALID"
        result["explanation"] = (
            "Cryptographic signature successfully verified using RSA-PSS SHA-256. "
            "The message payload matches the digest signed by the corresponding private key. "
            "Note: Public key validity verifies mathematical integrity; key authenticity depends on key trust origin."
        )
        return result

    except InvalidSignature:
        result["is_valid"] = False
        result["status_code"] = "INVALID_SIGNATURE"
        result["error"] = "Cryptographic signature verification failed (InvalidSignature)."
        result["explanation"] = (
            "The signature does not match the message digest or was signed by a different private key. "
            "The message may have been altered in transit, or the signature or key was modified."
        )
        return result
    except Exception as e:
        result["is_valid"] = False
        result["status_code"] = "VERIFICATION_ERROR"
        result["error"] = f"Verification execution error: {str(e)}"
        result["explanation"] = f"An unexpected cryptographic runtime error occurred: {str(e)}"
        return result


def tamper_message(message: str) -> str:
    """Simulate a single-byte tamper in the message payload."""
    if not message:
        return "[TAMPERED_INJECTED_DATA]"
    # Alter the last character
    last_char = message[-1]
    replacement = "!" if last_char != "!" else "?"
    return message[:-1] + replacement


def tamper_signature(signature_b64: str) -> str:
    """Simulate a corrupted signature by bit-flipping characters."""
    if len(signature_b64) < 10:
        return "AAAA" + signature_b64
    chars = list(signature_b64)
    # Mutate middle character
    mid = len(chars) // 2
    chars[mid] = "X" if chars[mid] != "X" else "Y"
    return "".join(chars)
