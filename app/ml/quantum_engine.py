import math
import numpy as np
from typing import Dict, Any, List, Tuple

# Domain feature weights (must sum to 1.0)
FEATURE_WEIGHTS = {
    "crypto_failure": 0.40,        # Pure cryptographic verification failure
    "burst_failure_rate": 0.25,    # Rapid repeated failures in time window
    "velocity_anomaly": 0.15,      # High request frequency anomaly
    "key_degradation": 0.10,       # Weak/sub-standard key length or non-standard format
    "format_entropy_penalty": 0.10 # Encoding, entropy, or padding irregularities
}

class QuantumInspiredThreatEngine:
    """
    Quantum-Inspired Classical Threat Detection Module for Digital Signature Security.
    
    Theoretical Formulation:
    ------------------------
    Rather than claiming quantum hardware execution, this algorithm maps multi-dimensional
    cybersecurity event telemetry into quantum-inspired probability amplitude space.
    
    1. Feature Normalization:
       Each security indicator x_j is bounded in [0, 1].
       
    2. Phase Angle Mapping:
       theta_j = x_j * (pi / 2), where theta_j in [0, pi/2].
       When x_j = 0 (nominal), theta_j = 0 -> sin(theta_j) = 0.
       When x_j = 1 (critical threat), theta_j = pi/2 -> sin(theta_j) = 1.
       
    3. Quantum Superposition State Vector:
       |psi> = alpha |0> + beta |1>
       where |0> denotes Nominal Security State, and |1> denotes Cyber Threat State.
       
       By the Born Rule: |alpha|^2 + |beta|^2 = 1.
       We define the threat amplitude beta as:
       beta = sqrt( sum_{j=1}^n w_j * sin^2(theta_j) )
       alpha = sqrt( 1 - beta^2 )
       
    4. Threat Probability & Classical Score:
       P(Threat) = |beta|^2 = sum_{j=1}^n w_j * sin^2(x_j * pi / 2)
       Threat Score = 100.0 * P(Threat) in [0, 100].
       
    5. Explainability (XAI):
       Each feature's amplitude contribution Delta S_j = 100 * w_j * sin^2(theta_j)
       allows rigorous forensic explanation of which factors drove the threat assessment.
    """

    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or FEATURE_WEIGHTS.copy()
        # Ensure weights sum to 1.0
        total_w = sum(self.weights.values())
        if not math.isclose(total_w, 1.0, rel_tol=1e-4):
            self.weights = {k: v / total_w for k, v in self.weights.items()}

    def extract_features(
        self,
        is_crypto_valid: bool,
        recent_failures_count: int,
        attempt_frequency_per_min: float,
        key_size: int | None,
        format_issues_count: int,
        is_tampered_flag: bool = False
    ) -> Dict[str, float]:
        """
        Normalizes raw telemetry into [0, 1] bounded feature inputs.
        """
        # 1. Cryptographic failure: 1.0 if invalid, 0.0 if mathematically valid
        crypto_val = 0.0 if is_crypto_valid else 1.0
        if is_tampered_flag:
            crypto_val = 1.0

        # 2. Burst failure rate: 0 to 5+ failures mapped asymptotically using tanh
        burst_val = float(np.tanh(recent_failures_count / 2.5))

        # 3. Request velocity: normal <= 5/min (0.0), extreme >= 30/min (1.0)
        velocity_val = float(np.clip((attempt_frequency_per_min - 2.0) / 28.0, 0.0, 1.0))

        # 4. Key degradation: >= 2048 bit is standard (0.0), 1024 bit is weak (0.6), <1024 or None is critical (1.0)
        if key_size is None or key_size < 1024:
            key_val = 1.0
        elif key_size < 2048:
            key_val = 0.6
        elif key_size == 2048:
            key_val = 0.0
        else: # 3072 or 4096-bit
            key_val = 0.0

        # 5. Format & Entropy issues: 0 issues = 0.0, 1 issue = 0.5, >=2 issues = 1.0
        format_val = float(np.clip(format_issues_count * 0.5, 0.0, 1.0))

        return {
            "crypto_failure": crypto_val,
            "burst_failure_rate": burst_val,
            "velocity_anomaly": velocity_val,
            "key_degradation": key_val,
            "format_entropy_penalty": format_val,
        }

    def evaluate(
        self,
        is_crypto_valid: bool,
        recent_failures_count: int = 0,
        attempt_frequency_per_min: float = 1.0,
        key_size: int | None = 2048,
        format_issues_count: int = 0,
        is_tampered_flag: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates the quantum-inspired threat score, amplitudes, and explainability vectors.
        """
        features = self.extract_features(
            is_crypto_valid=is_crypto_valid,
            recent_failures_count=recent_failures_count,
            attempt_frequency_per_min=attempt_frequency_per_min,
            key_size=key_size,
            format_issues_count=format_issues_count,
            is_tampered_flag=is_tampered_flag
        )

        phase_angles: Dict[str, float] = {}
        amplitude_contributions: Dict[str, float] = {}
        reasons: List[str] = []
        recommendations: List[str] = []

        total_threat_probability = 0.0

        for feat_name, x_val in features.items():
            w = self.weights[feat_name]
            # Phase angle theta in [0, pi/2]
            theta = float(x_val * (np.pi / 2.0))
            phase_angles[feat_name] = round(theta, 4)

            # Amplitude squared contribution
            contrib = float(w * (np.sin(theta) ** 2))
            amplitude_contributions[feat_name] = round(contrib * 100.0, 2)
            total_threat_probability += contrib

            # Qualitative explainability detection reasons
            if feat_name == "crypto_failure" and x_val > 0.5:
                reasons.append("Cryptographic signature mathematical mismatch detected (Invalid Signature).")
                recommendations.append("Investigate potential payload tampering or private key desynchronization.")
            elif feat_name == "burst_failure_rate" and x_val > 0.4:
                reasons.append(f"High-frequency failed verification burst detected ({recent_failures_count} failures in window).")
                recommendations.append("Apply IP rate-limiting and check for brute-force signature forgery probes.")
            elif feat_name == "velocity_anomaly" and x_val > 0.3:
                reasons.append(f"Elevated verification velocity ({attempt_frequency_per_min:.1f} req/min).")
                recommendations.append("Inspect origin IP and enforce client token verification.")
            elif feat_name == "key_degradation" and x_val > 0.3:
                reasons.append(f"Sub-standard RSA key size detected ({key_size if key_size else 'Unknown'}-bit). Minimum recommendation: 2048-bit.")
                recommendations.append("Rotate key pair immediately to at least 2048-bit or 3072-bit RSA.")
            elif feat_name == "format_entropy_penalty" and x_val > 0.3:
                reasons.append("Irregular Base64 formatting or PEM header anomalies detected.")
                recommendations.append("Audit client encoding implementation and transmission pipeline integrity.")

        # Threat amplitude beta, nominal amplitude alpha
        beta = float(np.sqrt(np.clip(total_threat_probability, 0.0, 1.0)))
        alpha = float(np.sqrt(np.clip(1.0 - (beta ** 2), 0.0, 1.0)))

        threat_score = round(total_threat_probability * 100.0, 2)

        # Categorize risk severity
        if threat_score <= 25.0:
            risk_level = "LOW"
            if not reasons:
                reasons.append("Normal cryptographic operations within baseline tolerances.")
            recommendations.append("Continue regular telemetry monitoring; no immediate defensive action required.")
        elif threat_score <= 55.0:
            risk_level = "MEDIUM"
            recommendations.append("Review originating client history and monitor next verification attempts.")
        elif threat_score <= 80.0:
            risk_level = "HIGH"
            recommendations.append("Elevate logging verbosity, quarantine suspicious transactions, and review certificate provenance.")
        else:
            risk_level = "CRITICAL"
            recommendations.append("Trigger automated SOC alert, temporarily isolate endpoint, and conduct forensic payload audit.")

        # Crucial clarification disclosure
        academic_disclaimer = (
            "Classical quantum-inspired amplitude projection algorithm. "
            "Computations are executed on classical hardware using bounded phase-angle mappings and Born rule probabilities. "
            "Threat prediction is an operational risk metric and not cryptographic proof of forgery."
        )

        return {
            "threat_score": threat_score,
            "risk_level": risk_level,
            "amplitudes": {
                "alpha_nominal": round(alpha, 4),
                "beta_threat": round(beta, 4),
                "probability_nominal": round(alpha ** 2, 4),
                "probability_threat": round(beta ** 2, 4),
            },
            "features": {k: round(v, 4) for k, v in features.items()},
            "phase_angles": phase_angles,
            "amplitude_contributions": amplitude_contributions,
            "detection_reasons": reasons,
            "recommendations": recommendations,
            "disclaimer": academic_disclaimer,
        }
