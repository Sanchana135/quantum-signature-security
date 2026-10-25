import math
import pytest
from app.ml.quantum_engine import QuantumInspiredThreatEngine
from app.ml.anomaly_model import ClassicalAnomalyModel

def test_feature_normalization_bounds():
    """Verify that all extracted security features are strictly bounded in [0.0, 1.0]."""
    engine = QuantumInspiredThreatEngine()

    # Extreme edge cases
    features = engine.extract_features(
        is_crypto_valid=False,
        recent_failures_count=100,
        attempt_frequency_per_min=500.0,
        key_size=512,
        format_issues_count=10,
        is_tampered_flag=True
    )

    for k, v in features.items():
        assert 0.0 <= v <= 1.0, f"Feature {k} with value {v} outside [0.0, 1.0]"


def test_born_rule_probability_normalization():
    """Verify that Born rule amplitudes satisfy |alpha|^2 + |beta|^2 = 1.0."""
    engine = QuantumInspiredThreatEngine()

    test_scenarios = [
        {"crypto": True, "burst": 0, "vel": 1.0, "key": 2048, "fmt": 0},
        {"crypto": False, "burst": 1, "vel": 4.0, "key": 2048, "fmt": 0},
        {"crypto": False, "burst": 8, "vel": 30.0, "key": 1024, "fmt": 2},
    ]

    for sc in test_scenarios:
        eval_res = engine.evaluate(
            is_crypto_valid=sc["crypto"],
            recent_failures_count=sc["burst"],
            attempt_frequency_per_min=sc["vel"],
            key_size=sc["key"],
            format_issues_count=sc["fmt"]
        )

        amps = eval_res["amplitudes"]
        alpha = amps["alpha_nominal"]
        beta = amps["beta_threat"]
        total_prob = (alpha ** 2) + (beta ** 2)

        assert math.isclose(total_prob, 1.0, abs_tol=1e-3), f"Born rule violated: {total_prob} != 1.0"
        assert 0.0 <= eval_res["threat_score"] <= 100.0


def test_monotonic_risk_progression():
    """Verify that anomalous factors strictly escalate the threat score."""
    engine = QuantumInspiredThreatEngine()

    # 1. Nominal case
    res_nominal = engine.evaluate(is_crypto_valid=True, recent_failures_count=0, attempt_frequency_per_min=1.0)
    assert res_nominal["risk_level"] == "LOW"
    assert res_nominal["threat_score"] < 25.0

    # 2. Crypto failure only
    res_crypto_fail = engine.evaluate(is_crypto_valid=False, recent_failures_count=0, attempt_frequency_per_min=1.0)
    assert res_crypto_fail["threat_score"] > res_nominal["threat_score"]

    # 3. Crypto failure + severe failure burst
    res_burst = engine.evaluate(is_crypto_valid=False, recent_failures_count=6, attempt_frequency_per_min=25.0)
    assert res_burst["threat_score"] > res_crypto_fail["threat_score"]
    assert res_burst["risk_level"] in ("HIGH", "CRITICAL")


def test_isolation_forest_inference():
    """Verify that scikit-learn Isolation Forest runs inference cleanly."""
    model = ClassicalAnomalyModel()

    # Nominal features
    nom_features = {
        "crypto_failure": 0.0,
        "burst_failure_rate": 0.0,
        "velocity_anomaly": 0.05,
        "key_degradation": 0.0,
        "format_entropy_penalty": 0.0
    }
    nom_pred = model.predict_anomaly(nom_features)
    assert "ml_anomaly_score" in nom_pred
    assert nom_pred["isolation_forest_anomaly"] is False

    # Attack features
    attack_features = {
        "crypto_failure": 1.0,
        "burst_failure_rate": 0.9,
        "velocity_anomaly": 0.8,
        "key_degradation": 1.0,
        "format_entropy_penalty": 1.0
    }
    attack_pred = model.predict_anomaly(attack_features)
    assert attack_pred["ml_anomaly_score"] > nom_pred["ml_anomaly_score"]
