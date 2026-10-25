import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List

class ClassicalAnomalyModel:
    """
    Classical Machine Learning Anomaly Detector using scikit-learn Isolation Forest.
    Trained reproducibly on synthetic baseline signature verification telemetry
    to provide comparative benchmarking against the quantum-inspired engine.
    
    Academic Disclosure:
    --------------------
    This Isolation Forest is trained on synthetic demonstration telemetry representing
    standard digital signature verification vs. simulated attack patterns (brute force,
    bit-flipping, high velocity). In production, this model should be continuously retrained
    on audited historical enterprise telemetry.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=self.random_state,
        )
        self._fit_synthetic_baseline()

    def _fit_synthetic_baseline(self):
        """Fit model with reproducible synthetic telemetry."""
        np.random.seed(self.random_state)
        
        # Nominal signature telemetry (approx 850 samples)
        # Features: [crypto_fail (0), burst_fails (0-1), velocity (1-5), key_degradation (0), format_issues (0)]
        nominal_count = 850
        n_crypto = np.zeros(nominal_count)
        n_burst = np.random.exponential(scale=0.2, size=nominal_count).clip(0, 1.0)
        n_velocity = np.random.normal(loc=0.1, scale=0.08, size=nominal_count).clip(0, 1.0)
        n_key = np.zeros(nominal_count)
        n_format = np.zeros(nominal_count)
        nominal_data = np.column_stack([n_crypto, n_burst, n_velocity, n_key, n_format])

        # Attack / Anomalous telemetry (approx 150 samples)
        anomaly_count = 150
        a_crypto = np.random.choice([0.0, 1.0], size=anomaly_count, p=[0.2, 0.8])
        a_burst = np.random.uniform(0.4, 1.0, size=anomaly_count)
        a_velocity = np.random.uniform(0.3, 1.0, size=anomaly_count)
        a_key = np.random.choice([0.0, 0.6, 1.0], size=anomaly_count, p=[0.3, 0.4, 0.3])
        a_format = np.random.choice([0.0, 0.5, 1.0], size=anomaly_count, p=[0.2, 0.4, 0.4])
        anomaly_data = np.column_stack([a_crypto, a_burst, a_velocity, a_key, a_format])

        X_train = np.vstack([nominal_data, anomaly_data])
        self.model.fit(X_train)

    def predict_anomaly(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Runs inference on normalized feature dictionary.
        Returns Isolation Forest score and decision.
        """
        feature_vector = np.array([[
            feature_dict.get("crypto_failure", 0.0),
            feature_dict.get("burst_failure_rate", 0.0),
            feature_dict.get("velocity_anomaly", 0.0),
            feature_dict.get("key_degradation", 0.0),
            feature_dict.get("format_entropy_penalty", 0.0),
        ]])

        raw_score = float(self.model.decision_function(feature_vector)[0])
        # decision_function gives negative score for outliers, positive for inliers
        # Map to an intuitive 0-100 anomaly scale
        # Typically raw_score ranges from -0.3 to +0.3
        mapped_anomaly_score = float(np.clip((0.2 - raw_score) / 0.4 * 100.0, 0.0, 100.0))
        is_anomaly = bool(self.model.predict(feature_vector)[0] == -1)

        return {
            "isolation_forest_anomaly": is_anomaly,
            "raw_decision_score": round(raw_score, 4),
            "ml_anomaly_score": round(mapped_anomaly_score, 2),
            "model_type": "Isolation Forest (scikit-learn)",
            "disclaimer": "Trained on synthetic demonstration telemetry with 15% synthetic contamination."
        }
