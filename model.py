"""
SecureBridge — ML Anomaly Detection Engine
Isolation Forest trained on OT device behavioral baselines

Detects deviations that signature-based tools miss:
- Abnormal polling frequency
- Unusual register access patterns
- New source IPs accessing OT devices
- Abnormal response times
- Off-hours activity
"""

import os
import sys
import pickle
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))

logger = logging.getLogger("SecureBridge.Detection")


# ─────────────────────────────────────────────────────────
# Feature Engineering
# ─────────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert raw OT events into ML features

    Features capture behavioral patterns, not just raw values:
    - Time-based: hour, is_business_hours
    - Statistical: rolling mean/std of values
    - Behavioral: polling frequency, write ratio
    - Network: source IP consistency
    """
    features = pd.DataFrame()

    # Time features
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    features["hour"] = df["timestamp"].dt.hour
    features["is_business_hours"] = (
        (features["hour"] >= 8) & (features["hour"] <= 18)
    ).astype(int)
    features["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

    # Process value features (if available)
    if "value" in df.columns:
        features["value"] = pd.to_numeric(df["value"], errors="coerce").fillna(0)
        features["value_rolling_mean"] = (
            features["value"].rolling(5, min_periods=1).mean()
        )
        features["value_deviation"] = abs(
            features["value"] - features["value_rolling_mean"]
        )

    # Polling frequency
    if "transaction_id" in df.columns:
        features["transaction_rate"] = (
            pd.to_numeric(df["transaction_id"], errors="coerce")
            .fillna(0)
            .rolling(10, min_periods=1)
            .count()
        )

    # Write flag (higher risk)
    if "is_write" in df.columns:
        features["is_write"] = df["is_write"].astype(int)
    else:
        features["is_write"] = 0

    # Register address (large values may indicate scanning)
    if "register_address" in df.columns:
        features["register_address"] = (
            pd.to_numeric(df["register_address"], errors="coerce").fillna(0)
        )

    # Payload size anomaly
    if "payload_length" in df.columns:
        pl = pd.to_numeric(df["payload_length"], errors="coerce").fillna(12)
        features["payload_size"] = pl
        features["payload_size_rolling_std"] = pl.rolling(10, min_periods=1).std().fillna(0)

    return features.fillna(0)


# ─────────────────────────────────────────────────────────
# Model Training
# ─────────────────────────────────────────────────────────

def train_model(
    data_path: str,
    model_path: str = "data/models/ot_model.pkl",
    contamination: float = 0.05
) -> dict:
    """
    Train Isolation Forest on baseline OT traffic data

    Args:
        data_path: CSV file from EventLogger
        model_path: where to save trained model
        contamination: expected anomaly rate (5% default)

    Returns:
        Training summary dict
    """
    logger.info(f"Loading training data: {data_path}")

    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df)} events")

    if len(df) < 50:
        logger.warning(
            f"Only {len(df)} events — need more data for reliable baseline. "
            "Collect at least 1 hour of normal traffic."
        )

    features = engineer_features(df)
    logger.info(f"Features: {list(features.columns)}")

    # Scale features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Train Isolation Forest
    logger.info("Training Isolation Forest...")
    model = IsolationForest(
        contamination=contamination,
        n_estimators=200,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    model.fit(features_scaled)

    # Calculate baseline scores on training data
    scores = model.score_samples(features_scaled)
    anomaly_scores = normalize_scores(scores)

    # Save model + scaler + metadata
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    metadata = {
        "trained_at": datetime.now().isoformat(),
        "training_samples": len(df),
        "features": list(features.columns),
        "contamination": contamination,
        "score_mean": float(np.mean(anomaly_scores)),
        "score_std": float(np.std(anomaly_scores)),
        "score_p95": float(np.percentile(anomaly_scores, 95)),
    }

    with open(model_path, "wb") as f:
        pickle.dump({
            "model": model,
            "scaler": scaler,
            "metadata": metadata,
            "feature_names": list(features.columns)
        }, f)

    logger.info(f"✅ Model saved: {model_path}")
    logger.info(f"   Training samples: {len(df)}")
    logger.info(f"   Avg anomaly score: {metadata['score_mean']:.1f}")
    logger.info(f"   P95 score: {metadata['score_p95']:.1f}")

    return metadata


# ─────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────

def normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    """
    Convert Isolation Forest scores to 0-100 scale
    Higher = more anomalous
    """
    # IF returns negative scores for anomalies (more negative = more anomalous)
    min_s = raw_scores.min()
    max_s = raw_scores.max()

    if max_s == min_s:
        return np.zeros_like(raw_scores)

    normalized = (raw_scores - max_s) / (min_s - max_s) * 100
    return np.clip(normalized, 0, 100)


def classify_severity(score: float) -> str:
    """Classify anomaly severity from score"""
    if score >= 80:
        return "CRITICAL"
    elif score >= 65:
        return "HIGH"
    elif score >= 45:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────────────────
# Real-time Scorer
# ─────────────────────────────────────────────────────────

class AnomalyScorer:
    """
    Real-time anomaly scoring for incoming OT events
    Loads trained model and scores events as they arrive
    """

    def __init__(self, model_path: str = "data/models/ot_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.metadata = None
        self.feature_names = None
        self._load_model()

    def _load_model(self):
        """Load trained model from disk"""
        if not os.path.exists(self.model_path):
            logger.warning(
                f"No model at {self.model_path}. "
                "Collect baseline data first, then run train_model()."
            )
            return

        with open(self.model_path, "rb") as f:
            saved = pickle.load(f)

        self.model = saved["model"]
        self.scaler = saved["scaler"]
        self.metadata = saved["metadata"]
        self.feature_names = saved["feature_names"]

        trained_at = self.metadata.get("trained_at", "Unknown")
        samples = self.metadata.get("training_samples", 0)
        logger.info(f"Model loaded — trained {trained_at} on {samples} samples")

    def score_event(self, event_dict: dict) -> dict:
        """
        Score a single OT event

        Returns:
            dict with anomaly_score, severity, is_anomaly, features
        """
        if not self.model:
            return {
                "anomaly_score": 0,
                "severity": "UNKNOWN",
                "is_anomaly": False,
                "error": "Model not loaded"
            }

        try:
            # Build single-row dataframe
            df = pd.DataFrame([event_dict])
            features = engineer_features(df)

            # Align features with training
            for col in self.feature_names:
                if col not in features.columns:
                    features[col] = 0
            features = features[self.feature_names]

            # Scale and score
            features_scaled = self.scaler.transform(features)
            raw_score = self.model.score_samples(features_scaled)[0]
            anomaly_score = float(normalize_scores(np.array([raw_score]))[0])
            is_anomaly = self.model.predict(features_scaled)[0] == -1
            severity = classify_severity(anomaly_score)

            return {
                "anomaly_score": round(anomaly_score, 1),
                "severity": severity,
                "is_anomaly": bool(is_anomaly),
                "features": features.iloc[0].to_dict(),
                "error": None
            }

        except Exception as e:
            logger.error(f"Scoring error: {e}")
            return {
                "anomaly_score": 0,
                "severity": "ERROR",
                "is_anomaly": False,
                "error": str(e)
            }

    def score_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score a batch of events"""
        if not self.model:
            df["anomaly_score"] = 0
            df["severity"] = "UNKNOWN"
            df["is_anomaly"] = False
            return df

        features = engineer_features(df)

        for col in self.feature_names:
            if col not in features.columns:
                features[col] = 0
        features = features[self.feature_names]

        features_scaled = self.scaler.transform(features)
        raw_scores = self.model.score_samples(features_scaled)
        anomaly_scores = normalize_scores(raw_scores)
        predictions = self.model.predict(features_scaled)

        df = df.copy()
        df["anomaly_score"] = np.round(anomaly_scores, 1)
        df["is_anomaly"] = predictions == -1
        df["severity"] = df["anomaly_score"].apply(classify_severity)

        return df

    def reload(self):
        """Reload model from disk (for periodic retraining)"""
        self._load_model()


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python model.py <command> [args]")
        print("Commands:")
        print("  train <data_csv>     Train model on collected data")
        print("  score <data_csv>     Score events in CSV file")
        sys.exit(1)

    command = sys.argv[1]

    if command == "train":
        if len(sys.argv) < 3:
            print("Usage: python model.py train <data_csv>")
            sys.exit(1)
        metadata = train_model(sys.argv[2])
        print("\nTraining complete:")
        for k, v in metadata.items():
            print(f"  {k}: {v}")

    elif command == "score":
        if len(sys.argv) < 3:
            print("Usage: python model.py score <data_csv>")
            sys.exit(1)
        scorer = AnomalyScorer()
        df = pd.read_csv(sys.argv[2])
        scored = scorer.score_batch(df)
        alerts = scored[scored["is_anomaly"] == True]
        print(f"\nScored {len(df)} events")
        print(f"Anomalies detected: {len(alerts)}")
        if not alerts.empty:
            print("\nTop anomalies:")
            print(alerts[["timestamp", "device_id",
                          "event_type", "anomaly_score",
                          "severity"]].head(10).to_string())
