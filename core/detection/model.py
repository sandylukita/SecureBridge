"""
SecureBridge — ML Anomaly Detection Engine
Isolation Forest trained on OT device behavioral baselines

Detects deviations that signature-based tools miss:
- Abnormal polling frequency / packet delta time bursts
- Unusual register access patterns
- New source IPs accessing OT devices
- High-risk function codes (Write, Discovery)
- Off-hours activity

Feature Engineering v2 — additions over v1:
  * function_code_risk_score  : weighted risk per Modbus FC
  * packet_delta_time         : inter-packet gap (seconds)
  * delta_time_rolling_std    : burst detection via std of gaps
  * is_unknown_src_ip         : IP not seen during training baseline
  * src_ip_hash               : numeric encoding for batch training

Bugfix v2:
  * AnomalyScorer.score_event() now maintains a sliding EventWindow
    so rolling features (mean, std, delta_time) are computed on real
    context, not a meaningless single-row DataFrame.
"""

import os
import sys
import pickle
import logging
import numpy as np
import pandas as pd
from collections import deque
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))

logger = logging.getLogger("SecureBridge.Detection")


# ─────────────────────────────────────────────────────────
# Modbus Function Code Risk Weights
# ─────────────────────────────────────────────────────────

# Weighted 0-10 scale:
#   0-2  = normal read operations
#   3-5  = unusual but may be legitimate
#   6-8  = elevated risk (writes, force)
#   9-10 = critical (recon / broadcast write)
FC_RISK_WEIGHTS = {
    1:  2,   # Read Coils              — normal
    2:  2,   # Read Discrete Inputs    — normal
    3:  1,   # Read Holding Registers  — most common / lowest risk
    4:  1,   # Read Input Registers    — normal
    5:  7,   # Write Single Coil       — elevated
    6:  8,   # Write Single Register   — elevated
    15: 8,   # Write Multiple Coils    — high risk
    16: 9,   # Write Multiple Registers — high risk
    43: 10,  # Read Device ID          — recon signature
}
FC_RISK_DEFAULT = 5   # Unknown function codes are suspicious


# ─────────────────────────────────────────────────────────
# Feature Engineering
# ─────────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame, known_src_ips: set = None) -> pd.DataFrame:
    """
    Convert raw OT events into ML features.

    Parameters
    ----------
    df : pd.DataFrame
        Raw events — can be a full CSV batch or a sliding window
        of recent events for real-time scoring.
    known_src_ips : set, optional
        Set of src_ip addresses seen during training baseline.
        If provided, enables the is_unknown_src_ip feature.
        Pass None during training (feature will be 0).

    Features
    --------
    Time-based:
        hour, is_business_hours, is_weekend

    Value-based:
        value, value_rolling_mean, value_deviation

    Network timing (NEW v2):
        packet_delta_time       — seconds since previous packet
        delta_time_rolling_mean — rolling mean of gaps (5-packet window)
        delta_time_rolling_std  — burst detection via std of gaps

    Function code risk (NEW v2):
        function_code_risk      — weighted risk score 0-10 per FC

    Protocol behavior:
        is_write                — binary write flag
        register_address        — may indicate scanning if sequential
        payload_size, payload_size_rolling_std

    Transaction rate:
        transaction_rate        — rolling count (proxy for polling freq)

    Source IP (NEW v2):
        src_ip_hash             — numeric hash of src_ip for IF
        is_unknown_src_ip       — 1 if IP not in training baseline
    """
    features = pd.DataFrame()

    # ── Time features ───────────────────────────────────────
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.now())

    features["hour"] = df["timestamp"].dt.hour
    features["is_business_hours"] = (
        (features["hour"] >= 8) & (features["hour"] <= 18)
    ).astype(int)
    features["is_weekend"] = df["timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

    # ── Packet delta time (NEW v2) ───────────────────────────
    # dt.total_seconds() gives inter-packet gap; first row = 0
    delta = df["timestamp"].diff().dt.total_seconds().fillna(0)
    features["packet_delta_time"] = delta.clip(lower=0)
    features["delta_time_rolling_mean"] = (
        features["packet_delta_time"].rolling(5, min_periods=1).mean()
    )
    features["delta_time_rolling_std"] = (
        features["packet_delta_time"].rolling(5, min_periods=1).std().fillna(0)
    )
    # Burst flag: delta < 0.1s (sub-100ms = scanning / DDoS pattern)
    features["is_burst"] = (
        (features["packet_delta_time"] < 0.1) &
        (features["packet_delta_time"] > 0)
    ).astype(int)

    # ── Value features ───────────────────────────────────────
    if "value" in df.columns:
        features["value"] = pd.to_numeric(df["value"], errors="coerce").fillna(0)
        features["value_rolling_mean"] = (
            features["value"].rolling(5, min_periods=1).mean()
        )
        features["value_deviation"] = abs(
            features["value"] - features["value_rolling_mean"]
        )

    # ── Function code risk score (NEW v2) ───────────────────
    if "function_code" in df.columns:
        fc = pd.to_numeric(df["function_code"], errors="coerce").fillna(0).astype(int)
        features["function_code_risk"] = fc.map(
            lambda x: FC_RISK_WEIGHTS.get(x, FC_RISK_DEFAULT)
        )
    else:
        features["function_code_risk"] = 0

    # ── Write flag ───────────────────────────────────────────
    if "is_write" in df.columns:
        features["is_write"] = df["is_write"].astype(int)
    else:
        features["is_write"] = 0

    # ── Register address ─────────────────────────────────────
    if "register_address" in df.columns:
        features["register_address"] = (
            pd.to_numeric(df["register_address"], errors="coerce").fillna(0)
        )
        # Sequential register access = scanning signature
        features["register_addr_delta"] = (
            features["register_address"].diff().abs().fillna(0)
        )

    # ── Payload size ─────────────────────────────────────────
    if "payload_length" in df.columns:
        pl = pd.to_numeric(df["payload_length"], errors="coerce").fillna(12)
        features["payload_size"] = pl
        features["payload_size_rolling_std"] = (
            pl.rolling(10, min_periods=1).std().fillna(0)
        )

    # ── Transaction rate ─────────────────────────────────────
    if "transaction_id" in df.columns:
        features["transaction_rate"] = (
            pd.to_numeric(df["transaction_id"], errors="coerce")
            .fillna(0)
            .rolling(10, min_periods=1)
            .count()
        )

    # ── Source IP features (NEW v2) ──────────────────────────
    if "src_ip" in df.columns:
        # Numeric hash — lets IF learn normal source patterns
        features["src_ip_hash"] = df["src_ip"].apply(
            lambda ip: abs(hash(str(ip))) % 100000
        ).astype(float)

        # Unknown IP flag — only meaningful when known_src_ips is provided
        if known_src_ips:
            features["is_unknown_src_ip"] = (
                ~df["src_ip"].isin(known_src_ips)
            ).astype(int)
        else:
            features["is_unknown_src_ip"] = 0
    else:
        features["src_ip_hash"] = 0
        features["is_unknown_src_ip"] = 0

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
    Train Isolation Forest on baseline OT traffic data.

    Args:
        data_path    : CSV file from EventLogger
        model_path   : where to save trained model artifact
        contamination: expected anomaly rate (5% default)

    Returns:
        Training summary dict (also saved in model metadata)

    v2 additions:
        - Saves known_src_ips set in metadata for runtime IP anomaly detection
        - Trains on expanded feature set (delta_time, fc_risk, src_ip_hash)
    """
    logger.info(f"Loading training data: {data_path}")
    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df)} events")

    if len(df) < 50:
        logger.warning(
            f"Only {len(df)} events — need more data for reliable baseline. "
            "Collect at least 1 hour of normal traffic."
        )

    # Extract baseline src_ips before feature engineering
    known_src_ips = set(df["src_ip"].dropna().unique()) if "src_ip" in df.columns else set()
    logger.info(f"Baseline source IPs: {known_src_ips}")

    # Engineer features (pass None for known_src_ips — all training IPs are "known")
    features = engineer_features(df, known_src_ips=None)
    logger.info(f"Features ({len(features.columns)}): {list(features.columns)}")

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

    # ── Save model + scaler + metadata ───────────────────────
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    metadata = {
        "trained_at":       datetime.now().isoformat(),
        "training_samples": len(df),
        "features":         list(features.columns),
        "feature_count":    len(features.columns),
        "contamination":    contamination,
        "known_src_ips":    list(known_src_ips),          # NEW v2
        "score_mean":       float(np.mean(anomaly_scores)),
        "score_std":        float(np.std(anomaly_scores)),
        "score_p95":        float(np.percentile(anomaly_scores, 95)),
        "fc_risk_weights":  FC_RISK_WEIGHTS,               # NEW v2 — for reference
    }

    with open(model_path, "wb") as f:
        pickle.dump({
            "model":         model,
            "scaler":        scaler,
            "metadata":      metadata,
            "feature_names": list(features.columns),
        }, f)

    logger.info(f"Model saved: {model_path}")
    logger.info(f"   Training samples : {len(df)}")
    logger.info(f"   Features         : {len(features.columns)}")
    logger.info(f"   Avg anomaly score: {metadata['score_mean']:.1f}")
    logger.info(f"   P95 score        : {metadata['score_p95']:.1f}")
    logger.info(f"   Known src IPs    : {known_src_ips}")

    return metadata


# ─────────────────────────────────────────────────────────
# Score Utilities
# ─────────────────────────────────────────────────────────

def normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    """
    Convert Isolation Forest scores to 0-100 scale.
    Higher = more anomalous.
    IF returns negative scores for anomalies (more negative = more anomalous).
    """
    min_s = raw_scores.min()
    max_s = raw_scores.max()
    if max_s == min_s:
        return np.zeros_like(raw_scores)
    normalized = (raw_scores - max_s) / (min_s - max_s) * 100
    return np.clip(normalized, 0, 100)


def classify_severity(score: float) -> str:
    """Classify anomaly severity from 0-100 score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 65:
        return "HIGH"
    elif score >= 45:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────────────────
# EventWindow — sliding context buffer for real-time scoring
# ─────────────────────────────────────────────────────────

class EventWindow:
    """
    Maintains a fixed-size rolling window of recent OT events.

    This is critical for real-time scoring correctness:
    Rolling features (delta_time, rolling_std, rolling_mean) require
    multiple rows of history to be meaningful. Scoring a single event
    in isolation produces wrong feature values.

    Usage inside AnomalyScorer:
        self._window = EventWindow(maxlen=20)
        self._window.push(event_dict)
        df = self._window.to_dataframe()
        features = engineer_features(df)
        score = features.iloc[-1]   # last row = current event
    """

    def __init__(self, maxlen: int = 20):
        self._buf: deque = deque(maxlen=maxlen)

    def push(self, event: dict) -> None:
        """Add an event dict to the window."""
        self._buf.append(event)

    def to_dataframe(self) -> pd.DataFrame:
        """Return current window as a DataFrame, ordered oldest → newest."""
        return pd.DataFrame(list(self._buf))

    def __len__(self):
        return len(self._buf)


# ─────────────────────────────────────────────────────────
# Real-time Anomaly Scorer
# ─────────────────────────────────────────────────────────

class AnomalyScorer:
    """
    Real-time anomaly scoring for incoming OT events.

    v2 improvements:
    - Maintains EventWindow (sliding buffer) so rolling features
      are computed on real context, not a meaningless single-row DF.
    - Loads known_src_ips from model metadata for IP anomaly detection.
    - Exposes per-feature breakdown in score result for dashboard display.

    Usage:
        scorer = AnomalyScorer()
        result = scorer.score_event(event.to_dict())
        print(result["anomaly_score"], result["severity"])
    """

    WINDOW_SIZE = 20   # rolling context depth

    def __init__(self, model_path: str = "data/models/ot_model.pkl"):
        self.model_path      = model_path
        self.model           = None
        self.scaler          = None
        self.metadata        = None
        self.feature_names   = None
        self.known_src_ips: set = set()            # populated from metadata
        self._window = EventWindow(self.WINDOW_SIZE)  # sliding context buffer
        self._load_model()

    # ── Model I/O ────────────────────────────────────────────

    def _load_model(self):
        """Load trained model + metadata from disk."""
        if not os.path.exists(self.model_path):
            logger.warning(
                f"No model at {self.model_path}. "
                "Collect baseline data first, then run train_model()."
            )
            return

        with open(self.model_path, "rb") as f:
            saved = pickle.load(f)

        self.model         = saved["model"]
        self.scaler        = saved["scaler"]
        self.metadata      = saved["metadata"]
        self.feature_names = saved["feature_names"]

        # Restore known src IPs for runtime anomaly detection
        self.known_src_ips = set(
            self.metadata.get("known_src_ips", [])
        )

        trained_at = self.metadata.get("trained_at", "Unknown")
        samples    = self.metadata.get("training_samples", 0)
        features_n = self.metadata.get("feature_count", len(self.feature_names))
        logger.info(
            f"Model loaded — trained {trained_at} | "
            f"{samples} samples | {features_n} features | "
            f"{len(self.known_src_ips)} known src IPs"
        )

    def reload(self):
        """Reload model from disk (call after retraining)."""
        self._window = EventWindow(self.WINDOW_SIZE)  # reset window too
        self._load_model()

    # ── Real-time Scoring ─────────────────────────────────────

    def score_event(self, event_dict: dict) -> dict:
        """
        Score a single OT event with full rolling context.

        The event is pushed into the internal EventWindow first.
        Features are then engineered on the whole window, and only
        the last row (= current event) is scored.

        Returns
        -------
        dict with:
            anomaly_score  : float 0-100 (higher = more anomalous)
            severity       : str  CRITICAL / HIGH / MEDIUM / LOW
            is_anomaly     : bool
            features       : dict of engineered feature values
            flags          : dict of human-readable anomaly explanations
            error          : str or None
        """
        if not self.model:
            return {
                "anomaly_score": 0,
                "severity":      "UNKNOWN",
                "is_anomaly":    False,
                "features":      {},
                "flags":         {},
                "error":         "Model not loaded",
            }

        try:
            # Push into sliding window
            self._window.push(event_dict)
            df = self._window.to_dataframe()

            # Engineer features on the full window
            features = engineer_features(df, known_src_ips=self.known_src_ips)

            # Align columns with training schema
            for col in self.feature_names:
                if col not in features.columns:
                    features[col] = 0
            features = features[self.feature_names]

            # Score only the last row (current event)
            current_features = features.iloc[[-1]]
            features_scaled  = self.scaler.transform(current_features)
            raw_score        = self.model.score_samples(features_scaled)[0]
            anomaly_score    = float(normalize_scores(np.array([raw_score]))[0])
            is_anomaly       = self.model.predict(features_scaled)[0] == -1
            severity         = classify_severity(anomaly_score)

            # Build human-readable flags for dashboard / alert context
            feat_row = current_features.iloc[0]
            flags    = self._build_flags(feat_row, event_dict)

            return {
                "anomaly_score": round(anomaly_score, 1),
                "severity":      severity,
                "is_anomaly":    bool(is_anomaly),
                "features":      feat_row.to_dict(),
                "flags":         flags,
                "error":         None,
            }

        except Exception as exc:
            logger.error(f"Scoring error: {exc}")
            return {
                "anomaly_score": 0,
                "severity":      "ERROR",
                "is_anomaly":    False,
                "features":      {},
                "flags":         {},
                "error":         str(exc),
            }

    def _build_flags(self, feat_row: pd.Series, event_dict: dict) -> dict:
        """
        Translate engineered feature values into human-readable
        anomaly flags for dashboard and alert messages.
        """
        flags = {}

        fc_risk = feat_row.get("function_code_risk", 0)
        if fc_risk >= 7:
            fc_name = event_dict.get("function_name", f"FC {event_dict.get('function_code', '?')}")
            flags["high_risk_function"] = (
                f"High-risk Modbus command: {fc_name} (risk={int(fc_risk)}/10)"
            )

        if feat_row.get("is_unknown_src_ip", 0) == 1:
            flags["unknown_source_ip"] = (
                f"Unknown source IP: {event_dict.get('src_ip', '?')} "
                f"— not seen during baseline"
            )

        if feat_row.get("is_burst", 0) == 1:
            delta = feat_row.get("packet_delta_time", 0)
            flags["packet_burst"] = (
                f"Packet burst detected: delta={delta:.3f}s "
                f"(sub-100ms = possible scan/DDoS)"
            )

        if feat_row.get("delta_time_rolling_std", 0) > 5.0:
            flags["timing_anomaly"] = (
                f"Irregular polling rhythm: "
                f"std={feat_row.get('delta_time_rolling_std', 0):.2f}s"
            )

        if feat_row.get("is_write", 0) == 1:
            flags["write_command"] = (
                f"Write command to register "
                f"{event_dict.get('register_address', '?')}"
            )

        return flags

    # ── Batch Scoring ─────────────────────────────────────────

    def score_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score a batch of events from a CSV file.
        Uses the full batch for rolling context (correct behavior).
        """
        if not self.model:
            df = df.copy()
            df["anomaly_score"] = 0
            df["severity"]      = "UNKNOWN"
            df["is_anomaly"]    = False
            return df

        features = engineer_features(df, known_src_ips=self.known_src_ips)

        for col in self.feature_names:
            if col not in features.columns:
                features[col] = 0
        features = features[self.feature_names]

        features_scaled = self.scaler.transform(features)
        raw_scores      = self.model.score_samples(features_scaled)
        anomaly_scores  = normalize_scores(raw_scores)
        predictions     = self.model.predict(features_scaled)

        df = df.copy()
        df["anomaly_score"] = np.round(anomaly_scores, 1)
        df["is_anomaly"]    = predictions == -1
        df["severity"]      = df["anomaly_score"].apply(classify_severity)

        return df


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if len(sys.argv) < 2:
        print("Usage: python model.py <command> [args]")
        print("Commands:")
        print("  train <data_csv>   Train model on collected data")
        print("  score <data_csv>   Score events in CSV file")
        sys.exit(1)

    command = sys.argv[1]

    if command == "train":
        if len(sys.argv) < 3:
            print("Usage: python model.py train <data_csv>")
            sys.exit(1)
        metadata = train_model(sys.argv[2])
        print("\nTraining complete:")
        for k, v in metadata.items():
            if k not in ("fc_risk_weights", "known_src_ips"):
                print(f"  {k}: {v}")
        print(f"  known_src_ips ({len(metadata['known_src_ips'])}): "
              f"{metadata['known_src_ips']}")

    elif command == "score":
        if len(sys.argv) < 3:
            print("Usage: python model.py score <data_csv>")
            sys.exit(1)
        scorer = AnomalyScorer()
        df     = pd.read_csv(sys.argv[2])
        scored = scorer.score_batch(df)
        alerts = scored[scored["is_anomaly"] == True]
        print(f"\nScored {len(df)} events")
        print(f"Anomalies detected: {len(alerts)}")
        if not alerts.empty:
            print("\nTop anomalies:")
            cols = ["timestamp", "device_id", "event_type",
                    "anomaly_score", "severity"]
            avail = [c for c in cols if c in alerts.columns]
            print(alerts[avail].head(10).to_string())

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
