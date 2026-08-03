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
    # Store RAW decision-function statistics (before normalization) so that
    # future single-event scoring can use the same reference range — this
    # prevents the min==max collapse that occurs when normalizing a 1-row batch.
    raw_scores = model.score_samples(features_scaled)
    anomaly_scores = normalize_scores(raw_scores,
                                      train_max=float(np.max(raw_scores)),
                                      train_min=float(np.min(raw_scores)))

    # ── Save model + scaler + metadata ───────────────────────
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    metadata = {
        "trained_at":        datetime.now().isoformat(),
        "training_samples":  len(df),
        "features":          list(features.columns),
        "feature_count":     len(features.columns),
        "contamination":     contamination,
        "known_src_ips":     list(known_src_ips),
        # Raw decision-function range from training set — used for normalization
        "score_raw_min":     float(np.min(raw_scores)),
        "score_raw_max":     float(np.max(raw_scores)),
        "score_raw_mean":    float(np.mean(raw_scores)),
        "score_raw_std":     float(np.std(raw_scores)),
        # Normalized score stats (for reference / logging)
        "score_mean":        float(np.mean(anomaly_scores)),
        "score_std":         float(np.std(anomaly_scores)),
        "score_p95":         float(np.percentile(anomaly_scores, 95)),
        "fc_risk_weights":   FC_RISK_WEIGHTS,
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
    logger.info(f"   Raw score range  : [{metadata['score_raw_min']:.3f}, {metadata['score_raw_max']:.3f}]")
    logger.info(f"   Avg anomaly score: {metadata['score_mean']:.1f}")
    logger.info(f"   P95 score        : {metadata['score_p95']:.1f}")
    logger.info(f"   Known src IPs    : {known_src_ips}")

    return metadata


# ─────────────────────────────────────────────────────────
# Score Utilities
# ─────────────────────────────────────────────────────────

def normalize_scores(raw_scores: np.ndarray,
                     train_max: float = 0.2,
                     train_min: float = -0.5) -> np.ndarray:
    """
    Convert Isolation Forest decision function scores to 0-100 scale.
    Higher = more anomalous.

    Uses the raw score range from the *training dataset* as reference bounds,
    so that single-event scoring produces consistent results relative to the
    baseline distribution the model was trained on.

    Parameters
    ----------
    raw_scores : np.ndarray
        Isolation Forest `score_samples()` output (~+0.2 normal, ~-0.5 critical).
    train_max : float
        Maximum `score_samples()` value observed during training (normal upper bound).
        Defaults to 0.2 as a conservative fallback when metadata is unavailable.
    train_min : float
        Minimum `score_samples()` value observed during training (most anomalous).
        Defaults to -0.5 as a conservative fallback.
    """
    raw_scores = np.asarray(raw_scores, dtype=float)
    score_range = train_max - train_min
    if score_range == 0:
        # Degenerate case: all training scores were identical (shouldn't happen)
        return np.zeros_like(raw_scores)
    normalized = (train_max - raw_scores) / score_range * 100
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
        self.model_path       = model_path
        self.model            = None
        self.scaler           = None
        self.metadata         = None
        self.feature_names    = None
        self.known_src_ips: set = set()            # populated from metadata
        # Training-data raw score bounds — used for consistent normalization
        # Defaults are reasonable fallbacks when model has no metadata yet
        self.train_score_max: float = 0.2
        self.train_score_min: float = -0.5
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

        # Restore raw score bounds from training for consistent normalization
        self.train_score_max = self.metadata.get("score_raw_max", 0.2)
        self.train_score_min = self.metadata.get("score_raw_min", -0.5)

        trained_at = self.metadata.get("trained_at", "Unknown")
        samples    = self.metadata.get("training_samples", 0)
        features_n = self.metadata.get("feature_count", len(self.feature_names))
        logger.info(
            f"Model loaded — trained {trained_at} | "
            f"{samples} samples | {features_n} features | "
            f"score range [{self.train_score_min:.3f}, {self.train_score_max:.3f}] | "
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
            # Use training-data bounds for normalization — ensures consistent
            # scoring regardless of how many events are in the current window.
            anomaly_score    = float(normalize_scores(
                np.array([raw_score]),
                train_max=self.train_score_max,
                train_min=self.train_score_min
            )[0])
            is_anomaly       = self.model.predict(features_scaled)[0] == -1

            feat_row = current_features.iloc[0]

            severity = classify_severity(anomaly_score)
            flags    = self._build_flags(feat_row, event_dict)

            res = dict(event_dict)
            res.update({
                "anomaly_score": round(anomaly_score, 1),
                "severity":      severity,
                "is_anomaly":    bool(is_anomaly),
                "features":      feat_row.to_dict(),
                "flags":         flags,
                "error":         None,
            })
            return res

        except Exception as exc:
            logger.error(f"Scoring error: {exc}")
            res = dict(event_dict)
            res.update({
                "anomaly_score": 0,
                "severity":      "ERROR",
                "is_anomaly":    False,
                "features":      {},
                "flags":         {},
                "error":         str(exc),
            })
            return res

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
        # Use training-data bounds for normalization — same reference as score_event()
        anomaly_scores  = normalize_scores(raw_scores,
                                           train_max=self.train_score_max,
                                           train_min=self.train_score_min)
        predictions     = self.model.predict(features_scaled)

        df = df.copy()
        df["anomaly_score"] = np.round(anomaly_scores, 1)
        df["is_anomaly"]    = predictions == -1
        df["severity"]      = df["anomaly_score"].apply(classify_severity)

        return df


# ─────────────────────────────────────────────────────────
# Incremental Scorer (SIEM-grade delta scoring with cache)
# ─────────────────────────────────────────────────────────

class IncrementalScorer:
    """
    Cache-backed incremental anomaly scorer for dashboard performance.

    In production SIEM/SOC platforms, historical events are never re-processed
    on every dashboard refresh.  Only *new* events (delta since last refresh)
    are scored by the ML model.  Previously-seen events are served instantly
    from a local cache, reducing Isolation Forest invocations from O(N_total)
    to O(N_new) per refresh cycle.

    Cache invalidation strategy
    ---------------------------
    The cache stores the ``trained_at`` timestamp of the model used to score
    each entry.  If the model is retrained (new pickle saved), ``trained_at``
    changes and the entire cache is automatically flushed and rebuilt on the
    next refresh — ensuring scores are always consistent with the live model.

    Row identity
    ------------
    Each event is identified by an MD5 hash of its ``timestamp``,
    ``device_id``, and ``register_address`` fields.  This is collision-resistant
    enough for the event volumes encountered in OT environments (< 1 M events/day).

    Usage
    -----
        scorer = AnomalyScorer()
        inc    = IncrementalScorer(scorer)
        scored_df = inc.score_incremental(raw_df)

    On first call  : all rows are scored via ``scorer.score_batch()`` (~1-2s).
    On later calls : only rows not in cache are scored (<0.1s for typical delta).
    """

    CACHE_VERSION = "1"   # bump to force a full cache flush on breaking changes

    def __init__(
        self,
        scorer: "AnomalyScorer",
        cache_path: str = "data/models/score_cache.pkl",
    ):
        self.scorer     = scorer
        self.cache_path = cache_path
        self._cache: dict = {}          # {row_hash: {anomaly_score, severity, is_anomaly}}
        self._cached_model_ts: str = "" # trained_at of model when cache was built
        self._load_cache()

    # ── Cache I/O ─────────────────────────────────────────────

    def _load_cache(self) -> None:
        """Load existing cache from disk.  Flush if model has been retrained."""
        if not os.path.exists(self.cache_path):
            return
        try:
            with open(self.cache_path, "rb") as f:
                saved = pickle.load(f)

            # Guard: reject cache if built for a different model version
            if (saved.get("version")    != self.CACHE_VERSION or
                    saved.get("model_ts") != self._current_model_ts()):
                logger.info("IncrementalScorer: model retrained — cache invalidated")
                return

            self._cache           = saved.get("cache", {})
            self._cached_model_ts = saved.get("model_ts", "")
            logger.info(
                f"IncrementalScorer: loaded {len(self._cache)} cached scores "
                f"(model ts: {self._cached_model_ts})"
            )
        except Exception as exc:
            logger.warning(f"IncrementalScorer: cache load failed ({exc}) — starting fresh")
            self._cache = {}

    def _save_cache(self) -> None:
        """Persist cache to disk."""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "wb") as f:
                pickle.dump({
                    "version":  self.CACHE_VERSION,
                    "model_ts": self._current_model_ts(),
                    "cache":    self._cache,
                }, f)
        except Exception as exc:
            logger.warning(f"IncrementalScorer: cache save failed ({exc})")

    def _current_model_ts(self) -> str:
        """Return the trained_at timestamp of the currently loaded model."""
        if self.scorer.metadata:
            return self.scorer.metadata.get("trained_at", "")
        return ""

    # ── Row Hashing ───────────────────────────────────────────

    @staticmethod
    def _hash_row(row: pd.Series) -> str:
        """
        Stable MD5 fingerprint for a single event row.

        Uses timestamp + device_id + register_address — sufficient to uniquely
        identify an OT packet in normal Modbus polling patterns.
        """
        import hashlib
        key = (
            str(row.get("timestamp", ""))
            + str(row.get("device_id", ""))
            + str(row.get("register_address", ""))
            + str(row.get("function_code", ""))
            + str(row.get("src_ip", ""))
        )
        return hashlib.md5(key.encode()).hexdigest()

    # ── Incremental Scoring ───────────────────────────────────

    def score_incremental(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score a DataFrame incrementally — only new rows hit Isolation Forest.

        Parameters
        ----------
        df : pd.DataFrame
            Full set of events for the current dashboard time window.

        Returns
        -------
        pd.DataFrame
            Same rows as ``df`` with ``anomaly_score``, ``severity``, and
            ``is_anomaly`` columns added.  Rows are returned in the original
            order (sorted by timestamp).
        """
        if df.empty:
            return df

        # Check model timestamp — invalidate in-memory cache if model changed
        current_ts = self._current_model_ts()
        if current_ts != self._cached_model_ts:
            logger.info("IncrementalScorer: model change detected — flushing in-memory cache")
            self._cache           = {}
            self._cached_model_ts = current_ts

        df = df.copy().reset_index(drop=True)
        df["_row_hash"] = df.apply(self._hash_row, axis=1)

        # Split: rows already in cache vs rows that need scoring
        cached_mask = df["_row_hash"].isin(self._cache)
        new_df      = df[~cached_mask].copy()
        old_df      = df[cached_mask].copy()

        n_new   = len(new_df)
        n_cache = len(old_df)
        logger.debug(
            f"IncrementalScorer: {n_cache} from cache, {n_new} need scoring"
        )

        # Score only new rows using full batch (preserves rolling feature context)
        if not new_df.empty:
            # Drop the helper column before passing to score_batch
            scored_new = self.scorer.score_batch(new_df.drop(columns=["_row_hash"]))
            scored_new["_row_hash"] = new_df["_row_hash"].values

            # Store results in cache
            for _, row in scored_new.iterrows():
                self._cache[row["_row_hash"]] = {
                    "anomaly_score": row["anomaly_score"],
                    "severity":      row["severity"],
                    "is_anomaly":    row["is_anomaly"],
                }
            self._save_cache()
        else:
            scored_new = pd.DataFrame()

        # Apply cached scores to old rows
        if not old_df.empty:
            old_df = old_df.drop(columns=["_row_hash"])
            for col in ("anomaly_score", "severity", "is_anomaly"):
                old_df[col] = old_df.apply(
                    lambda r: self._cache.get(
                        df.loc[r.name, "_row_hash"], {}
                    ).get(col, 0 if col == "anomaly_score" else "UNKNOWN"),
                    axis=1,
                )
        else:
            old_df = pd.DataFrame()

        # Combine and restore original order
        if not scored_new.empty and "_row_hash" in scored_new.columns:
            scored_new = scored_new.drop(columns=["_row_hash"])

        result = pd.concat([old_df, scored_new], ignore_index=True)

        # Re-sort by timestamp to maintain chronological order
        if "timestamp" in result.columns:
            result = result.sort_values("timestamp").reset_index(drop=True)

        logger.info(
            f"IncrementalScorer: {n_cache} cached + {n_new} newly scored "
            f"= {len(result)} total | cache size: {len(self._cache)}"
        )
        return result

    def clear_cache(self) -> None:
        """Manually flush in-memory and on-disk cache (e.g. after model retrain)."""
        self._cache           = {}
        self._cached_model_ts = ""
        if os.path.exists(self.cache_path):
            os.remove(self.cache_path)
        logger.info("IncrementalScorer: cache cleared")


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
