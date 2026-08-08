"""
core/ingestion/event_reader.py
──────────────────────────────────────────────────────────────────────
Bounded-Memory Incremental Event Processing for SecureBridge.

Design decisions:
  - Reads ONLY newly-appended bytes since the last refresh (O(delta-N) I/O).
  - Maintains a deque(maxlen=5000) as the bounded working set for the dashboard.
  - Persistent state (counters + reader checkpoint) stored in a single JSON file
    so counters survive both Streamlit refreshes AND application restarts.
  - Partial-line safety (Strategy A): uses rfind(b'\n') on the new buffer so
    that a line being actively written by the simulator is never injected into
    the detection pipeline mid-write.
  - File-rotation detection: when the tracked filename differs from the most
    recent log file, offset resets to 0 on the new file.

Persistent state schema (data/models/event_counters.json):
  {
    "total_events":   <int>,
    "total_critical": <int>,
    "total_high":     <int>,
    "last_updated":   <ISO-8601 string>,
    "reader": {
      "filename": <str | null>,
      "offset":   <int>
    }
  }

Author: Sandy Lukita | PT Optima Sarana Instrument
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from collections import deque
from datetime import datetime
from typing import Optional

import pandas as pd

logger = logging.getLogger("SecureBridge.IncrementalEventReader")

WINDOW_SIZE        = 5_000
DEFAULT_STATE_PATH = "data/models/event_counters.json"

_EMPTY_STATE: dict = {
    "total_events":   0,
    "total_critical": 0,
    "total_high":     0,
    "last_updated":   None,
    "reader": {
        "filename": None,
        "offset":   0,
    },
}


class IncrementalEventReader:
    """
    Incremental CSV reader with bounded working set and persistent state.

    Usage (inside Streamlit, registered with @st.cache_resource):
        reader = IncrementalEventReader(log_dir="data/logs")
        df     = reader.get_recent_df()
        totals = reader.counters
    """

    def __init__(
        self,
        log_dir: str,
        state_path: str = DEFAULT_STATE_PATH,
        window: int = WINDOW_SIZE,
    ) -> None:
        self.log_dir    = log_dir
        self.state_path = state_path
        self.window     = window
        self._buf: deque[dict] = deque(maxlen=window)
        self._state: dict = {}
        self._load_state()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_recent_df(self) -> pd.DataFrame:
        """Advance reader by delta-N new bytes, return bounded DataFrame."""
        self._advance()
        return self._to_dataframe()

    @property
    def counters(self) -> dict:
        return {
            "total_events":   self._state["total_events"],
            "total_critical": self._state["total_critical"],
            "total_high":     self._state["total_high"],
            "last_updated":   self._state["last_updated"],
        }

    # ── State persistence ─────────────────────────────────────────────────────

    def _load_state(self) -> None:
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                self._state = {**_EMPTY_STATE, **loaded}
                self._state["reader"] = {
                    **_EMPTY_STATE["reader"],
                    **loaded.get("reader", {}),
                }
                logger.info(
                    f"[Reader] State loaded — total={self._state['total_events']}, "
                    f"file={self._state['reader']['filename']}, "
                    f"offset={self._state['reader']['offset']}"
                )
                self._replay_recent_from_disk()
            except Exception as exc:
                logger.warning(f"[Reader] Failed to load state ({exc}), starting fresh.")
                self._reset_state()
        else:
            self._reset_state()

    def _reset_state(self) -> None:
        self._state = _EMPTY_STATE.copy()
        self._state["reader"] = _EMPTY_STATE["reader"].copy()

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2, default=str)
            os.replace(tmp, self.state_path)
        except Exception as exc:
            logger.warning(f"[Reader] Failed to save state ({exc})")

    # ── Core advance logic ────────────────────────────────────────────────────

    def _resolve_current_file(self) -> Optional[str]:
        if not os.path.isdir(self.log_dir):
            return None
        csv_files = [
            os.path.join(self.log_dir, f)
            for f in os.listdir(self.log_dir)
            if f.endswith(".csv")
        ]
        return max(csv_files, key=os.path.getmtime) if csv_files else None

    def _advance(self) -> None:
        current_file = self._resolve_current_file()
        if current_file is None:
            return

        prev_filename = self._state["reader"]["filename"]
        prev_offset   = self._state["reader"]["offset"]

        # Rotation detection
        if prev_filename and (os.path.basename(current_file) != os.path.basename(prev_filename)):
            logger.info(f"[Reader] Rotation: {os.path.basename(prev_filename)} -> {os.path.basename(current_file)}")
            prev_offset = 0
            self._state["reader"]["_fieldnames"] = None  # reset cached header

        try:
            file_size = os.path.getsize(current_file)
        except OSError:
            return

        if file_size <= prev_offset:
            return

        try:
            with open(current_file, "rb") as f:
                f.seek(prev_offset)
                raw_bytes = f.read(file_size - prev_offset)
        except OSError as exc:
            logger.warning(f"[Reader] Read failed ({exc})")
            return

        if not raw_bytes:
            return

        # Strategy A: partial-line safety
        last_newline = raw_bytes.rfind(b"\n")
        if last_newline == -1:
            return  # no complete line yet

        complete_bytes = raw_bytes[: last_newline + 1]
        new_offset     = prev_offset + last_newline + 1

        new_rows = self._parse_csv_bytes(complete_bytes, current_file, prev_offset)
        self._buf.extend(new_rows)

        # Update counters
        n_new      = len(new_rows)
        n_critical = sum(1 for r in new_rows if str(r.get("severity", "")).upper() == "CRITICAL")
        n_high     = sum(1 for r in new_rows if str(r.get("severity", "")).upper() == "HIGH")

        self._state["total_events"]   += n_new
        self._state["total_critical"] += n_critical
        self._state["total_high"]     += n_high
        self._state["last_updated"]    = datetime.now().isoformat()
        self._state["reader"]["filename"] = current_file
        self._state["reader"]["offset"]   = new_offset

        if n_new:
            logger.info(
                f"[Reader] +{n_new} events (crit={n_critical}, high={n_high}) "
                f"| buf={len(self._buf)} | total={self._state['total_events']}"
            )

        self._save_state()

    def _parse_csv_bytes(self, raw_bytes: bytes, current_file: str, prev_offset: int) -> list:
        text = raw_bytes.decode("utf-8", errors="replace")

        if prev_offset == 0:
            reader_obj = csv.DictReader(io.StringIO(text))
            rows = list(reader_obj)
            if reader_obj.fieldnames:
                self._state["reader"]["_fieldnames"] = list(reader_obj.fieldnames)
        else:
            fieldnames = self._state["reader"].get("_fieldnames")
            if not fieldnames:
                try:
                    with open(current_file, "r", encoding="utf-8", errors="replace") as f:
                        header_line = f.readline()
                    fieldnames = next(csv.reader([header_line]))
                    self._state["reader"]["_fieldnames"] = fieldnames
                except Exception:
                    logger.warning("[Reader] Cannot resolve fieldnames — skipping delta")
                    return []
            reader_obj = csv.DictReader(io.StringIO(text), fieldnames=fieldnames)
            rows = list(reader_obj)

        return rows

    def _replay_recent_from_disk(self) -> None:
        filename = self._state["reader"].get("filename")
        offset   = self._state["reader"].get("offset", 0)
        if not filename or not os.path.exists(filename):
            return
        try:
            read_back = min(offset, self.window * 200)
            start_pos = offset - read_back
            with open(filename, "rb") as f:
                if start_pos > 0:
                    f.seek(start_pos)
                    f.readline()  # skip partial line at boundary
                raw_bytes = f.read(read_back)
            if not raw_bytes:
                return
            last_nl = raw_bytes.rfind(b"\n")
            if last_nl != -1:
                raw_bytes = raw_bytes[: last_nl + 1]
            rows = self._parse_csv_bytes(raw_bytes, filename, prev_offset=1)
            self._buf.extend(rows[-self.window :])
            logger.info(f"[Reader] Replayed {len(self._buf)} rows into working set.")
        except Exception as exc:
            logger.warning(f"[Reader] Replay failed ({exc})")

    # ── DataFrame conversion ──────────────────────────────────────────────────

    def _to_dataframe(self) -> pd.DataFrame:
        if not self._buf:
            return pd.DataFrame()
        df = pd.DataFrame(list(self._buf))

        # Type coercion — csv.DictReader returns ALL values as strings.
        # pd.read_csv() used to auto-infer types; we must do it explicitly.

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Numeric columns
        for col in ("anomaly_score", "register_address", "payload_length",
                    "transaction_id", "value", "function_code"):
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # Boolean-like columns stored as "True"/"False" strings by the simulator
        for col in ("is_write", "is_anomaly"):
            if col in df.columns:
                df[col] = df[col].map(
                    lambda v: True if str(v).strip().lower() in ("true", "1") else False
                )

        if "severity" not in df.columns:
            df["severity"] = "UNKNOWN"

        return df
