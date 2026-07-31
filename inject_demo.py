"""
SecureBridge -- Demo Anomaly Injector
Injects realistic anomalies into the lab simulation for showcase purposes.

Usage:
    python inject_demo.py              # inject all anomalies (default)
    python inject_demo.py frequency    # network scan only
    python inject_demo.py write        # unauthorized write only
"""

import sys
import os
import time

# Add project root to path
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import logging
from queue import Queue
from core.capture.monitor import LabSimulator, EventLogger

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SecureBridge.DemoInjector")


def inject(anomaly_type: str = "all"):
    event_queue = Queue()
    event_logger = EventLogger(log_dir="data/logs")
    sim = LabSimulator(event_queue, plc_count=3)

    print("")
    print("=" * 60)
    print("  SecureBridge -- Demo Anomaly Injector")
    print("=" * 60)

    if anomaly_type in ("write", "all"):
        print("")
        print("[CRITICAL] INJECTING: Unauthorized Write Command")
        print("   src: 192.168.10.199 -> PLC-001 | FC06 | Reg 40001 | Val 9999")
        sim.inject_anomaly("write")
        count = 0
        while not event_queue.empty():
            ev = event_queue.get()
            event_logger.log(ev)
            count += 1
        print("   [OK] " + str(count) + " event(s) logged to data/logs/")

    if anomaly_type == "all":
        print("")
        print("[...] Waiting 3 seconds before next anomaly...")
        print("")
        time.sleep(3)

    if anomaly_type in ("frequency", "all"):
        print("[HIGH] INJECTING: Abnormal Polling Frequency (network scan)")
        print("   src: 192.168.10.199 -- 20 rapid reads in 2s")
        sim.inject_anomaly("frequency")
        count = 0
        while not event_queue.empty():
            ev = event_queue.get()
            event_logger.log(ev)
            count += 1
        print("   [OK] " + str(count) + " scan events logged to data/logs/")

    print("")
    print("=" * 60)
    print("  [DONE] Anomaly injection complete!")
    print("  [>>]  Open http://localhost:8501 and refresh dashboard")
    print("  [>>]  Look for RED/ORANGE spikes in the anomaly timeline")
    print("=" * 60)
    print("")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode not in ("write", "frequency", "all"):
        print("Unknown mode '" + mode + "'. Use: write | frequency | all")
        sys.exit(1)
    inject(mode)
