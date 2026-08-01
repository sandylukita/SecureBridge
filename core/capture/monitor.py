"""
SecureBridge — OT Network Monitor
Agentless passive packet capture for industrial networks

Works in two modes:
- LIVE: Real network interface (SPAN port / network tap)
- LAB: Simulated Modbus traffic from ModRSsim2

Zero impact on OT operations — passive monitoring only.
"""

import sys
import os
import time
import json
import logging
import threading
import socket
import struct
from datetime import datetime
from queue import Queue

# Add project root to path so all modules resolve correctly
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from config.settings import load_config

# ─────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SecureBridge.Monitor")


# ─────────────────────────────────────────────────────────
# OT Event Data Structure
# ─────────────────────────────────────────────────────────

class OTEvent:
    """Represents a captured OT network event"""

    def __init__(self, src_ip: str, dst_ip: str,
                 protocol: str, event_type: str,
                 data: dict):
        self.timestamp = datetime.now().isoformat()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.event_type = event_type
        self.data = data

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "event_type": self.event_type,
            **self.data
        }

    def __repr__(self):
        return (f"OTEvent({self.protocol} | {self.src_ip} → {self.dst_ip} "
                f"| {self.event_type})")


# ─────────────────────────────────────────────────────────
# Modbus TCP Parser
# ─────────────────────────────────────────────────────────

MODBUS_PORT = 502
MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    43: "Read Device Identification"
}


def parse_modbus_packet(payload: bytes, src_ip: str,
                        dst_ip: str) -> OTEvent | None:
    """
    Parse Modbus TCP Application Data Unit (ADU)
    Structure: [Transaction ID (2)] [Protocol ID (2)]
               [Length (2)] [Unit ID (1)] [PDU...]
    """
    if len(payload) < 8:
        return None

    try:
        transaction_id = struct.unpack(">H", payload[0:2])[0]
        protocol_id = struct.unpack(">H", payload[2:4])[0]

        if protocol_id != 0:  # Modbus always has protocol_id = 0
            return None

        length = struct.unpack(">H", payload[4:6])[0]
        unit_id = payload[6]
        function_code = payload[7]

        func_name = MODBUS_FUNCTIONS.get(
            function_code, f"Unknown (FC {function_code})"
        )

        data = {
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": func_name,
            "transaction_id": transaction_id,
            "payload_length": length,
            "is_write": function_code in [5, 6, 15, 16],
            "raw_size": len(payload)
        }

        # Extract register address for read/write functions
        if function_code in [1, 2, 3, 4, 5, 6, 15, 16] and len(payload) >= 10:
            register_addr = struct.unpack(">H", payload[8:10])[0]
            data["register_address"] = register_addr

        # Flag write operations — higher risk
        if function_code in [5, 6, 15, 16]:
            event_type = "MODBUS_WRITE"
        elif function_code == 43:
            event_type = "MODBUS_DISCOVERY"
        else:
            event_type = "MODBUS_READ"

        return OTEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="Modbus TCP",
            event_type=event_type,
            data=data
        )

    except (struct.error, IndexError):
        return None


# ─────────────────────────────────────────────────────────
# Live Network Monitor
# Primary  : pyshark.LiveCapture (TShark / libpcap)
# Fallback : raw sockets (AF_INET / SOCK_RAW)
# ─────────────────────────────────────────────────────────

class LiveMonitor:
    """
    Passive OT network monitor.

    Capture engine selection (controlled by config.capture.use_pyshark):

    1. PysharkCapture (preferred)
       Uses pyshark.LiveCapture + libpcap/Npcap with a BPF filter.
       Supports Modbus TCP, EtherNet/IP, and BACnet/IP.
       Requires: Npcap (Windows) or libpcap (Linux) + TShark in PATH.

    2. Raw socket fallback
       Uses socket.AF_INET / SOCK_RAW — Modbus TCP only.
       Requires: administrator / root privileges.
       Activated automatically when pyshark or TShark is unavailable.

    Production deployment:
       Connect interface to SPAN / mirror port — no IP address needed.
       Interface cannot initiate connections → zero impact on OT operations.
    """

    def __init__(
        self,
        interface: str,
        event_queue: Queue,
        use_pyshark: bool = True,
        bpf_filter: str = "tcp port 502 or tcp port 44818 or udp port 47808",
    ):
        self.interface   = interface
        self.event_queue = event_queue
        self.use_pyshark = use_pyshark
        self.bpf_filter  = bpf_filter
        self.running     = False
        self._stats      = {"packets": 0, "events": 0, "errors": 0}
        self._engine     = "none"      # populated when capture starts

    # ── Public API ───────────────────────────────────────────

    def start(self) -> None:
        """Start passive capture — tries pyshark first, falls back to raw socket."""
        self.running = True

        if self.use_pyshark and self._try_pyshark():
            return   # pyshark ran and exited cleanly

        # ── Fallback: raw sockets ──
        self._start_raw_socket()

    def stop(self) -> None:
        self.running = False

    # ── Engine 1: Pyshark ────────────────────────────────────

    def _try_pyshark(self) -> bool:
        """
        Attempt to start PysharkCapture.

        Returns True  if pyshark started successfully (even if it later stopped).
        Returns False if pyshark / tshark is unavailable → caller should fallback.
        """
        try:
            from core.capture.pyshark_capture import PysharkCapture

            cap = PysharkCapture(
                interface=self.interface,
                event_queue=self.event_queue,
                bpf_filter=self.bpf_filter,
            )
            self._engine = "pyshark"

            logger.info("Capture engine  : pyshark.LiveCapture (primary)")
            logger.info(f"BPF filter      : {self.bpf_filter}")
            logger.info("Interface mode  : PASSIVE — no IP, no TX")

            cap.start()   # blocking

            # Sync stats back
            ps_stats = cap.get_stats()
            self._stats["packets"] = ps_stats["packets_total"]
            self._stats["events"]  = ps_stats["events_emitted"]
            self._stats["errors"]  = ps_stats["errors"]
            return True

        except ImportError:
            logger.warning(
                "pyshark not installed — run: pip install pyshark"
            )
        except Exception as exc:
            # TShark not found, Npcap missing, permission denied, etc.
            logger.warning(
                f"pyshark unavailable ({type(exc).__name__}: {exc})"
            )
        return False

    # ── Engine 2: Raw socket fallback ────────────────────────

    def _start_raw_socket(self) -> None:
        """
        Fallback passive capture using AF_INET / SOCK_RAW.
        Covers Modbus TCP (port 502) only.
        Requires administrator / root privileges.
        """
        self._engine = "raw_socket"
        logger.info("Capture engine  : raw socket (fallback)")
        logger.info("Protocol support: Modbus TCP only")
        logger.info("Mode            : PASSIVE — zero impact on OT operations")

        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP,
            )
            sock.settimeout(1.0)

            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)
                    self._stats["packets"] += 1
                    self._process_raw_packet(packet, addr)
                except socket.timeout:
                    continue
                except Exception as exc:
                    self._stats["errors"] += 1
                    logger.debug(f"Packet error: {exc}")

        except PermissionError:
            logger.error(
                "Root / administrator privileges required for raw socket capture."
            )
            logger.info("Tip: On Windows run as Administrator; on Linux use sudo.")
        finally:
            logger.info(f"Raw socket capture stopped. Stats: {self._stats}")

    def _process_raw_packet(self, packet: bytes, addr: tuple) -> None:
        """Extract TCP payload and route to Modbus parser (raw socket fallback)."""
        try:
            ip_header_len = (packet[0] & 0xF) * 4
            tcp_start     = ip_header_len

            if len(packet) < tcp_start + 20:
                return

            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])

            tcp_header     = packet[tcp_start:tcp_start + 20]
            dst_port       = struct.unpack(">H", tcp_header[2:4])[0]
            tcp_header_len = ((tcp_header[12] >> 4) & 0xF) * 4
            payload_start  = tcp_start + tcp_header_len
            payload        = packet[payload_start:]

            if not payload:
                return

            event = None
            if dst_port == MODBUS_PORT:
                event = parse_modbus_packet(payload, src_ip, dst_ip)

            if event:
                event.data["capture_engine"] = "raw_socket"
                self._stats["events"] += 1
                self.event_queue.put(event)

        except Exception:
            pass


# ─────────────────────────────────────────────────────────
# Lab Simulator (Modbus TCP client)
# ─────────────────────────────────────────────────────────

class LabSimulator:
    """
    Simulates OT network traffic for lab/demo mode
    Connects to ModRSsim2 or pymodbus server
    Generates realistic Modbus polling patterns
    """

    def __init__(self, event_queue: Queue, plc_count: int = 3):
        self.event_queue = event_queue
        self.plc_count = plc_count
        self.running = False

        # Simulated PLCs
        self.plcs = [
            {
                "device_id": f"PLC-{i+1:02d}",
                "ip": f"192.168.40.{10 + i}",
                "unit_id": i + 1,
                "registers": {
                    40001: {"name": "Pressure", "base": 100, "variance": 5},
                    40002: {"name": "Temperature", "base": 75, "variance": 3},
                    40003: {"name": "Flow_Rate", "base": 50, "variance": 8},
                    40004: {"name": "Level", "base": 60, "variance": 4},
                }
            }
            for i in range(plc_count)
        ]

    def start(self):
        """Start simulation"""
        self.running = True
        logger.info(f"Lab simulator started — {self.plc_count} simulated PLCs")

        import random
        cycle = 0

        while self.running:
            cycle += 1

            for plc in self.plcs:
                # Normal polling — every 5 seconds
                for reg_addr, reg_info in plc["registers"].items():
                    value = int(
                        reg_info["base"] +
                        random.gauss(0, reg_info["variance"])
                    )
                    value = max(0, value)

                    event = OTEvent(
                        src_ip="192.168.10.100",   # SCADA workstation
                        dst_ip=plc["ip"],
                        protocol="Modbus TCP",
                        event_type="MODBUS_READ",
                        data={
                            "unit_id": plc["unit_id"],
                            "function_code": 3,
                            "function_name": "Read Holding Registers",
                            "register_address": reg_addr,
                            "register_name": reg_info["name"],
                            "value": value,
                            "device_id": plc["device_id"],
                            "payload_length": 12,
                            "raw_size": 20,
                            "transaction_id": cycle,
                            "is_write": False,
                        }
                    )
                    self.event_queue.put(event)

            time.sleep(5)

    def inject_anomaly(self, anomaly_type: str = "frequency"):
        """Inject anomaly for demo purposes"""
        import random

        if anomaly_type == "frequency":
            # Rapid polling — network scan signature
            logger.warning("INJECTING: Abnormal polling frequency anomaly")
            plc = self.plcs[0]
            for i in range(20):
                event = OTEvent(
                    src_ip="192.168.10.199",  # Unknown source
                    dst_ip=plc["ip"],
                    protocol="Modbus TCP",
                    event_type="MODBUS_READ",
                    data={
                        "unit_id": 0,  # Broadcast
                        "function_code": 3,
                        "function_name": "Read Holding Registers",
                        "register_address": 40001 + i,
                        "value": 0,
                        "device_id": plc["device_id"],
                        "payload_length": 12,
                        "raw_size": 20,
                        "transaction_id": 9000 + i,
                        "is_write": False,
                        "anomaly_injected": True,
                    }
                )
                self.event_queue.put(event)
                time.sleep(0.1)

        elif anomaly_type == "write":
            # Unauthorized write — critical risk
            logger.warning("INJECTING: Unauthorized write command anomaly")
            plc = self.plcs[0]
            event = OTEvent(
                src_ip="192.168.10.199",
                dst_ip=plc["ip"],
                protocol="Modbus TCP",
                event_type="MODBUS_WRITE",
                data={
                    "unit_id": plc["unit_id"],
                    "function_code": 6,
                    "function_name": "Write Single Register",
                    "register_address": 40001,
                    "value": 9999,  # Abnormal value
                    "device_id": plc["device_id"],
                    "payload_length": 12,
                    "raw_size": 20,
                    "transaction_id": 9999,
                    "is_write": True,
                    "anomaly_injected": True,
                }
            )
            self.event_queue.put(event)

    def stop(self):
        self.running = False


# ─────────────────────────────────────────────────────────
# Event Logger
# ─────────────────────────────────────────────────────────

class EventLogger:
    """Persists OT events to CSV for ML training and audit"""

    def __init__(self, log_dir: str = "data/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(
            log_dir,
            f"ot_events_{datetime.now().strftime('%Y%m%d')}.csv"
        )
        self._init_file()
        self._stats = {"total": 0, "writes": 0, "anomalies": 0}

    def _init_file(self):
        if not os.path.exists(self.log_file):
            import csv
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "src_ip", "dst_ip",
                    "protocol", "event_type",
                    "unit_id", "function_code", "function_name",
                    "register_address", "value", "device_id",
                    "payload_length", "raw_size", "is_write",
                    "transaction_id", "anomaly_injected"
                ])

    def log(self, event: OTEvent):
        import csv
        self._stats["total"] += 1
        if event.data.get("is_write"):
            self._stats["writes"] += 1
        if event.data.get("anomaly_injected"):
            self._stats["anomalies"] += 1

        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                event.timestamp,
                event.src_ip,
                event.dst_ip,
                event.protocol,
                event.event_type,
                event.data.get("unit_id", ""),
                event.data.get("function_code", ""),
                event.data.get("function_name", ""),
                event.data.get("register_address", ""),
                event.data.get("value", ""),
                event.data.get("device_id", ""),
                event.data.get("payload_length", ""),
                event.data.get("raw_size", ""),
                event.data.get("is_write", False),
                event.data.get("transaction_id", ""),
                event.data.get("anomaly_injected", False),
            ])

    @property
    def stats(self):
        return self._stats


# ─────────────────────────────────────────────────────────
# Main Monitor Process
# ─────────────────────────────────────────────────────────

def run_monitor(config_path: str = "config/lab.yaml"):
    """Main entry point for OT network monitoring"""

    config = load_config(config_path)
    event_queue = Queue(maxsize=10000)
    event_logger = EventLogger(config.log_dir)

    logger.info("=" * 60)
    logger.info("  SecureBridge OT Network Monitor")
    logger.info(f"  Mode: {config.mode.upper()}")
    logger.info(f"  Network: {config.capture.target_network}")
    logger.info("=" * 60)

    # Start appropriate monitor/simulator
    if config.mode == "live":
        monitor = LiveMonitor(
            interface=config.capture.interface,
            event_queue=event_queue,
            use_pyshark=config.capture.use_pyshark,
            bpf_filter=config.capture.bpf_filter,
        )
        monitor_thread = threading.Thread(
            target=monitor.start, daemon=True
        )
        monitor_thread.start()
        logger.info(
            f"✅ Live monitoring active — "
            f"engine: {'pyshark' if config.capture.use_pyshark else 'raw_socket'}"
        )

    else:
        simulator = LabSimulator(event_queue, plc_count=3)
        sim_thread = threading.Thread(
            target=simulator.start, daemon=True
        )
        sim_thread.start()
        logger.info("✅ Lab simulator active — 3 PLCs")

    # Process events
    logger.info("Processing OT events... (Ctrl+C to stop)")
    event_count = 0

    try:
        while True:
            if not event_queue.empty():
                event = event_queue.get()
                event_logger.log(event)
                event_count += 1

                # Log writes immediately — higher risk
                if event.data.get("is_write"):
                    logger.warning(
                        f"⚠️  WRITE detected: {event.src_ip} → "
                        f"{event.dst_ip} | "
                        f"Register {event.data.get('register_address')}"
                    )

                # Progress update every 100 events
                if event_count % 100 == 0:
                    stats = event_logger.stats
                    logger.info(
                        f"Events: {stats['total']} | "
                        f"Writes: {stats['writes']} | "
                        f"Log: {event_logger.log_file}"
                    )

            time.sleep(0.01)

    except KeyboardInterrupt:
        logger.info("\nStopping monitor...")
        final = event_logger.stats
        logger.info(f"Final stats: {final}")
        logger.info(f"Log file: {event_logger.log_file}")
        logger.info("SecureBridge monitor stopped.")


if __name__ == "__main__":
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/lab.yaml"
    run_monitor(config_path)
