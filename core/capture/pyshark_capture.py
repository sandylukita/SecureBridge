"""
SecureBridge — Pyshark Passive Capture Engine
=============================================
Passive OT network monitoring via pyshark.LiveCapture (TShark/libpcap).

Architecture:
    SPAN/mirror port → [no IP, no TX] → pyshark.LiveCapture
                                              │
                           BPF filter: tcp/502, tcp/44818, udp/47808
                                              │
                        _parse_modbus() / _parse_enip() / _parse_bacnet()
                                              │
                                         OTEvent → event_queue

Prerequisites:
    Windows : Npcap  ≥ 1.75  (https://npcap.com)
    Linux   : libpcap-dev, run as root or with CAP_NET_RAW
    Python  : pyshark ≥ 0.6  (pip install pyshark)

Interview reference:
    "We use pyshark.LiveCapture() on a SPAN mirror port with a BPF filter
     targeting OT protocol ports — TCP 502 (Modbus), TCP 44818 (EtherNet/IP),
     UDP 47808 (BACnet). The monitoring interface has no IP address and cannot
     initiate connections — the same passive-only design used by Nozomi Networks
     and Claroty."
"""

from __future__ import annotations

import logging
import struct
from queue import Queue
from typing import Optional

logger = logging.getLogger("SecureBridge.PysharkCapture")

# ─────────────────────────────────────────────────────────
# OT Protocol Port Constants
# ─────────────────────────────────────────────────────────

MODBUS_PORT   = 502    # Modbus TCP  — IEC 61158 / most PLCs
ENIP_PORT     = 44818  # EtherNet/IP — Rockwell / Allen-Bradley
BACNET_PORT   = 47808  # BACnet/IP   — Building automation (UDP)

# Modbus function code registry
MODBUS_FUNCTIONS = {
    1:  "Read Coils",
    2:  "Read Discrete Inputs",
    3:  "Read Holding Registers",
    4:  "Read Input Registers",
    5:  "Write Single Coil",
    6:  "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    43: "Read Device Identification",
}

# Default BPF filter — covers the three most common OT protocols
DEFAULT_BPF_FILTER = (
    f"tcp port {MODBUS_PORT} "
    f"or tcp port {ENIP_PORT} "
    f"or udp port {BACNET_PORT}"
)


# ─────────────────────────────────────────────────────────
# OTEvent (inline — avoids circular import from monitor.py)
# ─────────────────────────────────────────────────────────

class OTEvent:
    """Represents a single decoded OT network event."""

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        event_type: str,
        data: dict,
    ):
        from datetime import datetime
        self.timestamp  = datetime.now().isoformat()
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.protocol   = protocol
        self.event_type = event_type
        self.data       = data

    def to_dict(self) -> dict:
        return {
            "timestamp":  self.timestamp,
            "src_ip":     self.src_ip,
            "dst_ip":     self.dst_ip,
            "protocol":   self.protocol,
            "event_type": self.event_type,
            **self.data,
        }

    def __repr__(self):
        return (
            f"OTEvent({self.protocol} | {self.src_ip} -> {self.dst_ip} "
            f"| {self.event_type})"
        )


# ─────────────────────────────────────────────────────────
# Pyshark Capture Engine
# ─────────────────────────────────────────────────────────

class PysharkCapture:
    """
    Passive OT network capture engine using pyshark.LiveCapture.

    Parameters
    ----------
    interface : str
        Network interface to sniff on.  For production use, this should be
        a SPAN / mirror port with no IP address assigned.
    event_queue : Queue
        Thread-safe queue where decoded OTEvent objects are placed.
    bpf_filter : str, optional
        Berkeley Packet Filter expression.  Defaults to covering Modbus TCP,
        EtherNet/IP, and BACnet/IP.

    Example
    -------
    >>> cap = PysharkCapture("eth1", event_queue)
    >>> cap.start()   # blocking — run in a thread
    """

    def __init__(
        self,
        interface: str,
        event_queue: Queue,
        bpf_filter: str = DEFAULT_BPF_FILTER,
    ):
        self.interface   = interface
        self.event_queue = event_queue
        self.bpf_filter  = bpf_filter
        self.running     = False

        self._stats = {
            "packets_total":   0,
            "packets_modbus":  0,
            "packets_enip":    0,
            "packets_bacnet":  0,
            "packets_unknown": 0,
            "events_emitted":  0,
            "errors":          0,
        }

    # ── Public API ──────────────────────────────────────────

    def start(self) -> None:
        """
        Start passive capture (blocking).
        Call this inside a daemon thread so it doesn't block the main process.

        Raises
        ------
        ImportError
            If pyshark is not installed.
        RuntimeError
            If tshark binary is not found (Npcap / libpcap missing).
        """
        import pyshark  # Deferred import — fails loudly if not installed

        self.running = True

        logger.info("=" * 60)
        logger.info("  SecureBridge — Pyshark Passive Capture")
        logger.info(f"  Interface : {self.interface}")
        logger.info(f"  BPF filter: {self.bpf_filter}")
        logger.info("  Mode      : PASSIVE — zero TX, zero impact")
        logger.info("=" * 60)

        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            # use_json + include_raw give us raw bytes for protocol parsing
            use_json=True,
            include_raw=True,
        )

        logger.info("✅ pyshark.LiveCapture started — sniffing OT traffic")

        try:
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                try:
                    self._dispatch(packet)
                except Exception as exc:
                    self._stats["errors"] += 1
                    logger.debug(f"Packet dispatch error: {exc}")
        finally:
            capture.close()
            logger.info(f"Capture stopped. Stats: {self._stats}")

    def stop(self) -> None:
        """Signal the capture loop to stop after the next packet."""
        self.running = False
        logger.info("PysharkCapture stop requested")

    def get_stats(self) -> dict:
        """Return a snapshot of capture statistics."""
        return dict(self._stats)

    # ── Internal: dispatch ───────────────────────────────────

    def _dispatch(self, pkt) -> None:
        """Route a pyshark packet to the appropriate protocol parser."""
        self._stats["packets_total"] += 1

        # ── Modbus TCP (port 502) ──
        if self._is_tcp_port(pkt, MODBUS_PORT):
            self._stats["packets_modbus"] += 1
            event = self._parse_modbus(pkt)

        # ── EtherNet/IP (port 44818) ──
        elif self._is_tcp_port(pkt, ENIP_PORT):
            self._stats["packets_enip"] += 1
            event = self._parse_enip(pkt)

        # ── BACnet/IP (UDP port 47808) ──
        elif self._is_udp_port(pkt, BACNET_PORT):
            self._stats["packets_bacnet"] += 1
            event = self._parse_bacnet(pkt)

        else:
            self._stats["packets_unknown"] += 1
            return

        if event is not None:
            self._stats["events_emitted"] += 1
            self.event_queue.put(event)

    # ── Internal: helpers ────────────────────────────────────

    @staticmethod
    def _get_ip_pair(pkt) -> tuple[str, str]:
        """Extract (src_ip, dst_ip) from packet. Returns ('?','?') on failure."""
        try:
            return str(pkt.ip.src), str(pkt.ip.dst)
        except AttributeError:
            return "?", "?"

    @staticmethod
    def _is_tcp_port(pkt, port: int) -> bool:
        try:
            return (
                hasattr(pkt, "tcp")
                and (
                    int(pkt.tcp.dstport) == port
                    or int(pkt.tcp.srcport) == port
                )
            )
        except Exception:
            return False

    @staticmethod
    def _is_udp_port(pkt, port: int) -> bool:
        try:
            return (
                hasattr(pkt, "udp")
                and (
                    int(pkt.udp.dstport) == port
                    or int(pkt.udp.srcport) == port
                )
            )
        except Exception:
            return False

    # ── Protocol parsers ─────────────────────────────────────

    def _parse_modbus(self, pkt) -> Optional[OTEvent]:
        """
        Parse Modbus TCP Application Data Unit from a pyshark packet.

        Modbus TCP ADU structure (on top of TCP payload):
            [Transaction ID  2B]
            [Protocol ID     2B]  always 0x0000
            [Length          2B]
            [Unit ID         1B]
            [Function Code   1B]
            [Data           nB]
        """
        src_ip, dst_ip = self._get_ip_pair(pkt)

        # ── Strategy 1: use pyshark's built-in Modbus dissector ──
        if hasattr(pkt, "mbtcp"):
            try:
                func_code = int(pkt.mbtcp.func_code)
                func_name = MODBUS_FUNCTIONS.get(
                    func_code, f"Unknown (FC {func_code})"
                )
                unit_id = int(getattr(pkt.mbtcp, "unit_id", 0))

                # Register address (present for FC 1-6, 15, 16)
                reg_addr = None
                if func_code in [1, 2, 3, 4, 5, 6, 15, 16]:
                    try:
                        reg_addr = int(pkt.mbtcp.reference_num)
                    except AttributeError:
                        pass

                is_write = func_code in [5, 6, 15, 16]
                event_type = (
                    "MODBUS_WRITE"     if is_write
                    else "MODBUS_DISCOVERY" if func_code == 43
                    else "MODBUS_READ"
                )

                data = {
                    "unit_id":          unit_id,
                    "function_code":    func_code,
                    "function_name":    func_name,
                    "is_write":         is_write,
                    "payload_length":   int(getattr(pkt.mbtcp, "len", 0)),
                    "raw_size":         int(pkt.length) if hasattr(pkt, "length") else 0,
                    "capture_engine":   "pyshark",
                }
                if reg_addr is not None:
                    data["register_address"] = reg_addr

                logger.debug(
                    f"Modbus {event_type}: {src_ip} → {dst_ip} "
                    f"FC={func_code} ({func_name})"
                )
                return OTEvent(src_ip, dst_ip, "Modbus TCP", event_type, data)

            except Exception as exc:
                logger.debug(f"Modbus dissector parse error: {exc}")

        # ── Strategy 2: manual parse from raw TCP payload ──
        try:
            raw_payload = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
            return self._parse_modbus_raw(raw_payload, src_ip, dst_ip)
        except Exception:
            pass

        return None

    def _parse_modbus_raw(
        self, payload: bytes, src_ip: str, dst_ip: str
    ) -> Optional[OTEvent]:
        """
        Fallback: parse Modbus ADU from raw bytes.
        Mirrors the logic in monitor.py:parse_modbus_packet().
        """
        if len(payload) < 8:
            return None

        try:
            protocol_id   = struct.unpack(">H", payload[2:4])[0]
            if protocol_id != 0:          # Modbus protocol_id is always 0
                return None

            length        = struct.unpack(">H", payload[4:6])[0]
            unit_id       = payload[6]
            function_code = payload[7]
            func_name     = MODBUS_FUNCTIONS.get(
                function_code, f"Unknown (FC {function_code})"
            )

            data: dict = {
                "unit_id":          unit_id,
                "function_code":    function_code,
                "function_name":    func_name,
                "transaction_id":   struct.unpack(">H", payload[0:2])[0],
                "payload_length":   length,
                "is_write":         function_code in [5, 6, 15, 16],
                "raw_size":         len(payload),
                "capture_engine":   "pyshark_raw",
            }

            if function_code in [1, 2, 3, 4, 5, 6, 15, 16] and len(payload) >= 10:
                data["register_address"] = struct.unpack(">H", payload[8:10])[0]

            is_write   = function_code in [5, 6, 15, 16]
            event_type = (
                "MODBUS_WRITE"     if is_write
                else "MODBUS_DISCOVERY" if function_code == 43
                else "MODBUS_READ"
            )

            return OTEvent(src_ip, dst_ip, "Modbus TCP", event_type, data)

        except (struct.error, IndexError):
            return None

    def _parse_enip(self, pkt) -> Optional[OTEvent]:
        """
        Parse EtherNet/IP (CIP) traffic.
        EtherNet/IP is used by Rockwell / Allen-Bradley PLCs.

        We capture the encapsulation command to classify traffic
        (e.g. RegisterSession, SendRRData, SendUnitData).
        """
        src_ip, dst_ip = self._get_ip_pair(pkt)

        ENIP_COMMANDS = {
            0x0001: "ListServices",
            0x0004: "ListIdentity",
            0x0006: "ListInterfaces",
            0x0065: "RegisterSession",
            0x0066: "UnRegisterSession",
            0x006F: "SendRRData",        # Request/Response (explicit messaging)
            0x0070: "SendUnitData",      # Implicit / I/O messaging
        }

        try:
            # pyshark dissects EtherNet/IP as "enip"
            if hasattr(pkt, "enip"):
                cmd_val  = int(pkt.enip.command, 16)
                cmd_name = ENIP_COMMANDS.get(cmd_val, f"Cmd_0x{cmd_val:04X}")
                is_write = cmd_val in [0x006F, 0x0070]

                data = {
                    "enip_command":   cmd_name,
                    "enip_command_id": f"0x{cmd_val:04X}",
                    "session_handle": str(getattr(pkt.enip, "session", "?")),
                    "is_write":       is_write,
                    "raw_size":       int(pkt.length) if hasattr(pkt, "length") else 0,
                    "capture_engine": "pyshark",
                }

                event_type = "ENIP_WRITE" if is_write else "ENIP_READ"
                logger.debug(
                    f"EtherNet/IP {cmd_name}: {src_ip} → {dst_ip}"
                )
                return OTEvent(src_ip, dst_ip, "EtherNet/IP", event_type, data)

        except Exception as exc:
            logger.debug(f"EtherNet/IP parse error: {exc}")

        # Minimal fallback: log the packet with port info only
        return OTEvent(
            src_ip, dst_ip,
            "EtherNet/IP",
            "ENIP_TRAFFIC",
            {
                "is_write":       False,
                "raw_size":       int(pkt.length) if hasattr(pkt, "length") else 0,
                "capture_engine": "pyshark_fallback",
            },
        )

    def _parse_bacnet(self, pkt) -> Optional[OTEvent]:
        """
        Parse BACnet/IP traffic (UDP port 47808 / 0xBAC0).
        Common in building automation and some industrial HVAC systems.
        """
        src_ip, dst_ip = self._get_ip_pair(pkt)

        BACNET_SERVICES = {
            0:  "AcknowledgedAlarm",
            6:  "AtomicReadFile",
            7:  "AtomicWriteFile",
            12: "ReadProperty",
            14: "ReadPropertyMultiple",
            15: "WriteProperty",
            16: "WritePropertyMultiple",
            26: "WhoHas",
            28: "WhoIs",
        }

        try:
            if hasattr(pkt, "bacapp"):
                svc_choice = int(getattr(pkt.bacapp, "service_choice", -1))
                svc_name   = BACNET_SERVICES.get(
                    svc_choice, f"Service_{svc_choice}"
                )
                is_write   = svc_choice in [7, 15, 16]

                data = {
                    "bacnet_service":  svc_name,
                    "service_choice":  svc_choice,
                    "is_write":        is_write,
                    "raw_size":        int(pkt.length) if hasattr(pkt, "length") else 0,
                    "capture_engine":  "pyshark",
                }

                event_type = "BACNET_WRITE" if is_write else "BACNET_READ"
                logger.debug(f"BACnet {svc_name}: {src_ip} → {dst_ip}")
                return OTEvent(src_ip, dst_ip, "BACnet/IP", event_type, data)

        except Exception as exc:
            logger.debug(f"BACnet parse error: {exc}")

        return None


# ─────────────────────────────────────────────────────────
# Smoke-test / CLI helper
# ─────────────────────────────────────────────────────────

def _smoke_test():
    """
    Quick offline smoke test — validates import and class instantiation
    without needing an active network interface.

    Usage:
        python core/capture/pyshark_capture.py --test
    """
    print("\n------------------------------------------")
    print("  SecureBridge -- PysharkCapture smoke test")
    print("------------------------------------------")

    # 1. Check pyshark importable
    try:
        import pyshark
        try:
            from importlib.metadata import version as pkg_version
            ver = pkg_version("pyshark")
        except Exception:
            ver = "installed"
        print(f"  [OK] pyshark version : {ver}")
    except ImportError:
        print("  [FAIL] pyshark not installed — run: pip install pyshark")
        return False

    # 2. Check tshark binary
    import shutil
    tshark_path = shutil.which("tshark")
    if tshark_path:
        print(f"  [OK] tshark found     : {tshark_path}")
    else:
        print("  [WARN] tshark not in PATH")
        print("         Windows -> install Npcap from https://npcap.com")
        print("         Linux   -> sudo apt install tshark")

    # 3. Class instantiation
    from queue import Queue
    q = Queue()
    cap = PysharkCapture("lo", q)
    print(f"  [OK] PysharkCapture   : interface={cap.interface}")
    print(f"  [OK] BPF filter       : {cap.bpf_filter}")

    # 4. Modbus raw parser (no network needed)
    test_payload = bytes([
        0x00, 0x01,  # Transaction ID = 1
        0x00, 0x00,  # Protocol ID = 0 (Modbus)
        0x00, 0x06,  # Length = 6
        0x01,        # Unit ID = 1
        0x03,        # Function Code = 3 (Read Holding Registers)
        0x9C, 0x41,  # Register address = 40001
        0x00, 0x04,  # Quantity = 4
    ])
    event = cap._parse_modbus_raw(test_payload, "192.168.40.10", "192.168.10.100")
    if event and event.data["function_code"] == 3:
        print(f"  [OK] Modbus parser    : {event}")
    else:
        print("  [FAIL] Modbus raw parser returned unexpected result")
        return False

    print("\n  All checks passed [OK]")
    print("------------------------------------------\n")
    return True


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        success = _smoke_test()
        sys.exit(0 if success else 1)
    else:
        print("Usage: python pyshark_capture.py --test")
        print("       (LiveCapture is started from monitor.py)")
