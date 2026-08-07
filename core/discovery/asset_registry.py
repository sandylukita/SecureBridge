"""
SecureBridge — Passive OT Asset Discovery & Purdue Model Registry
Sandy Lukita | PT Optima Sarana Instrument

Performs passive device profiling & fingerprinting from captured network traffic
without active scanning (zero impact on OT infrastructure).
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class OTAsset:
    ip: str
    name: str
    asset_type: str            # PLC, SCADA Server, HMI Station, Rogue Device, Historian
    purdue_level: str          # Level 1, Level 2, Level 3, Level 3.5 (DMZ)
    unit_id: Optional[int] = None
    protocol: str = "Modbus TCP"
    vendor: str = "Generic OT"
    status: str = "ONLINE"       # ONLINE, WARNING, CRITICAL
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    event_count: int = 0
    max_score: float = 0.0
    active_threat: bool = False


class AssetRegistry:
    """
    Passive OT Asset Discovery Engine.
    Maps captured packets (src_ip, dst_ip, unit_id, protocol) into a Purdue Model Inventory.
    """

    def __init__(self):
        self.assets: Dict[str, OTAsset] = {}
        self._seed_known_assets()

    def _seed_known_assets(self):
        """Seed default baseline assets for OT network simulation"""
        defaults = [
            OTAsset(
                ip="192.168.40.10",
                name="PLC-01 (Turbine Control)",
                asset_type="PLC",
                purdue_level="Level 1 (Field Control)",
                unit_id=1,
                protocol="Modbus TCP",
                vendor="Schneider Electric / Modicon",
            ),
            OTAsset(
                ip="192.168.40.11",
                name="PLC-02 (Cooling Pump)",
                asset_type="PLC",
                purdue_level="Level 1 (Field Control)",
                unit_id=2,
                protocol="Modbus TCP",
                vendor="Rockwell / Allen-Bradley",
            ),
            OTAsset(
                ip="192.168.40.12",
                name="PLC-03 (Valve Actuator)",
                asset_type="PLC",
                purdue_level="Level 1 (Field Control)",
                unit_id=3,
                protocol="Modbus TCP",
                vendor="Siemens S7-1200",
            ),
            OTAsset(
                ip="192.168.20.5",
                name="SCADA-Master-01",
                asset_type="SCADA Server",
                purdue_level="Level 2 (Supervisory Control)",
                protocol="Modbus TCP / CIP",
                vendor="Wonderware / Aveva",
            ),
            OTAsset(
                ip="192.168.20.10",
                name="HMI-Operator-01",
                asset_type="HMI Station",
                purdue_level="Level 2 (Supervisory Control)",
                protocol="Modbus TCP",
                vendor="InduSoft Web Studio",
            ),
        ]
        for a in defaults:
            self.assets[a.ip] = a

    def process_event(self, event_data: dict):
        """Passively update or discover assets from captured event dict"""
        src_ip = event_data.get("src_ip")
        dst_ip = event_data.get("dst_ip")
        score = float(event_data.get("anomaly_score", 0.0))
        unit_id = event_data.get("unit_id")
        protocol = event_data.get("protocol", "Modbus TCP")

        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            if ip not in self.assets:
                # Auto-discover new asset based on IP subnet & traffic behavior
                self._discover_asset(ip, unit_id, protocol)
            
            asset = self.assets[ip]
            asset.event_count += 1
            asset.last_seen = datetime.now().isoformat()
            if score > asset.max_score:
                asset.max_score = score
            if score >= 75.0:
                asset.active_threat = True
                asset.status = "CRITICAL" if score >= 85 else "WARNING"

    def process_events(self, df):
        """Vectorized update of assets from a DataFrame of events"""
        import pandas as pd
        if df.empty:
            return
            
        src_ips = set(df["src_ip"].dropna().unique())
        dst_ips = set(df["dst_ip"].dropna().unique())
        all_ips = src_ips | dst_ips
        
        unknown_ips = all_ips - set(self.assets.keys())
        for ip in unknown_ips:
            mask = (df["src_ip"] == ip) | (df["dst_ip"] == ip)
            sub_df = df[mask]
            
            unit_id = None
            if "unit_id" in sub_df.columns:
                units = sub_df["unit_id"].dropna()
                if not units.empty:
                    unit_id = int(units.iloc[0])
                    
            protocol = "Modbus TCP"
            if "protocol" in sub_df.columns:
                protos = sub_df["protocol"].dropna()
                if not protos.empty:
                    protocol = str(protos.iloc[0])
                    
            self._discover_asset(ip, unit_id, protocol)
            
        src_counts = df["src_ip"].value_counts() if "src_ip" in df.columns else pd.Series()
        dst_counts = df["dst_ip"].value_counts() if "dst_ip" in df.columns else pd.Series()
        total_counts = src_counts.add(dst_counts, fill_value=0).astype(int)
        
        if "anomaly_score" in df.columns:
            src_max = df.groupby("src_ip")["anomaly_score"].max() if "src_ip" in df.columns else pd.Series()
            dst_max = df.groupby("dst_ip")["anomaly_score"].max() if "dst_ip" in df.columns else pd.Series()
            max_scores = pd.concat([src_max, dst_max], axis=1).max(axis=1)
        else:
            max_scores = pd.Series(0.0, index=total_counts.index)
            
        now_str = datetime.now().isoformat()
        
        for ip, count in total_counts.items():
            if ip in self.assets:
                asset = self.assets[ip]
                asset.event_count += count
                asset.last_seen = now_str
                
                score = float(max_scores.get(ip, 0.0))
                if score > asset.max_score:
                    asset.max_score = score
                if score >= 75.0:
                    asset.active_threat = True
                    asset.status = "CRITICAL" if score >= 85 else "WARNING"

    def _discover_asset(self, ip: str, unit_id: Optional[int], protocol: str):
        """Infer Purdue level and asset type from IP subnet & protocol profile"""
        parts = ip.split(".")
        subnet = parts[2] if len(parts) == 4 else "0"

        if subnet == "40" or unit_id in (1, 2, 3):
            purdue = "Level 1 (Field Control)"
            atype = "PLC / Controller"
            name = f"Discovered-PLC-{ip.split('.')[-1]}"
        elif subnet == "20":
            purdue = "Level 2 (Supervisory Control)"
            atype = "HMI / SCADA Workstation"
            name = f"Discovered-HMI-{ip.split('.')[-1]}"
        elif subnet == "10":
            purdue = "Level 3.5 (Industrial DMZ)"
            atype = "Rogue Host / Vendor Laptop"
            name = f"Rogue-Host-{ip.split('.')[-1]}"
        else:
            purdue = "External / Unknown"
            atype = "Unknown Device"
            name = f"Host-{ip}"

        self.assets[ip] = OTAsset(
            ip=ip,
            name=name,
            asset_type=atype,
            purdue_level=purdue,
            unit_id=unit_id,
            protocol=protocol,
            status="WARNING",
            active_threat=True
        )

    def get_topology_nodes_and_edges(self) -> dict:
        """Generate node and edge structure for Purdue topology rendering"""
        nodes = []
        edges = []

        purdue_y_map = {
            "Level 3.5 (Industrial DMZ)": 3,
            "Level 2 (Supervisory Control)": 2,
            "Level 1 (Field Control)": 1,
            "External / Unknown": 4
        }

        for ip, asset in self.assets.items():
            nodes.append({
                "id": ip,
                "label": f"{asset.name}\n({ip})",
                "level": asset.purdue_level,
                "y_rank": purdue_y_map.get(asset.purdue_level, 1),
                "type": asset.asset_type,
                "status": asset.status,
                "max_score": asset.max_score,
                "active_threat": asset.active_threat,
            })

        # Add logical communication edges
        for ip, asset in self.assets.items():
            if asset.purdue_level == "Level 1 (Field Control)":
                edges.append({
                    "from": "192.168.20.5",
                    "to": ip,
                    "label": "Modbus Polling (502)",
                    "threat": asset.active_threat
                })
            elif asset.purdue_level == "Level 3.5 (Industrial DMZ)":
                edges.append({
                    "from": ip,
                    "to": "192.168.40.10",
                    "label": "UNAUTHORIZED WRITE (FC6)",
                    "threat": True
                })

        return {"nodes": nodes, "edges": edges}
