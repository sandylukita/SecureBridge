"""
SecureBridge Configuration Manager
Handles both live deployment and lab/demo modes
"""

import yaml
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CaptureConfig:
    interface: str = "eth0"
    target_network: str = "192.168.1.0/24"
    buffer_size: int = 65536
    timeout: int = 30


@dataclass
class DetectionConfig:
    model_path: str = "data/models/ot_model.pkl"
    anomaly_threshold: float = 60.0
    baseline_hours: int = 24
    retrain_interval_hours: int = 168  # weekly


@dataclass
class AlertConfig:
    email_enabled: bool = False
    email_from: str = ""
    email_to: List[str] = field(default_factory=list)
    email_smtp: str = "smtp.gmail.com"
    email_port: int = 587
    email_password: str = ""
    telegram_enabled: bool = False
    telegram_token: str = ""
    telegram_chat_id: str = ""
    min_severity: str = "HIGH"


@dataclass
class DashboardConfig:
    host: str = "0.0.0.0"
    port: int = 8501
    refresh_seconds: int = 10
    max_alerts: int = 100


@dataclass
class ComplianceConfig:
    client_name: str = "Client"
    consultant_name: str = "Sandy Lukita"
    consulting_firm: str = "PT Optima Sarana Instrument"
    report_output_dir: str = "data/reports"


@dataclass
class SecureBridgeConfig:
    mode: str = "lab"          # "live" or "lab"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    log_dir: str = "data/logs"
    data_dir: str = "data"


def load_config(config_path: str = "config/active.yaml") -> SecureBridgeConfig:
    """Load configuration from YAML file"""

    if not os.path.exists(config_path):
        print(f"⚠️  Config not found at {config_path}")
        print("   Using default lab configuration")
        return SecureBridgeConfig()

    with open(config_path, 'r') as f:
        raw = yaml.safe_load(f)

    config = SecureBridgeConfig()
    config.mode = raw.get("mode", "lab")

    if "capture" in raw:
        c = raw["capture"]
        config.capture = CaptureConfig(
            interface=c.get("interface", "eth0"),
            target_network=c.get("target_network", "192.168.1.0/24"),
            buffer_size=c.get("buffer_size", 65536),
        )

    if "detection" in raw:
        d = raw["detection"]
        config.detection = DetectionConfig(
            anomaly_threshold=d.get("anomaly_threshold", 60.0),
            baseline_hours=d.get("baseline_hours", 24),
        )

    if "alerts" in raw:
        a = raw["alerts"]
        config.alerts = AlertConfig(
            email_enabled=a.get("email_enabled", False),
            email_from=a.get("email_from", ""),
            email_to=a.get("email_to", []),
            telegram_enabled=a.get("telegram_enabled", False),
            telegram_token=a.get("telegram_token", ""),
            telegram_chat_id=a.get("telegram_chat_id", ""),
            min_severity=a.get("min_severity", "HIGH"),
        )

    if "compliance" in raw:
        comp = raw["compliance"]
        config.compliance = ComplianceConfig(
            client_name=comp.get("client_name", "Client"),
            consultant_name=comp.get("consultant_name", "Sandy Lukita"),
            consulting_firm=comp.get("consulting_firm", "PT Optima Sarana Instrument"),
        )

    return config


def save_config(config: SecureBridgeConfig, path: str):
    """Save config to YAML"""
    data = {
        "mode": config.mode,
        "capture": {
            "interface": config.capture.interface,
            "target_network": config.capture.target_network,
        },
        "detection": {
            "anomaly_threshold": config.detection.anomaly_threshold,
            "baseline_hours": config.detection.baseline_hours,
        },
        "alerts": {
            "email_enabled": config.alerts.email_enabled,
            "telegram_enabled": config.alerts.telegram_enabled,
            "min_severity": config.alerts.min_severity,
        },
        "compliance": {
            "client_name": config.compliance.client_name,
        }
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)
    print(f"Config saved to {path}")
