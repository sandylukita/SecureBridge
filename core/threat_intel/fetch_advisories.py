"""
SecureBridge — CISA Advisory Pre-Fetch Script
Sandy Lukita | PT Optima Sarana Instrument

Populates local cache (data/threat_intel/cisa_cache.json) using EXCLUSIVELY
the 5 human-verified CISA advisories from CISA.gov provided by the user.

No LLM-generated or assumed advisories are used.
"""

import sys
import os
import json
import logging

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from core.threat_intel.feed_aggregator import ThreatIntelFeed, VENDOR_KEYWORDS

CACHE_PATH = os.path.join(_ROOT, "data", "threat_intel", "cisa_cache.json")


def write_human_verified_cisa_cache(cache_path: str):
    """
    Write EXCLUSIVELY the 5 human-verified CISA ICS Advisories from CISA.gov.
    """
    from datetime import datetime
    bundled = {
        "fetched_at": datetime.now().isoformat(),
        "source":     "CISA ICS-CERT (Human-Verified CISA.gov Data)",
        "source_url": "https://www.cisa.gov/news-events/ics-advisories",
        "total":      5,
        "advisories": [
            {
                "id":        "ICSA-23-227-01",
                "title":     "Schneider Electric EcoStruxure Control Expert and Modicon Controllers",
                "vendor":    "Schneider Electric",
                "cves":      ["CVE-2022-45789"],
                "cvss":      None,
                "published": "2023-08-15",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-23-227-01",
                "summary":   "Authentication bypass via Modbus capture-replay in EcoStruxure Control Expert and "
                             "Modicon M340, M580, Momentum, and MC80 controllers.",
            },
            {
                "id":        "ICSA-25-035-04",
                "title":     "Schneider Electric Modicon M580 PLCs, BMENOR2200H, EVLink Pro AC",
                "vendor":    "Schneider Electric",
                "cves":      ["CVE-2024-11425"],
                "cvss":      8.7,
                "published": "2025-02-04",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-25-035-04",
                "summary":   "Incorrect buffer size calculation allows DoS condition via specially crafted HTTPS packets "
                             "on Modicon M580 PLCs and BMENOR2200H communication modules.",
            },
            {
                "id":        "ICSA-22-090-05",
                "title":     "Rockwell Automation Logix Controllers (ControlLogix, CompactLogix, GuardLogix)",
                "vendor":    "Rockwell Automation",
                "cves":      ["CVE-2022-1161"],
                "cvss":      10.0,
                "published": "2022-03-31",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-22-090-05",
                "summary":   "CRITICAL (CVSS 10.0): Attacker can modify PLC executable program code without detection "
                             "because readable source logic and compiled bytecode are stored separately. Reported by Claroty.",
            },
            {
                "id":        "ICSA-24-284-01",
                "title":     "Siemens SIMATIC S7-1500 and S7-1200 CPUs Open Redirect",
                "vendor":    "Siemens",
                "cves":      ["CVE-2024-46886"],
                "cvss":      5.1,
                "published": "2024-10-10",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-284-01",
                "summary":   "Open redirect vulnerability in integrated web server of Siemens SIMATIC S7-1500 and S7-1200 CPUs.",
            },
            {
                "id":        "ICSA-24-284-10",
                "title":     "Siemens SIMATIC S7-1500 CPUs Information Disclosure",
                "vendor":    "Siemens",
                "cves":      ["CVE-2024-46887"],
                "cvss":      6.9,
                "published": "2024-10-10",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-284-10",
                "summary":   "Unauthenticated attacker can view CPU cycle time and communication load telemetry on SIMATIC S7-1500 CPUs.",
            },
        ]
    }
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(bundled, f, indent=2, ensure_ascii=False)
    return bundled


def main():
    print("=" * 60)
    print("  SecureBridge -- Human-Verified CISA Pre-Fetch")
    print("=" * 60)
    print(f"  Cache target : {CACHE_PATH}")
    print()

    print("  Writing 5 human-verified CISA.gov advisories...")
    bundled = write_human_verified_cisa_cache(CACHE_PATH)
    advisories = bundled["advisories"]
    print(f"  [OK] Wrote {len(advisories)} human-verified advisories to cache.")

    print()
    print("  Vendor breakdown:")

    feed = ThreatIntelFeed(cache_path=CACHE_PATH, mode="lab")
    for vendor in VENDOR_KEYWORDS.keys():
        matched = feed.get_advisories_for_vendor(vendor)
        if matched:
            print(f"    {vendor:35s}: {len(matched):3d} advisories")

    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)

    print()
    print(f"  Synced at    : {meta.get('fetched_at', 'unknown')}")
    print(f"  Total cached : {meta.get('total', len(advisories))}")
    print(f"  Cache file   : {CACHE_PATH}")
    print()
    print("  Cache updated exclusively with human-verified CISA data.")


if __name__ == "__main__":
    main()
