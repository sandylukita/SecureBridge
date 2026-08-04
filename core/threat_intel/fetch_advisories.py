"""
SecureBridge — CISA Advisory Pre-Fetch Script
Run this BEFORE a demo or interview to populate the local cache.

Usage:
    python core/threat_intel/fetch_advisories.py

This script:
  1. Attempts live fetch from CISA ICS-CERT
  2. On failure, falls back to bundled representative advisories
  3. Saves to data/threat_intel/cisa_cache.json with fetched_at timestamp
  4. Dashboard will use this cached file -- no live API calls during demo

Run this once before each demo session.
Demo reliability does NOT depend on internet connection after this runs.
"""

import sys
import os
import json
import logging

# Resolve project root
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from core.threat_intel.feed_aggregator import ThreatIntelFeed, VENDOR_KEYWORDS

CACHE_PATH = os.path.join(_ROOT, "data", "threat_intel", "cisa_cache.json")


def _write_bundled_cache(cache_path: str):
    """
    Write a bundled static cache with real-world-representative
    CISA ICS advisories. Used as fallback when live fetch fails.

    These are based on actual CISA advisory patterns for the three
    vendors in SecureBridge's default asset_registry:
    Schneider Electric, Rockwell Automation, Siemens.
    """
    from datetime import datetime
    bundled = {
        "fetched_at": datetime.now().isoformat(),
        "source":     "CISA ICS-CERT (bundled demo cache)",
        "source_url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        "total":      6,
        "advisories": [
            {
                "id":        "ICSA-24-102-01",
                "title":     "Schneider Electric EcoStruxure Power Monitoring Expert",
                "vendor":    "Schneider Electric",
                "cves":      ["CVE-2024-2229", "CVE-2024-2230"],
                "cvss":      9.8,
                "published": "2024-04-11",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-102-01",
                "summary":   "Successful exploitation could allow remote code execution or DoS. "
                             "Affects EcoStruxure Power Monitoring Expert versions prior to 2021 SP1.",
            },
            {
                "id":        "ICSA-24-074-02",
                "title":     "Schneider Electric Modicon M340 PLC Authentication Bypass",
                "vendor":    "Schneider Electric",
                "cves":      ["CVE-2024-2400"],
                "cvss":      8.1,
                "published": "2024-03-14",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-074-02",
                "summary":   "Modicon M340, Momentum, and MC80 PLCs contain authentication bypass "
                             "via Modbus protocol on port 502. Attacker with network access can gain "
                             "unauthorized write access to PLC registers.",
            },
            {
                "id":        "ICSA-24-107-01",
                "title":     "Rockwell Automation FactoryTalk View SE RCE",
                "vendor":    "Rockwell Automation",
                "cves":      ["CVE-2024-21915"],
                "cvss":      9.0,
                "published": "2024-04-16",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-107-01",
                "summary":   "FactoryTalk View SE is vulnerable to RCE. A threat actor with network access "
                             "could execute arbitrary code on HMI workstations at Purdue Level 2.",
            },
            {
                "id":        "ICSA-24-016-04",
                "title":     "Rockwell Allen-Bradley 1756 ControlLogix Vulnerabilities",
                "vendor":    "Rockwell Automation",
                "cves":      ["CVE-2024-21917", "CVE-2024-21918"],
                "cvss":      8.5,
                "published": "2024-01-16",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-016-04",
                "summary":   "Multiple vulnerabilities in Allen-Bradley 1756 ControlLogix allow authenticated "
                             "user to execute malicious code on the device via EtherNet/IP protocol.",
            },
            {
                "id":        "ICSA-24-130-01",
                "title":     "Siemens SIMATIC S7-1200 and S7-1500 CPU Denial of Service",
                "vendor":    "Siemens",
                "cves":      ["CVE-2024-30321"],
                "cvss":      7.5,
                "published": "2024-05-09",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-130-01",
                "summary":   "Siemens S7-1200 and S7-1500 PLCs contain improper input validation. "
                             "Exploitation causes denial-of-service via crafted S7 protocol packets.",
            },
            {
                "id":        "ICSA-24-193-03",
                "title":     "Siemens SCALANCE Network Devices Path Traversal",
                "vendor":    "Siemens",
                "cves":      ["CVE-2024-34057"],
                "cvss":      8.2,
                "published": "2024-07-11",
                "url":       "https://www.cisa.gov/news-events/ics-advisories/icsa-24-193-03",
                "summary":   "Siemens SCALANCE industrial switches contain path traversal allowing "
                             "authenticated remote attacker to read arbitrary files from device filesystem.",
            },
        ]
    }
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(bundled, f, indent=2, ensure_ascii=False)
    return bundled


def main():
    print("=" * 60)
    print("  SecureBridge -- CISA ICS-CERT Pre-Fetch")
    print("=" * 60)
    print(f"  Cache target : {CACHE_PATH}")
    print()

    feed = ThreatIntelFeed(cache_path=CACHE_PATH, mode="lab")

    print("  Attempting live fetch from CISA ICS-CERT...")
    advisories = feed.fetch_cisa_advisories(force=True)

    if not advisories:
        print("  [!] Live fetch failed -- writing bundled demo cache.")
        bundled = _write_bundled_cache(CACHE_PATH)
        advisories = bundled["advisories"]
        print(f"  [OK] Bundled cache written ({len(advisories)} advisories).")
    else:
        print(f"  [OK] Live fetch successful: {len(advisories)} advisories")

    print()
    print("  Vendor breakdown:")

    # Reload feed from saved cache to use get_advisories_for_vendor correctly
    feed2 = ThreatIntelFeed(cache_path=CACHE_PATH, mode="lab")
    for vendor in VENDOR_KEYWORDS.keys():
        matched = feed2.get_advisories_for_vendor(vendor)
        if matched:
            print(f"    {vendor:35s}: {len(matched):3d} advisories")

    import json
    with open(CACHE_PATH, "r") as f:
        meta = json.load(f)

    print()
    print(f"  Synced at    : {meta.get('fetched_at', 'unknown')}")
    print(f"  Total cached : {meta.get('total', len(advisories))}")
    print(f"  Cache file   : {CACHE_PATH}")
    print()
    print("  Dashboard is ready for offline demo.")
    print("  Re-run this script before each demo session to refresh.")


if __name__ == "__main__":
    main()
