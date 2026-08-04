"""
SecureBridge — OT Threat Intelligence Feed Aggregator
Sandy Lukita | PT Optima Sarana Instrument

Aggregates threat intelligence from FREE, PUBLIC sources:
  - CISA ICS-CERT Advisories (official US government feed)
  - Shodan exposure check (DISABLED in air-gapped mode by design)

Design principles:
  1. Cache-first: dashboard always reads from local cache, never blocks on API
  2. "Code IS the documentation": air-gapped enforcement is in the code, not docs
  3. Honest positioning: we aggregate public intel, we don't do threat research
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Optional
import urllib.request
import xml.etree.ElementTree as ET

logger = logging.getLogger("SecureBridge.ThreatIntel")

# ─────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────

class FeatureDisabledError(Exception):
    """Raised when a feature is explicitly disabled for the current deployment mode."""
    pass


# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────

CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"

# CISA advisory keyword → vendor mapping (lowercase match)
VENDOR_KEYWORDS = {
    "Schneider Electric": ["schneider", "modicon", "ecostruxure", "unity pro", "somachine"],
    "Rockwell Automation": ["rockwell", "allen-bradley", "allen bradley", "factorytalk", "logix"],
    "Siemens": ["siemens", "simatic", "s7-", "wincc", "tia portal", "scalance"],
    "Wonderware / Aveva": ["wonderware", "aveva", "intouch", "historian"],
    "Yokogawa": ["yokogawa", "centum", "prosafe"],
    "Honeywell": ["honeywell", "experion", "pks"],
    "ABB": ["abb", "symphony", "800xa"],
}

DEFAULT_CACHE_PATH = "data/threat_intel/cisa_cache.json"
CACHE_TTL_HOURS    = 24   # refresh cache if older than this


# ─────────────────────────────────────────────────────────
# Cache helpers
# ─────────────────────────────────────────────────────────

def _load_cache(cache_path: str) -> Optional[dict]:
    """Load JSON cache from disk. Returns None if missing or corrupt."""
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning(f"ThreatIntel: cache load failed ({exc})")
        return None


def _save_cache(data: dict, cache_path: str) -> None:
    """Persist JSON cache to disk."""
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"ThreatIntel: cache saved → {cache_path}")
    except Exception as exc:
        logger.warning(f"ThreatIntel: cache save failed ({exc})")


def _cache_is_fresh(cache: dict, ttl_hours: int = CACHE_TTL_HOURS) -> bool:
    """Return True if cache was fetched within TTL window."""
    fetched_at = cache.get("fetched_at")
    if not fetched_at:
        return False
    try:
        ts = datetime.fromisoformat(fetched_at)
        return (datetime.now() - ts) < timedelta(hours=ttl_hours)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────
# CISA ICS-CERT Feed Parser
# ─────────────────────────────────────────────────────────

def _parse_cisa_rss(xml_text: str) -> list:
    """
    Parse CISA ICS advisory RSS feed.
    Returns list of advisory dicts.
    """
    advisories = []
    try:
        root = ET.fromstring(xml_text)
        channel = root.find("channel")
        if channel is None:
            return []

        for item in channel.findall("item"):
            title       = (item.findtext("title") or "").strip()
            link        = (item.findtext("link") or "").strip()
            pub_date    = (item.findtext("pubDate") or "").strip()
            description = (item.findtext("description") or "").strip()

            # Detect vendor from title/description
            vendor_match = _detect_vendor(title + " " + description)

            # Extract CVE references
            import re
            cves = re.findall(r"CVE-\d{4}-\d+", title + " " + description)

            # Extract CVSS score if mentioned
            cvss_match = re.search(r"CVSS[^\d]*(\d+\.?\d*)", description)
            cvss_score = float(cvss_match.group(1)) if cvss_match else None

            # Extract advisory ID (ICSA-XX-XXX-XX pattern)
            id_match = re.search(r"ICS[A-Z]?-\d{2}-\d{3}-\d{2}", title + " " + link)
            advisory_id = id_match.group(0) if id_match else link.split("/")[-1]

            advisories.append({
                "id":          advisory_id,
                "title":       title,
                "vendor":      vendor_match,
                "cves":        list(set(cves)),
                "cvss":        cvss_score,
                "published":   pub_date,
                "url":         link,
                "summary":     description[:300] + ("..." if len(description) > 300 else ""),
            })
    except Exception as exc:
        logger.warning(f"ThreatIntel: CISA RSS parse error ({exc})")

    return advisories


def _detect_vendor(text: str) -> str:
    """Match advisory text against known OT vendor keywords."""
    text_lower = text.lower()
    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return vendor
    return "Generic / Unknown"


# ─────────────────────────────────────────────────────────
# Main ThreatIntelFeed class
# ─────────────────────────────────────────────────────────

class ThreatIntelFeed:
    """
    Public OT threat intelligence feed aggregator.

    Sources used:
      - CISA ICS-CERT Advisories (official US government, free, public)
      - Shodan OT exposure check (opt-in, disabled in air-gapped mode)

    This class does NOT perform original threat research.
    It aggregates, caches, and contextualizes publicly available intelligence
    against the assets detected by SecureBridge's asset_registry.
    """

    def __init__(
        self,
        cache_path: str = DEFAULT_CACHE_PATH,
        mode: str = "lab",            # "lab", "auto", "air-gapped"
    ):
        self.cache_path = cache_path
        self.mode       = mode
        self._cache     = _load_cache(cache_path) or {}

    # ── CISA ──────────────────────────────────────────────

    def fetch_cisa_advisories(self, force: bool = False) -> list:
        """
        Fetch CISA ICS-CERT advisories.
        Returns from local cache if fresh; fetches live only if stale.

        In air-gapped mode: always returns from cache (no external call).
        """
        # In air-gapped mode, always serve from cache — no external call ever
        if self.mode == "air-gapped":
            logger.info("ThreatIntel: air-gapped mode — serving CISA from local cache")
            return self._cache.get("advisories", [])

        # Return fresh cache if available
        if not force and self._cache and _cache_is_fresh(self._cache):
            logger.info(
                f"ThreatIntel: cache fresh "
                f"(fetched {self._cache.get('fetched_at', 'unknown')})"
            )
            return self._cache.get("advisories", [])

        # Live fetch
        try:
            logger.info(f"ThreatIntel: fetching CISA ICS advisories → {CISA_RSS_URL}")
            req  = urllib.request.Request(
                CISA_RSS_URL,
                headers={
                    "User-Agent": (
                        "SecureBridge/1.0 (OT Threat Intelligence Feed Aggregator; "
                        "Contact: security-team@optimasarana.com)"
                    ),
                    "Accept": "application/rss+xml, application/xml, text/xml, */*",
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                xml_text = resp.read().decode("utf-8", errors="replace")

            advisories = _parse_cisa_rss(xml_text)
            self._cache = {
                "fetched_at":  datetime.now().isoformat(),
                "source":      "CISA ICS-CERT",
                "source_url":  CISA_RSS_URL,
                "total":       len(advisories),
                "advisories":  advisories,
            }
            _save_cache(self._cache, self.cache_path)
            logger.info(f"ThreatIntel: fetched {len(advisories)} CISA advisories")
            return advisories

        except Exception as exc:
            logger.warning(
                f"ThreatIntel: CISA fetch failed ({exc}) — falling back to cache"
            )
            return self._cache.get("advisories", [])

    def get_advisories_for_vendor(self, vendor: str) -> list:
        """Return cached CISA advisories matching the given vendor string."""
        advisories = self._cache.get("advisories", [])
        if not advisories:
            return []
        vendor_lower = vendor.lower()
        # Match against VENDOR_KEYWORDS for the given vendor string
        matched_keywords = []
        for v, kws in VENDOR_KEYWORDS.items():
            if any(kw in vendor_lower for kw in kws) or vendor_lower in v.lower():
                matched_keywords = kws
                break
        if not matched_keywords:
            # fallback: direct substring match
            return [a for a in advisories if vendor_lower in a.get("vendor", "").lower()]

        return [
            a for a in advisories
            if any(kw in a.get("vendor", "").lower() for kw in matched_keywords)
            or any(kw in a.get("title", "").lower() for kw in matched_keywords)
        ]

    def get_asset_intel(self, ip: str, vendor: str) -> dict:
        """
        Return aggregated threat intel context for a specific asset.
        Designed to be called by the dashboard for the asset detail panel.
        """
        advisories = self.get_advisories_for_vendor(vendor)
        critical   = [a for a in advisories if (a.get("cvss") or 0) >= 9.0]
        high       = [a for a in advisories if 7.0 <= (a.get("cvss") or 0) < 9.0]

        return {
            "vendor":              vendor,
            "total_advisories":    len(advisories),
            "critical_advisories": len(critical),
            "high_advisories":     len(high),
            "latest_advisories":   advisories[:5],    # top 5 most recent
            "fetched_at":          self._cache.get("fetched_at", "Never"),
            "source":              "CISA ICS-CERT (Public)",
        }

    def get_cache_metadata(self) -> dict:
        """Return cache status info for UI display."""
        return {
            "fetched_at": self._cache.get("fetched_at", None),
            "total":      self._cache.get("total", 0),
            "source":     self._cache.get("source", "CISA ICS-CERT"),
            "is_fresh":   _cache_is_fresh(self._cache),
        }

    # ── Shodan (DISABLED in air-gapped mode) ──────────────

    def shodan_exposure_check(self, subnet: str) -> dict:
        """
        Check OT device exposure via Shodan API.

        DISABLED in air-gapped mode — querying an external API
        with client subnet information violates the zero-egress
        principle of air-gapped deployment.

        This is enforced in code, not just documented in README,
        so that it can be independently verified by any reviewer.
        """
        if self.mode == "air-gapped":
            raise FeatureDisabledError(
                "Shodan exposure check is disabled in air-gapped mode. "
                "Querying Shodan with client subnet data would violate "
                "the zero-egress principle of this deployment. "
                "Enable only in 'lab' or 'auto' mode."
            )
        # Placeholder — live Shodan integration is a roadmap item
        # Requires: pip install shodan + SHODAN_API_KEY env var
        raise NotImplementedError(
            "Shodan integration is on the roadmap. "
            "Current scope: CISA advisory feed only."
        )
