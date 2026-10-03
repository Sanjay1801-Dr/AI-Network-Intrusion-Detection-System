"""Threat Intelligence provider interface and local demonstration service (Phase 13).

Provides extensible threat reputation lookup architecture.
Strict Design Guarantee:
- Marked clearly as LOCAL_DEMO_INTELLIGENCE for local demo entries.
- Validates all IP addresses defensively using standard ipaddress library.
- No commercial or external paid API dependencies required.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any, Dict, List, Optional

from backend.app.core.errors import ValidationException

logger = logging.getLogger("nids.services.threat_intelligence")

SOURCE_LABEL = "LOCAL_DEMO_INTELLIGENCE"

# Curated demonstration database of known testing / research IP telemetry
DEMO_IP_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "192.0.2.1": {
        "reputation": "MALICIOUS",
        "confidence": 0.95,
        "categories": ["DoS", "SYN_Flood"],
        "first_seen": "2026-01-10T12:00:00Z",
        "last_seen": "2026-10-01T08:30:00Z",
        "notes": "Simulated high-volume SYN flood source from CIC-IDS test suite",
    },
    "198.51.100.42": {
        "reputation": "MALICIOUS",
        "confidence": 0.88,
        "categories": ["Port Scan", "Reconnaissance"],
        "first_seen": "2026-02-14T09:15:00Z",
        "last_seen": "2026-09-28T14:20:00Z",
        "notes": "Demonstration reconnaissance host conducting horizontal TCP sweeps",
    },
    "203.0.113.88": {
        "reputation": "SUSPICIOUS",
        "confidence": 0.72,
        "categories": ["Botnet", "C2_Beacon"],
        "first_seen": "2026-03-20T16:45:00Z",
        "last_seen": "2026-09-30T22:10:00Z",
        "notes": "Suspected command-and-control periodic beaconing endpoint",
    },
    "192.168.1.105": {
        "reputation": "MALICIOUS",
        "confidence": 0.91,
        "categories": ["Infiltration", "Lateral_Movement"],
        "first_seen": "2026-04-05T11:00:00Z",
        "last_seen": "2026-10-02T19:05:00Z",
        "notes": "Internal compromised lab node exhibiting anomalous lateral traffic",
    },
    "10.0.0.1": {
        "reputation": "BENIGN",
        "confidence": 0.99,
        "categories": ["Trusted_Gateway", "Internal_Infrastructure"],
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-10-04T00:00:00Z",
        "notes": "Default internal network gateway core switch",
    },
    "127.0.0.1": {
        "reputation": "BENIGN",
        "confidence": 1.0,
        "categories": ["Loopback", "Localhost"],
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-10-04T00:00:00Z",
        "notes": "Standard host loopback diagnostic interface",
    },
}

DEMO_DOMAIN_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "malicious-c2-demo.test": {
        "reputation": "MALICIOUS",
        "confidence": 0.92,
        "categories": ["Command_and_Control"],
        "first_seen": "2026-01-15T00:00:00Z",
        "last_seen": "2026-09-25T00:00:00Z",
        "notes": "Demonstration C2 domain reference",
    }
}

DEMO_HASH_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "reputation": "BENIGN",
        "confidence": 1.0,
        "categories": ["Empty_File"],
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-10-04T00:00:00Z",
        "notes": "SHA-256 hash of empty content",
    }
}


class ThreatIntelligenceProvider(ABC):
    """Abstract interface defining threat intelligence lookups."""

    @abstractmethod
    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up reputation and metadata for an IP address."""
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Look up reputation and metadata for a domain."""
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Look up reputation and metadata for a cryptographic payload hash."""
        pass


class LocalThreatIntelligenceProvider(ThreatIntelligenceProvider):
    """Local, offline reference threat intelligence provider for testing and demonstration."""

    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        return DEMO_IP_INTELLIGENCE.get(ip_address)

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return DEMO_DOMAIN_INTELLIGENCE.get(domain.lower().strip())

    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return DEMO_HASH_INTELLIGENCE.get(file_hash.lower().strip())


class ThreatIntelligenceService:
    """Domain service managing reputation enrichment queries."""

    _provider: ThreatIntelligenceProvider = LocalThreatIntelligenceProvider()

    @classmethod
    def set_provider(cls, provider: ThreatIntelligenceProvider) -> None:
        """Allow injecting alternative providers (e.g. for testing)."""
        cls._provider = provider

    @classmethod
    def validate_ip_address(cls, ip_str: str) -> str:
        """Validate that input string is a legitimate IPv4 or IPv6 address.

        Raises:
            ValidationException if invalid format.
        """
        clean_ip = ip_str.strip()
        try:
            parsed = ipaddress.ip_address(clean_ip)
            return str(parsed)
        except ValueError:
            raise ValidationException(
                message=f"Invalid IP address format: '{ip_str}'. Must be a valid IPv4 or IPv6 address.",
                details={"field": "ip_address", "value": ip_str},
            )

    @classmethod
    def lookup_ip(cls, raw_ip: str) -> Dict[str, Any]:
        """Look up IP threat intelligence with defensive validation and safe fallback."""
        clean_ip = cls.validate_ip_address(raw_ip)
        result = cls._provider.lookup_ip(clean_ip)

        if result:
            return {
                "ip": clean_ip,
                "found": True,
                "source": SOURCE_LABEL,
                "reputation": result.get("reputation", "UNKNOWN"),
                "confidence": float(result.get("confidence", 0.0)),
                "categories": list(result.get("categories", [])),
                "first_seen": result.get("first_seen"),
                "last_seen": result.get("last_seen"),
                "notes": result.get("notes"),
            }

        return {
            "ip": clean_ip,
            "found": False,
            "source": SOURCE_LABEL,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "categories": [],
            "first_seen": None,
            "last_seen": None,
            "notes": "No reputation record found in local demonstration threat intelligence base.",
        }
