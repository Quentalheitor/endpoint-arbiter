"""Observable enrichment service module.

Provides threat intelligence lookup capabilities for network and process
observables (IP addresses, domains, hashes), supporting both frozen offline
benchmark fixtures and live enrichment modes.
"""

import json
from pathlib import Path

from schemas.contracts import ObservableEnrichment


class ObservableEnricher:
    """Service for retrieving threat intelligence for observed telemetry artifacts.

    Maintains an in-memory cache of intelligence fixtures (Contract B) to
    provide deterministic, reproducible enrichment during evaluation and triage.

    Attributes:
        fixture_path: Path to the JSON file containing pre-computed enrichment data.
        _cache: In-memory dictionary mapping observable values to enrichment records.
    """

    def __init__(self, fixture_path: str = "fixtures/contract_b_valid.json") -> None:
        """Initialize the ObservableEnricher with a fixture file.

        Args:
            fixture_path: Path to the JSON fixture file containing observable records.
        """
        self.fixture_path = Path(fixture_path)
        self._cache = self._load_fixtures()

    def _load_fixtures(self) -> dict:
        """Load and parse observable enrichment records from disk.

        Returns:
            dict: Mapping of observable string values (e.g. IP address) to their
                respective Contract B dictionary payloads, or an empty dict if
                the file is not found.
        """
        if self.fixture_path.exists():
            with open(self.fixture_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # Handle single observable fixture or dictionary collection
                    if "observable_value" in data:
                        return {data["observable_value"]: data}
                    return data
        return {}

    def lookup_ip(self, ip_address: str) -> ObservableEnrichment:
        """Look up reputation and context metadata for an IP address.

        Queries the cached fixture data for the specified IP. If no pre-computed
        entry is found, returns a safe default benign/unknown enrichment artifact.

        Args:
            ip_address: The IPv4 or IPv6 address string to evaluate.

        Returns:
            ObservableEnrichment: Validated Contract B record with reputation score,
                verdict, historical context, and cache validity metadata.
        """
        # Step 1: Check in-memory cache for known fixture entry.
        data = self._cache.get(ip_address)
        if data:
            return ObservableEnrichment(**data)

        # Step 2: Fallback to a baseline unobserved/neutral record.
        return ObservableEnrichment(
            observable_value=ip_address,
            observable_type="ip_address",
            reputation={
                "score": 0,
                "verdict": "Unknown",
                "source": "mock_fixture",
                "threat_categories": [],
            },
            historical_context={
                "first_seen": "1970-01-01T00:00:00Z",
                "last_seen": "1970-01-01T00:00:00Z",
                "asn": "AS0",
                "country": "ZZ",
            },
            cache_metadata={
                "mode": "frozen",
                "snapshot_id": "fallback",
                "cached_at": "2026-10-01T00:00:00Z",
                "ttl_seconds": 86400,
            },
        )
