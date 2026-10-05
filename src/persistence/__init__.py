"""Persistence package for telemetry audit storage.

Contains storage managers utilizing DuckDB to maintain append-only audit
records of incoming events and synthesized triage artifacts.
"""

from src.persistence.storage import StorageManager

__all__ = ["StorageManager"]
