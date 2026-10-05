"""Storage and persistence manager using DuckDB.

Provides persistent audit storage for raw incoming endpoint telemetry events
(Contract A) and final immutable triage artifacts (Contract C).
"""

import json
import os
from pathlib import Path

import duckdb

from schemas.contracts import NormalizedInputTelemetry, TriageArtifact


class StorageManager:
    """Manages DuckDB persistence for telemetry events and triage artifacts.

    Maintains relational tables for quick audit lookups and stores the complete
    raw JSON models to support reproducibility and post-incident analysis.

    Attributes:
        conn: Open DuckDB connection instance.
    """

    def __init__(self, db_path: str | None = None) -> None:
        """Initialize the storage manager and connect to DuckDB.

        Args:
            db_path: Path to DuckDB database file, ':memory:' for in-memory DB,
                or None to read from the ARBITER_DB_PATH environment variable.
        """
        if db_path is None:
            db_path = os.getenv("ARBITER_DB_PATH", "data/arbiter.duckdb")
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize required database schemas and tables if they do not exist."""
        # Events table: stores normalized input telemetry (Contract A)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id VARCHAR PRIMARY KEY,
                event_hash VARCHAR,
                timestamp_utc VARCHAR,
                raw_json VARCHAR
            );
        """)
        # Triage artifacts table: stores immutable decision artifacts (Contract C)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS triage_artifacts (
                triage_id VARCHAR PRIMARY KEY,
                reference_event_id VARCHAR,
                verdict VARCHAR,
                risk_score INTEGER,
                confidence_score INTEGER,
                artifact_json VARCHAR,
                created_at VARCHAR
            );
        """)

    def save_event(self, event: NormalizedInputTelemetry) -> None:
        """Persist a normalized input telemetry event into the database.

        Args:
            event: The validated Contract A telemetry event.
        """
        self.conn.execute(
            "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?)",
            [
                event.event_id,
                event.event_hash,
                event.timestamp_utc,
                event.model_dump_json(),
            ],
        )

    def save_artifact(self, artifact: TriageArtifact) -> None:
        """Persist an immutable triage artifact into the database.

        Args:
            artifact: The validated Contract C triage artifact.
        """
        risk_score = (
            artifact.metrics.risk_score
            if hasattr(artifact.metrics, "risk_score")
            else artifact.metrics["risk_score"]
        )
        confidence_score = (
            artifact.metrics.confidence_score
            if hasattr(artifact.metrics, "confidence_score")
            else artifact.metrics["confidence_score"]
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO triage_artifacts VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                artifact.triage_id,
                artifact.reference_event_id,
                artifact.verdict,
                risk_score,
                confidence_score,
                artifact.model_dump_json(),
                artifact.analysis_timestamp,
            ],
        )

    def get_artifacts(self, limit: int = 100) -> list[dict]:
        """Query recent triage artifacts ordered by timestamp descending.

        Args:
            limit: Maximum number of artifact summaries to return (default: 100).

        Returns:
            list[dict]: List of dictionary summaries with triage ID, event ID,
                verdict, risk score, confidence score, and creation timestamp.
        """
        cursor = self.conn.execute(
            """
            SELECT triage_id, reference_event_id, verdict, risk_score, confidence_score, created_at
            FROM triage_artifacts
            ORDER BY created_at DESC
            LIMIT ?
            """,
            [limit],
        )
        cols = [col[0] for col in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def get_artifact_by_id(self, triage_id: str) -> dict | None:
        """Fetch full JSON payload of a single triage artifact by its ID.

        Args:
            triage_id: Unique triage artifact identifier.

        Returns:
            dict | None: Parsed JSON payload of the triage artifact, or None if not found.
        """
        cursor = self.conn.execute(
            "SELECT artifact_json FROM triage_artifacts WHERE triage_id = ?",
            [triage_id],
        )
        row = cursor.fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None
