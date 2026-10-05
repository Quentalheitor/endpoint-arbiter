"""FastAPI ingestion and triage service.

Exposes REST API endpoints for receiving normalized endpoint process telemetry,
orchestrating deterministic de-obfuscation, observable threat enrichment,
quarantined LLM extraction, privileged arbitration, and audit storage.
"""

import hashlib

from fastapi import FastAPI, HTTPException

from schemas.contracts import NormalizedInputTelemetry, TriageArtifact
from src.arbiter.arbiter import Arbiter
from src.enrichment.enricher import ObservableEnricher
from src.llm.extractor import QuarantinedExtractor
from src.normalizer.decoder import decode_powershell_base64
from src.persistence.storage import StorageManager

app = FastAPI(title="Endpoint Arbiter Triage Engine", version="0.1.0")

# Service components initialization
enricher = ObservableEnricher()
extractor = QuarantinedExtractor(use_mock=True)
arbiter = Arbiter()
storage = StorageManager()


@app.post("/api/v1/triage", response_model=TriageArtifact)
def triage_telemetry_event(event: NormalizedInputTelemetry) -> TriageArtifact:
    """Ingest and triage a single normalized endpoint telemetry event.

    Executes the complete multi-tier triage pipeline:
    1. Ensures canonical cryptographic hash exists on the event.
    2. Persists the incoming event to DuckDB for audit traceability.
    3. Deterministically normalizes and de-obfuscates command-line arguments.
    4. Performs observable reputation enrichment (Contract B lookup).
    5. Runs quarantined extraction on untrusted strings within strict boundaries.
    6. Executes privileged arbitration enforcing Safety Invariants I1 & I2.
    7. Persists and returns the resulting immutable Triage Artifact (Contract C).

    Args:
        event: Validated Contract A normalized input telemetry event.

    Returns:
        TriageArtifact: Final synthesized decision artifact (Contract C).
    """
    # 1. Compute canonical event hash if missing
    if not event.event_hash:
        event.event_hash = hashlib.sha256(event.model_dump_json().encode()).hexdigest()

    # 2. Persist incoming telemetry event
    storage.save_event(event)

    # 3. Deterministic normalizer decoding
    raw_cmd = event.process.command_line
    decoded_cmd, obf_type = decode_powershell_base64(raw_cmd)

    # 4. Asynchronous/Frozen Enrichment lookup
    dest_ip = event.network.destination_ip if event.network else "127.0.0.1"
    enrichment = enricher.lookup_ip(dest_ip)

    # 5. Quarantined extraction over decoded command line
    extracted_tokens = extractor.extract(decoded_cmd)

    # 6. Privileged arbitration & safety invariants enforcement
    artifact = arbiter.arbitrate(
        event=event,
        decoded_cmd=decoded_cmd,
        obf_type=obf_type,
        enrichment=enrichment,
        extractor_res=extracted_tokens,
    )

    # 7. Persist immutable triage artifact
    storage.save_artifact(artifact)

    return artifact


@app.get("/api/v1/artifacts")
def list_triage_artifacts(limit: int = 100) -> list[dict]:
    """Retrieve persisted audit artifact summaries from storage.

    Args:
        limit: Maximum number of artifact summaries to return (default: 100).

    Returns:
        list[dict]: List of triage artifact summary metadata ordered by creation date.
    """
    return storage.get_artifacts(limit=limit)


@app.get("/api/v1/artifacts/{triage_id}", response_model=TriageArtifact)
def get_triage_artifact(triage_id: str) -> dict:
    """Retrieve a single persisted triage artifact by its unique ID.

    Args:
        triage_id: The unique identifier of the triage decision artifact.

    Returns:
        dict: Complete JSON payload of the requested triage artifact.

    Raises:
        HTTPException: 404 status code if the artifact ID is not found in storage.
    """
    artifact_dict = storage.get_artifact_by_id(triage_id)
    if not artifact_dict:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact_dict
