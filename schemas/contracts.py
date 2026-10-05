"""Pydantic v2 Data Contracts for Trustworthy LLM Triage for Endpoint Security.

Implements Contracts A, B, C, and D described in Section 6 of the technical specification:
- Contract A: Normalized Input Telemetry (OCSF-aligned, Class 1007: Process Activity)
- Contract B: Observable Enrichment
- Contract C: Immutable Triage Artifact
- Contract D: Benchmark Record
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
)

# =====================================================================
# Enums and Value Sets
# =====================================================================


class Verdict(str, Enum):
    """Triaged or labeled event verdict."""

    MALICIOUS = "Malicious"
    BENIGN = "Benign"
    NEEDS_REVIEW = "Needs-Review"


class ArtifactState(str, Enum):
    """Triage execution state for Safety Invariant I2."""

    COMPLETE = "complete"
    DEGRADED = "degraded"
    FAILED = "failed"


class ResponsePriority(str, Enum):
    """Prioritized response recommendations (P0 critical to P3 low)."""

    P0 = "P0"  # Critical
    P1 = "P1"  # High
    P2 = "P2"  # Medium
    P3 = "P3"  # Low


class CacheMode(str, Enum):
    """Enrichment caching mode."""

    FROZEN = "frozen"
    LIVE = "live"


class ObservableType(str, Enum):
    """Extracted observable types for async enrichment."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "hash_sha256"
    PROCESS_NAME = "process_name"
    HOSTNAME = "hostname"
    USERNAME = "username"


class ObfuscationType(str, Enum):
    """Telemetry obfuscation taxonomy."""

    NONE = "None"
    BASE64 = "Base64"
    BASE64_UTF16LE = "Base64 (UTF-16LE)"
    CONCATENATION = "Concatenation"
    VARIABLE_EXPANSION = "Variable Expansion"
    MIXED = "Mixed"


class BenchmarkSplit(str, Enum):
    """Benchmark dataset partition."""

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    DEV = "dev"


class InjectionCategory(str, Enum):
    """Adversarial prompt injection categories across all 8 attack vectors."""

    DIRECT_INSTRUCTION = "direct_instruction"
    FIELD_SMUGGLING = "field_smuggling"
    PERSISTENT_STORE = "persistent_store"
    ENCODED_INSTRUCTION = "encoded_instruction"
    FORMAT_MIMICRY = "format_mimicry"
    CONTEXT_FLOODING = "context_flooding"
    MULTILINGUAL = "multilingual"
    CROSS_FIELD_SPLITTING = "cross_field_splitting"


# =====================================================================
# Datetime Coercion and Serialization (UTC ISO-8601)
# =====================================================================


def coerce_to_utc_datetime(v: Any) -> datetime:
    """Coerce input timestamps into a timezone-aware UTC datetime instance.

    Parses ISO-8601 formatted strings (supporting trailing 'Z' or offset notations)
    or validates existing datetime objects. Naive datetime objects are assumed to be
    in UTC, while offset-aware datetimes are converted to UTC.

    Args:
        v: The input timestamp value, expected as an ISO-8601 string or datetime object.

    Returns:
        datetime: A timezone-aware datetime instance in UTC (timezone.utc).

    Raises:
        TypeError: If the input is neither a string nor a datetime instance.
        ValueError: If the string cannot be parsed as a valid ISO-8601 timestamp.
    """
    if isinstance(v, str):
        cleaned = v.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
    elif isinstance(v, datetime):
        dt = v
    else:
        raise TypeError(
            f"Invalid timestamp value: expected ISO-8601 string or datetime, got {type(v).__name__}"
        )

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def serialize_utc_datetime(dt: datetime) -> str:
    """Format a UTC datetime object as an ISO-8601 string ending with Z.

    Converts the datetime to UTC and formats it with second or microsecond precision,
    appending 'Z' to designate the zero UTC offset.

    Args:
        dt: The datetime instance to serialize.

    Returns:
        str: ISO-8601 formatted string ending with 'Z' (e.g. '2026-10-05T14:30:00Z').
    """
    utc_dt = dt.astimezone(timezone.utc)
    if utc_dt.microsecond > 0:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


UTCDateTime = Annotated[
    datetime,
    BeforeValidator(coerce_to_utc_datetime),
    PlainSerializer(serialize_utc_datetime, return_type=str, when_used="json"),
]


# =====================================================================
# Contract A: Normalized Input Telemetry
# (OCSF-aligned, Class 1007: Process Activity)
# =====================================================================


class HostInfo(BaseModel):
    """Host/device information for endpoint telemetry."""

    model_config = ConfigDict(extra="ignore")

    hostname: str = Field(
        ..., min_length=1, description="Host name where the event occurred."
    )
    ip_addresses: list[str] = Field(
        default_factory=list, description="Observed network IP addresses for the host."
    )
    os: str | None = Field(default=None, description="Operating system details.")


class PrincipalInfo(BaseModel):
    """Actor / identity information executing the process."""

    model_config = ConfigDict(extra="ignore")

    username: str = Field(
        ..., min_length=1, description="Username of the executing principal."
    )
    domain: str | None = Field(default=None, description="Domain or workgroup name.")
    is_elevated: bool = Field(
        default=False, description="Whether the process runs with elevated privileges."
    )


class FileInfo(BaseModel):
    """Binary file metadata for the executing process."""

    model_config = ConfigDict(extra="ignore")

    executable_path: str | None = Field(
        default=None, description="Absolute file path of the executable image."
    )
    hash_sha256: str | None = Field(
        default=None, description="SHA-256 cryptographic digest of the executable file."
    )


class ProcessInfo(BaseModel):
    """Process execution attributes and parent-child lineage."""

    model_config = ConfigDict(extra="ignore")

    pid: int = Field(..., ge=0, description="Process ID.")
    name: str = Field(..., min_length=1, description="Name of the process executable.")
    file: FileInfo | None = Field(default=None, description="Executable file details.")
    command_line: str = Field(
        ..., description="Full command-line string including arguments."
    )
    parent_pid: int | None = Field(
        default=None, ge=0, description="Parent Process ID for lineage tracking."
    )
    parent_name: str | None = Field(
        default=None, description="Parent process executable name."
    )


class NetworkInfo(BaseModel):
    """Network connection details associated with the process activity."""

    model_config = ConfigDict(extra="ignore")

    destination_ip: str | None = Field(
        default=None, description="Destination IP address."
    )
    destination_port: int | None = Field(
        default=None, ge=1, le=65535, description="Destination TCP/UDP port."
    )
    protocol: str | None = Field(
        default=None, description="Network protocol (e.g. TCP, UDP)."
    )


class NormalizedInputTelemetry(BaseModel):
    """Contract A: OCSF-aligned normalized endpoint process activity event (Class 1007)."""

    model_config = ConfigDict(extra="ignore")

    category_uid: int = Field(
        default=1, description="OCSF Category UID: System Activity (1)."
    )
    class_uid: int = Field(
        default=1007, description="OCSF Class UID: Process Activity (1007)."
    )
    activity_id: int = Field(
        default=1, description="OCSF Activity ID (1 = Launch/Create, etc.)."
    )
    type_uid: int = Field(
        default=100701, description="OCSF Type UID (class_uid * 100 + activity_id)."
    )
    schema_version: str = Field(
        default="1.3.0", description="OCSF schema version alignment."
    )
    event_id: str = Field(..., min_length=1, description="Unique event identifier.")
    event_hash: str = Field(
        ...,
        min_length=1,
        description="Ingestion-time cryptographic SHA-256 hash of canonical event JSON.",
    )
    timestamp_utc: UTCDateTime = Field(
        ..., description="Coerced UTC ISO-8601 event occurrence timestamp."
    )
    sensor_source: str = Field(
        ...,
        min_length=1,
        description="Source sensor or agent identifier (e.g. endpoint_edr, sysmon).",
    )
    host: HostInfo = Field(..., description="Target host system metadata.")
    principal: PrincipalInfo = Field(
        ..., description="Actor / user identity execution context."
    )
    process: ProcessInfo = Field(
        ..., description="Process metadata and parent-child execution chain."
    )
    network: NetworkInfo | None = Field(
        default=None, description="Optional associated network activity connection."
    )
    untrusted_fields: list[str] = Field(
        default_factory=list,
        description="Explicit list of attacker-influenceable field paths flagged for quarantine.",
    )

    def compute_canonical_hash(self) -> str:
        """Compute the cryptographic SHA-256 digest over the canonical JSON representation.

        Dumps the model excluding the 'event_hash' field itself, sorts all JSON keys,
        and generates a deterministic SHA-256 hex digest to serve as a tamper-evident
        event identifier.

        Returns:
            str: 64-character lowercase hexadecimal SHA-256 hash string.
        """
        data = self.model_dump(mode="json", exclude={"event_hash"})
        canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


# Type alias for Contract A
ContractA = NormalizedInputTelemetry
NormalizedProcessActivity = NormalizedInputTelemetry


# =====================================================================
# Contract B: Observable Enrichment
# =====================================================================


class ReputationInfo(BaseModel):
    """External or frozen reputation assessment for an observable."""

    model_config = ConfigDict(extra="ignore")

    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Reputation score from 0 (benign) to 100 (critical malicious).",
    )
    verdict: str = Field(
        ...,
        min_length=1,
        description="Reputation verdict (e.g. Malicious, Suspicious, Benign).",
    )
    source: str = Field(
        ..., min_length=1, description="Enrichment feed or fixture provider."
    )
    threat_categories: list[str] = Field(
        default_factory=list,
        description="Identified threat or malware classifications.",
    )


class HistoricalContext(BaseModel):
    """Historical context and passive DNS / network infrastructure details."""

    model_config = ConfigDict(extra="ignore")

    first_seen: UTCDateTime | None = Field(
        default=None, description="First recorded observation timestamp."
    )
    last_seen: UTCDateTime | None = Field(
        default=None, description="Most recent observation timestamp."
    )
    asn: str | None = Field(
        default=None, description="Autonomous System Number (e.g. AS64496)."
    )
    country: str | None = Field(
        default=None, description="Two-letter country code (ISO 3166-1 alpha-2)."
    )


class CacheMetadata(BaseModel):
    """Cache operational metadata ensuring reproducibility and stampede prevention."""

    model_config = ConfigDict(extra="ignore")

    mode: CacheMode | str = Field(
        default=CacheMode.FROZEN,
        description="Enrichment cache operating mode: 'frozen' (benchmark evaluation) or 'live'.",
    )
    snapshot_id: str | None = Field(
        default=None,
        description="Versioned snapshot identifier for frozen mode reproducibility.",
    )
    cached_at: UTCDateTime = Field(
        ..., description="Timestamp when observable was cached."
    )
    ttl_seconds: int = Field(
        ..., ge=0, description="Time-To-Live in seconds for cache validity."
    )


class ObservableEnrichment(BaseModel):
    """Contract B: Observable intelligence enrichment record."""

    model_config = ConfigDict(extra="ignore")

    observable_value: str = Field(
        ..., min_length=1, description="Observable value (IP, domain, hash, etc.)."
    )
    observable_type: ObservableType | str = Field(
        ..., description="Observable classification category."
    )
    reputation: ReputationInfo = Field(
        ..., description="Observable reputation metrics and threat categories."
    )
    historical_context: HistoricalContext | None = Field(
        default=None, description="Historical context and routing metadata."
    )
    cache_metadata: CacheMetadata = Field(
        ..., description="Cache operational mode and validity metadata."
    )


# Type alias for Contract B
ContractB = ObservableEnrichment


# =====================================================================
# Contract C: Immutable Triage Artifact
# =====================================================================


class TriageMetrics(BaseModel):
    """Risk and confidence assessment scores."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    risk_score: int = Field(
        ..., ge=0, le=100, description="Computed risk severity score (0 to 100)."
    )
    confidence_score: int = Field(
        ..., ge=0, le=100, description="Decision confidence percentage (0 to 100)."
    )


class CostLog(BaseModel):
    """Token consumption and estimated inference cost log for LLM execution."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    prompt_tokens: int = Field(
        default=0, ge=0, description="Number of tokens in the prompt."
    )
    completion_tokens: int = Field(
        default=0, ge=0, description="Number of tokens in the generated completion."
    )
    total_tokens: int = Field(
        default=0, ge=0, description="Total tokens consumed in the LLM execution."
    )
    cost_usd: float = Field(
        default=0.0, ge=0.0, description="Estimated inference cost in USD."
    )


class TierTraceEntry(BaseModel):
    """Diagnostic execution trace for a single decision tier."""

    model_config = ConfigDict(frozen=True, extra="allow")

    tier: str = Field(
        ...,
        min_length=1,
        description="Tier identifier (e.g. 'A', 'B', 'C', 'Arbiter').",
    )
    rule_ids: list[str] | None = Field(
        default=None, description="Sigma or detection rule IDs that matched in Tier A."
    )
    role: str | None = Field(
        default=None, description="LLM role in Tier C (e.g. 'extractor' or 'reasoner')."
    )
    model_version: str | None = Field(
        default=None, description="Pinned model identifier invoked in Tier C."
    )
    score: float | None = Field(
        default=None, description="Calibrated ML probability score from Tier B."
    )
    reason_codes: list[str] | None = Field(
        default=None, description="Interpretability reason codes emitted by Tier B."
    )
    cost_log: CostLog | None = Field(
        default=None,
        description="Token consumption and estimated inference cost log for this tier.",
    )


class DecodedContent(BaseModel):
    """Deterministic decoding evidence and detected injection flags."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    command_line_decoded: str | None = Field(
        default=None,
        description="De-obfuscated command line (UTF-16LE, Base64, string expansion).",
    )
    obfuscation_type: ObfuscationType | str = Field(
        default=ObfuscationType.NONE,
        description="Primary obfuscation technique identified.",
    )
    injection_flags_detected: list[str] = Field(
        default_factory=list,
        description="Flags raised if injection patterns or format mimicry are encountered.",
    )


class TechniqueMapping(BaseModel):
    """Standardized ATT&CK or ATLAS framework technique mapping."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    framework: str = Field(
        default="MITRE_ATTACK",
        description="Security framework (e.g. MITRE_ATTACK or MITRE_ATLAS for injections).",
    )
    id: str = Field(
        ..., min_length=1, description="Technique or sub-technique ID (e.g. T1059.001)."
    )
    name: str = Field(
        ..., min_length=1, description="Descriptive technique name (e.g. PowerShell)."
    )
    tactic: str | None = Field(default=None, description="Parent tactic name.")


class ResponseRecommendation(BaseModel):
    """Prioritized incident response recommendation."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    action: str = Field(
        ..., min_length=1, description="Recommended remediation action."
    )
    target: str = Field(
        ..., min_length=1, description="Host, user, or process target entity."
    )
    priority: ResponsePriority | str = Field(
        default=ResponsePriority.P2,
        description="Prioritized action urgency (P0 critical to P3 low).",
    )


class ImmutableTriageArtifact(BaseModel):
    """Contract C: Immutable, schema-validated triage decision artifact dispatched downstream."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    triage_id: str = Field(
        ..., min_length=1, description="Unique triage artifact identifier."
    )
    reference_event_id: str = Field(
        ..., min_length=1, description="Event ID of the normalized input telemetry."
    )
    analysis_timestamp: UTCDateTime = Field(
        ..., description="UTC timestamp when triage arbitration completed."
    )
    config_version: str = Field(
        ...,
        min_length=1,
        description="Configuration version composite (<rules-ver>+<ml-ver>+<extractor>+<reasoner>).",
    )
    verdict: Verdict = Field(..., description="Final triage decision verdict.")
    state: ArtifactState | str = Field(
        default=ArtifactState.COMPLETE,
        description="Execution state (complete, degraded per Invariant I2, or failed).",
    )
    metrics: TriageMetrics = Field(
        ..., description="Assessed risk and confidence scores."
    )
    tier_trace: list[TierTraceEntry] = Field(
        default_factory=list,
        description="Audit trace of participating reasoning tiers (Invariant I4).",
    )
    cost_log: CostLog | None = Field(
        default=None,
        description="Aggregated token usage and estimated inference cost log across all tiers.",
    )
    decoded_content: DecodedContent = Field(
        ..., description="Deterministic decoding results and de-obfuscation evidence."
    )
    techniques: list[TechniqueMapping] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK / ATLAS techniques."
    )
    justification: str = Field(
        ...,
        min_length=1,
        description="Natural-language rationale explaining the decision.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Referenced event IDs and observable enrichment keys.",
    )
    recommended_response: list[ResponseRecommendation] = Field(
        default_factory=list, description="Prioritized response recommendations."
    )


# Type aliases for Contract C
ContractC = ImmutableTriageArtifact
TriageArtifact = ImmutableTriageArtifact


# =====================================================================
# Contract D: Benchmark Record
# =====================================================================


class BenchmarkProvenance(BaseModel):
    """Ground-truth provenance metadata."""

    model_config = ConfigDict(extra="allow")

    type: str = Field(
        ...,
        min_length=1,
        description="Provenance type: emulation, public_dataset, or manual_rule.",
    )
    test_id: str | None = Field(
        default=None, description="Atomic Red Team or emulation test ID."
    )
    dataset_ref: str | None = Field(
        default=None, description="Public dataset reference or citation."
    )
    rule_ref: str | None = Field(
        default=None, description="Manual rule or baseline reference."
    )


class BenchmarkLabels(BaseModel):
    """Ground-truth labels for benchmark evaluation."""

    model_config = ConfigDict(extra="ignore")

    verdict: Verdict = Field(..., description="Ground-truth label verdict.")
    attack_techniques: list[str] = Field(
        default_factory=list, description="Ground-truth MITRE ATT&CK technique IDs."
    )
    obfuscation_type: ObfuscationType | str = Field(
        default=ObfuscationType.NONE, description="Ground-truth obfuscation type."
    )
    provenance: BenchmarkProvenance = Field(
        ..., description="Label provenance and emulation test metadata."
    )
    scenario_id: str = Field(
        ...,
        min_length=1,
        description="Scenario run identifier used for GroupShuffleSplit.",
    )


class BenchmarkInjection(BaseModel):
    """Metadata for adversarial prompt injection benchmark subset."""

    model_config = ConfigDict(extra="ignore")

    category: InjectionCategory | str | None = Field(
        default=None,
        description="Injection category across the 8 attack classes, or null.",
    )
    target_field: str | None = Field(
        default=None,
        description="Target field where the injection payload was embedded, or null.",
    )


class BenchmarkRecord(BaseModel):
    """Contract D: Labeled benchmark dataset record."""

    model_config = ConfigDict(extra="ignore")

    record_id: str = Field(
        ..., min_length=1, description="Unique benchmark record identifier."
    )
    event_id: str = Field(..., min_length=1, description="Normalized event identifier.")
    labels: BenchmarkLabels = Field(
        ..., description="Ground-truth labels and scenario provenance."
    )
    split: BenchmarkSplit | str = Field(
        ..., description="Assigned dataset split (train, validation, test)."
    )
    injection: BenchmarkInjection = Field(
        default_factory=BenchmarkInjection,
        description="Adversarial prompt injection metadata for robustness evaluation.",
    )


# Type alias for Contract D
ContractD = BenchmarkRecord


# =====================================================================
# Module Exports
# =====================================================================

__all__ = [
    "ArtifactState",
    "BenchmarkInjection",
    "BenchmarkLabels",
    "BenchmarkProvenance",
    "BenchmarkRecord",
    "BenchmarkSplit",
    "CacheMetadata",
    "CacheMode",
    "ContractA",
    "ContractB",
    "ContractC",
    "ContractD",
    "DecodedContent",
    "FileInfo",
    "HistoricalContext",
    "HostInfo",
    "ImmutableTriageArtifact",
    "InjectionCategory",
    "NetworkInfo",
    "NormalizedInputTelemetry",
    "NormalizedProcessActivity",
    "ObfuscationType",
    "ObservableEnrichment",
    "ObservableType",
    "PrincipalInfo",
    "ProcessInfo",
    "ReputationInfo",
    "ResponsePriority",
    "ResponseRecommendation",
    "TechniqueMapping",
    "TierTraceEntry",
    "TriageArtifact",
    "TriageMetrics",
    "UTCDateTime",
    "Verdict",
    "coerce_to_utc_datetime",
    "serialize_utc_datetime",
]
