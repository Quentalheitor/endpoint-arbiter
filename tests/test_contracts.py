"""Tests for Pydantic v2 data contracts A, B, C, and D."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.contracts import (
    ArtifactState,
    BenchmarkInjection,
    BenchmarkRecord,
    ContractA,
    ContractB,
    ContractC,
    ContractD,
    ImmutableTriageArtifact,
    InjectionCategory,
    NormalizedInputTelemetry,
    ObservableEnrichment,
    ResponsePriority,
    Verdict,
    coerce_to_utc_datetime,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestContractA:
    """Test suite for Contract A: Normalized Input Telemetry."""

    def test_valid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_a_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        event = ContractA.model_validate(data)

        assert event.event_id == "evt-0001"
        assert event.class_uid == 1007
        assert event.host.hostname == "WKS-09"
        assert event.principal.username == "jdoe"
        assert event.process.pid == 4812
        assert event.network is not None
        assert event.network.destination_ip == "198.51.100.42"
        assert "process.command_line" in event.untrusted_fields

    def test_invalid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_a_invalid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))

        with pytest.raises(ValidationError) as exc_info:
            ContractA.model_validate(data)

        errors = exc_info.value.errors()
        error_fields = {
            e["loc"][0] if len(e["loc"]) == 1 else f"{e['loc'][0]}.{e['loc'][1]}"
            for e in errors
        }
        assert "event_id" in error_fields
        assert "event_hash" in error_fields
        assert "timestamp_utc" in error_fields

    def test_canonical_hash_computation(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_a_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        event = NormalizedInputTelemetry.model_validate(data)

        canonical_hash = event.compute_canonical_hash()
        assert len(canonical_hash) == 64
        # Re-computing on same event gives identical hash (determinism)
        assert canonical_hash == event.compute_canonical_hash()


class TestContractB:
    """Test suite for Contract B: Observable Enrichment."""

    def test_valid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_b_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        enrichment = ContractB.model_validate(data)

        assert enrichment.observable_value == "198.51.100.42"
        assert enrichment.observable_type == "ip_address"
        assert enrichment.reputation.score == 88
        assert enrichment.reputation.verdict == "Malicious"
        assert enrichment.cache_metadata.mode == "frozen"
        assert enrichment.cache_metadata.snapshot_id == "enrich-v1"

    def test_invalid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_b_invalid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))

        with pytest.raises(ValidationError) as exc_info:
            ObservableEnrichment.model_validate(data)

        errors = exc_info.value.errors()
        error_msgs = [e["msg"] for e in errors]
        assert any("less than or equal to 100" in msg for msg in error_msgs)
        assert any("greater than or equal to 0" in msg for msg in error_msgs)


class TestContractC:
    """Test suite for Contract C: Immutable Triage Artifact."""

    def test_valid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_c_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        artifact = ContractC.model_validate(data)

        assert artifact.triage_id == "trg-0001"
        assert artifact.reference_event_id == "evt-0001"
        assert artifact.verdict == Verdict.MALICIOUS
        assert artifact.state == ArtifactState.COMPLETE
        assert artifact.metrics.risk_score == 85
        assert artifact.metrics.confidence_score == 90
        assert len(artifact.techniques) == 2
        assert artifact.recommended_response[0].priority == ResponsePriority.P0

    def test_invalid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_c_invalid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))

        with pytest.raises(ValidationError) as exc_info:
            ImmutableTriageArtifact.model_validate(data)

        errors = exc_info.value.errors()
        error_fields = {e["loc"][-1] for e in errors}
        assert "verdict" in error_fields
        assert "decoded_content" in error_fields

    def test_immutability(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_c_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        artifact = ContractC.model_validate(data)

        with pytest.raises(ValidationError, match="Instance is frozen"):
            artifact.verdict = Verdict.BENIGN  # type: ignore[misc]

        with pytest.raises(ValidationError, match="Instance is frozen"):
            artifact.metrics.risk_score = 0  # type: ignore[misc]


class TestContractD:
    """Test suite for Contract D: Benchmark Record."""

    def test_valid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_d_valid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        record = ContractD.model_validate(data)

        assert record.record_id == "rec-0001"
        assert record.event_id == "evt-0001"
        assert record.labels.verdict == Verdict.MALICIOUS
        assert record.split == "test"
        assert record.injection.category is None

    def test_invalid_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "contract_d_invalid.json"
        data = json.loads(fixture_path.read_text(encoding="utf-8"))

        with pytest.raises(ValidationError) as exc_info:
            BenchmarkRecord.model_validate(data)

        errors = exc_info.value.errors()
        error_locs = [e["loc"] for e in errors]
        assert any("verdict" in loc for loc in error_locs)
        assert any("record_id" in loc for loc in error_locs)

    def test_adversarial_injection_record(self) -> None:
        record = BenchmarkRecord(
            record_id="rec-0002",
            event_id="evt-0002",
            labels={
                "verdict": Verdict.MALICIOUS,
                "attack_techniques": ["T1059.001"],
                "obfuscation_type": "None",
                "provenance": {"type": "emulation", "test_id": "art-01"},
                "scenario_id": "scn-015",
            },
            split="test",
            injection=BenchmarkInjection(
                category=InjectionCategory.DIRECT_INSTRUCTION,
                target_field="process.command_line",
            ),
        )

        assert record.injection.category == InjectionCategory.DIRECT_INSTRUCTION
        assert record.injection.target_field == "process.command_line"


class TestDatetimeCoercion:
    """Test suite for UTC timestamp coercion and serialization."""

    def test_utc_coercion_from_iso_with_z(self) -> None:
        dt = coerce_to_utc_datetime("2026-10-03T14:32:01.004000Z")
        assert dt.tzinfo == timezone.utc
        assert dt.microsecond == 4000

    def test_utc_coercion_from_offset(self) -> None:
        dt = coerce_to_utc_datetime("2026-10-03T17:32:01+03:00")
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 14
        assert dt.minute == 32

    def test_utc_coercion_from_naive_datetime(self) -> None:
        naive = datetime(2026, 10, 3, 14, 32, 1)  # noqa: DTZ001
        dt = coerce_to_utc_datetime(naive)
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 14

    def test_invalid_datetime_type(self) -> None:
        with pytest.raises(TypeError):
            coerce_to_utc_datetime(123456789)
