from pathlib import Path
import sys
import pytest
from copy import deepcopy
from unittest.mock import MagicMock
from typing import Optional
from pydantic import ValidationError

BASE_DIR = Path(__file__).resolve().parent.parent

SRC_DIR = BASE_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

# fmt: off
from llm import reasoner  # noqa: E402
# fmt: on


VALID_REASONER_PAYLOAD = {
    "provenance_block": {
        "event_id": "evt-0001",
        "event_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timestamp": "2026-10-03T14:32:01.004000Z",
    },
    "extractor_signal": {
        "primary_intent": "DOWNLOAD_EXECUTE",
        "sub_intents": ["DEFENSE_EVASION"],
        "suspicious_constructs": [
            "ENCODED_PAYLOAD_DETECTED",
            "UNUSUAL_PARENT_PROCESS_LINEAGE",
        ],
        "obfuscation": "Base64",
    },
    "atomic_tokens": {
        "normalized_target_binaries": {
            "PROCESS_BINARY_NAME": "powershell.exe",
            "PARENT_BINARY_NAME": "cmd.exe",
            "EXECUTION_PRIVILEGE": "STANDARD",
        },
        "sanitized_targets": [
            {
                "IP_ADDRESS": "198.51.100.42",
                "FQDN": "c2-update.corp-internal.net",
                "DESTINATION_PORT": 443,
                "TRANSPORT_PROTOCOL": "TCP",
            }
        ],
    },
    "tier_a_container": {
        "MATCHED_RULES": [
            {
                "RULE_IDENTIFIER": "sigma-proc-ps-encoded-download",
                "RULE_SEVERITY": "HIGH",
                "MITRE_ATTACK_TECH": ["T1059.001", "T1071.001"],
                "RULE_TITLE": "PowerShell Encoded Web Download",
            }
        ]
    },
    "tier_b_classifier": {
        "MALICIOUS_PROBABILITY": 0.89,
        "REASON_CODES": [
            "HIGH_COMMAND_ENTROPY",
            "ANOMALOUS_PARENT_CHILD_RELATION",
        ],
    },
    "context_enrichment": [
        {
            "OBSERVABLE_VALUE": "198.51.100.42",
            "OBSERVABLE_TYPE": "ip_address",
            "REPUTATION_VERDICT": "Malicious",
            "REPUTATION_SCORE": 88,
            "THREAT_CATEGORIES": ["Command and Control"],
            "ASN": "AS64496",
        }
    ],
    "target_roster": {
        "HOSTS": ["WKS-09"],
        "USERS": ["CORP\\jdoe"],
        "IPS": ["10.0.4.155"],
    },
    "evidence_refs": ["evt-0001", "enrichment:198.51.100.42"],
}


def build_mock_llm_client(
    parsed_output: Optional[reasoner.Priviledged_Reasoner_Output] = None,
) -> MagicMock:
    """Creates and configures a mock OpenAI client for the beta.chat.completions.parse method."""
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.parsed = parsed_output

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    mock_client.beta.chat.completions.parse.return_value = mock_response
    return mock_client


@pytest.fixture
def output() -> reasoner.Priviledged_Reasoner_Output:
    return reasoner.Priviledged_Reasoner_Output(
        verdict=reasoner.TriageVerdict.MALICIOUS,
        risk_score=85,
        confidence_score=90,
        techniques=[
            reasoner.Technical_Mapping(
                framework="MITRE_ATTACK", id="T1566", name="Phishing"
            )
        ],
        justification="Adversary activity confirmed via malicious communication channel.",
        recommended_response=[
            reasoner.Recommended_Response(
                action="isolate_host",
                target="WKS-09",
                priority=reasoner.ResponsePriority.P1,
            )
        ],
        evidence_refs=["evt-0001"],
    )


def test_normalized_target_binaries():
    dirty_paths = [
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\script.ps1",
    ]
    ntb = reasoner.Normalized_Target_Binaries(
        PROCESS_BINARY_NAME=dirty_paths[0],
        EXECUTION_PRIVILEGE=reasoner.Execution_priviledges.STANDARD,
    )
    assert ntb.PROCESS_BINARY_NAME == "powershell.exe"
    with pytest.raises(ValidationError):
        reasoner.Normalized_Target_Binaries.model_validate(
            {
                "PROCESS_BINARY_NAME": dirty_paths[1],
                "EXECUTION_PRIVILEGE": "STANDARD",
            }
        )


def test_destination_network_observables():
    dno = reasoner.Destination_network_observables(
        IP_ADDRESS="192.168.1.1"  # type: ignore
    )
    assert isinstance(dno.IP_ADDRESS, reasoner.ipaddress.IPv4Address)
    with pytest.raises(ValidationError):
        reasoner.Destination_network_observables.model_validate(
            {"IP_ADDRESS": "999.999.999.999"}
        )
    with pytest.raises(ValidationError):
        reasoner.Destination_network_observables.model_validate({"DESTINATION_PORT": 4})


def test_aggregate_tier_a_container():
    test_list = [
        reasoner.Rule_Match_TierA(
            RULE_IDENTIFIER="sigma-proc-ps-encoded-download",
            RULE_SEVERITY=reasoner.Rule_Severity.LOW,
            MITRE_ATTACK_TECH=["T1059.001"],
        ),
        reasoner.Rule_Match_TierA(
            RULE_IDENTIFIER="sigma-proc-ps-encoded-download2",
            RULE_SEVERITY=reasoner.Rule_Severity.HIGH,
            MITRE_ATTACK_TECH=["T1059.001", "T1071.001"],
        ),
    ]
    rmata = reasoner.Aggregate_TierA_container(MATCHED_RULES=test_list)
    assert rmata.max_sev == reasoner.Rule_Severity.HIGH
    assert rmata.is_sev_high is True
    assert rmata.attack_techniques == ["T1059.001", "T1071.001"]


def test_invariant_15_target_sanitization():
    pro = reasoner.Priviledged_Reasoner_Output(
        verdict=reasoner.TriageVerdict.MALICIOUS,
        risk_score=90,
        confidence_score=90,
        justification="Containment action against identified targets.",
        recommended_response=[
            reasoner.Recommended_Response(
                action="isolate_host",
                target="WKS-09",
                priority=reasoner.ResponsePriority.P1,
            ),
            reasoner.Recommended_Response(
                action="isolate_host",
                target="compromised-server",
                priority=reasoner.ResponsePriority.P1,
            ),
        ],
    )

    vtr = reasoner.Valid_Target_Roster(HOSTS=["wks-09"])
    pro.inspect_action_list(roster=vtr)
    assert len(pro.recommended_response) == 1
    assert pro.recommended_response[0].target == "WKS-09"


def test_invariant_11_no_downgrade():
    vrp_copy = deepcopy(VALID_REASONER_PAYLOAD)
    vrp_copy_input = reasoner.PriviledgedReasonerInput.model_validate(vrp_copy)
    assert vrp_copy_input.tier_a_container.max_sev == reasoner.Rule_Severity.HIGH

    llm_simulated_benign_verdict = reasoner.Priviledged_Reasoner_Output(
        verdict=reasoner.TriageVerdict.BENIGN,
        risk_score=10,
        confidence_score=95,
        techniques=[],
        justification="Legitimate administrative activity for system maintenance.",
        recommended_response=[],
        evidence_refs=["evt-0001"],
    )
    mock_client = build_mock_llm_client(parsed_output=llm_simulated_benign_verdict)
    result = reasoner.priviledged_reasoner_executer(
        raw_input=vrp_copy, llm_client=mock_client, model_name="mock_model"
    )

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 75
    assert result["state"] == "complete"
    mock_client.beta.chat.completions.parse.assert_called_once()


def test_invariant_12_degradation(output):
    vrp_copy = deepcopy(VALID_REASONER_PAYLOAD)
    del vrp_copy["provenance_block"]
    result = reasoner.priviledged_reasoner_executer(vrp_copy, model_name="mock_model")
    assert result["state"] == "degraded"
    assert result["verdict"] == "Needs-Review"
    assert result["confidence_score"] == 0
    assert result["metrics"]["latency_ms"] == 0.0
    assert result["tier_trace"][0]["status"] == "validation_failed"

    mock_client_error = MagicMock()
    mock_client_error.beta.chat.completions.parse.side_effect = RuntimeError(
        "Connection timeout"
    )
    result2 = reasoner.priviledged_reasoner_executer(
        VALID_REASONER_PAYLOAD, llm_client=mock_client_error, model_name="mock_model"
    )
    assert result2["state"] == "degraded"
    assert result2["verdict"] == "Needs-Review"
    assert "provider" in result2["justification"].lower()
    assert isinstance(result2["metrics"]["latency_ms"], float)
    assert result2["metrics"]["latency_ms"] >= 0.0

    mock_client_refusal = build_mock_llm_client(parsed_output=None)
    result3 = reasoner.priviledged_reasoner_executer(
        VALID_REASONER_PAYLOAD, llm_client=mock_client_refusal, model_name="mock_model"
    )
    assert result3["state"] == "degraded"
    assert result3["verdict"] == "Needs-Review"
    assert result3["tier_trace"][0]["status"] == "model_refusal"


def test_happy_path(output):
    mock_client = build_mock_llm_client(output)
    result = reasoner.priviledged_reasoner_executer(
        VALID_REASONER_PAYLOAD, llm_client=mock_client, model_name="mock_model"
    )
    assert result["state"] == "complete"
    assert result["verdict"] == reasoner.TriageVerdict.MALICIOUS.value
    assert result["metrics"]["latency_ms"] >= 0.0
    mock_client.beta.chat.completions.parse.assert_called_once()
