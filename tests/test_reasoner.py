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
    """Cria e configura um cliente OpenAI simulado para o método beta.chat.completions.parse[cite: 3]."""
    mock_client = MagicMock()

    # Estrutura a mensagem analisada dentro da escolha
    mock_choice = MagicMock()
    mock_choice.message.parsed = parsed_output

    # Encapsula a lista de escolhas na resposta simulada
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    # Vincula a resposta ao método parse consumido pelo executor
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
        justification="O adversário utilizou um canal de comunicação digital — especificamente [mencione o canal: e-mail / mensagem instantânea / SMS] — disfarçado como uma entidade legítima e de confiança [ex: o departamento de TI da empresa / uma instituição bancária / um serviço de nuvem]",
        recommended_response=[
            reasoner.Recommended_Response(
                action="something",
                target="someone",
                priority=reasoner.ResponsePriority.P1,
            )
        ],
        evidence_refs=["something"],
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
                "EXECUTION_PRIVILEGE": reasoner.Execution_priviledges.STANDARD,
            }
        )


def test_Destination_network_observables():
    dno = reasoner.Destination_network_observables(
        IP_ADDRESS="192.168.1.1"  # type: ignore
    )
    assert isinstance(dno.IP_ADDRESS, reasoner.ipaddress.IPv4Address)
    with pytest.raises(ValidationError):
        reasoner.Destination_network_observables.model_validate(
            {"IP_ADDRESS": "999.999.999.999"}
        )
    with pytest.raises(ValueError):
        reasoner.Destination_network_observables.model_validate({"DESTINATION_PORT": 4})


def test_Aggregate_TierA_container():
    test_list = [
        reasoner.Rule_Match_TierA(
            RULE_IDENTIFIER="sigma-proc-ps-encoded-download",
            RULE_SEVERITY=reasoner.Rule_Severity.LOW,
        ),
        reasoner.Rule_Match_TierA(
            RULE_IDENTIFIER="sigma-proc-ps-encoded-download2",
            RULE_SEVERITY=reasoner.Rule_Severity.HIGH,
        ),
        reasoner.Rule_Match_TierA(
            RULE_IDENTIFIER="sigma-proc-ps-encoded-download",
            RULE_SEVERITY=reasoner.Rule_Severity.LOW,
        ),
    ]
    rmata = reasoner.Aggregate_TierA_container(MATCHED_RULES=test_list)
    assert rmata.max_sev == "HIGH"
    assert rmata.is_sev_high
    assert len(test_list) != len(rmata.MATCHED_RULES)


def test_invariant_5():
    pro = reasoner.Priviledged_Reasoner_Output(
        verdict=reasoner.TriageVerdict.MALICIOUS,
        risk_score=90,
        confidence_score=90,
        justification="placeholder",
        recommended_response=[
            reasoner.Recommended_Response(
                action="something",
                target="WKS-09",
                priority=reasoner.ResponsePriority.P1,
            ),
            reasoner.Recommended_Response(
                action="placeholder",
                target="compromised-server",
                priority=reasoner.ResponsePriority.P1,
            ),
        ],
    )

    vtr = reasoner.Valid_Target_Roster(HOSTS=["wks-09"])
    pro.inspect_action_list(roster=vtr)
    assert len(pro.recommended_response) == 1
    assert pro.recommended_response[0].target == "WKS-09"


def test_invariant_1():
    vrp_copy = deepcopy(VALID_REASONER_PAYLOAD)
    vrp_copy_input = reasoner.PriviledgedReasonerInput.model_validate(vrp_copy)
    assert vrp_copy_input.tier_a_container.max_sev == "HIGH"
    llm_simulated_benign_verdict = reasoner.Priviledged_Reasoner_Output(
        verdict=reasoner.TriageVerdict.BENIGN,
        risk_score=10,
        confidence_score=95,
        techniques=[],
        justification="Atividade administrativa legitima de manutencao do sistema.",
        recommended_response=[],
        evidence_refs=["evt-0001"],
    )
    mock_client = build_mock_llm_client(parsed_output=llm_simulated_benign_verdict)
    payload = vrp_copy
    result = reasoner.priviledged_reasoner_executer(
        raw_input=payload, llm_client=mock_client, model_name="mock_model"
    )

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 75
    assert result["state"] == "complete"

    mock_client.beta.chat.completions.parse.assert_called_once()


def test_invariant_2():
    vrp_copy = deepcopy(VALID_REASONER_PAYLOAD)
    del vrp_copy["provenance_block"]
    result = reasoner.priviledged_reasoner_executer(vrp_copy, model_name="mock_model")
    assert result["state"] == "degraded"
    assert result["verdict"] == "Needs-Review"
    assert result["confidence_score"] == 0
    assert result["metrics"]["latency_ms"] == 0.0
    assert result["ter_trace"][0]["status"] == "validation_failed"
