from pathlib import Path
import sys
import pytest
from copy import deepcopy
from unittest.mock import MagicMock
from typing import Optional
import ipaddress

BASE_DIR = Path(__file__).resolve().parent.parent

SRC_DIR = BASE_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

# fmt: off
from llm import reasoner,extractor # noqa: E402


VALID_EXTRACTOR_PAYLOAD = {
    "event_id" : "evt-001",
    "timestamp" : "2026-10-03T14:32:01.004000Z",
    "raw_event_payload" : {"process_path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell.exe -enc SQBFAFgaHIBddbSMeCOUElAeds", "parent_process_path":"C:\\Windows\\System32\\cmd.exe", "user_privilege":"STANDART","network_connection":"198.51.100.42:443"}
}

def build_mock_extractor_client(parsed_output: Optional[extractor.QuarantinedExtractorOutput] = None, prompt_tokens:Optional[int] = 150, completion_tokens:Optional[int] = 50) -> MagicMock:
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_response = MagicMock()
    mock_choice.message.parsed = parsed_output
    mock_response.choices = [mock_choice]
    if isinstance(prompt_tokens,int) and isinstance(completion_tokens,int):
        mock_response.usage.prompt_tokens = prompt_tokens
        mock_response.usage.completion_tokens = completion_tokens
    else:
        mock_response.usage = None
    mock_client.beta.chat.completions.parse.return_value = mock_response
    return mock_client

@pytest.fixture
def output() -> extractor.QuarantinedExtractorOutput:
    return extractor.QuarantinedExtractorOutput(
        extractor_signal=reasoner.Extractor_Signals(
            primary_intent=reasoner.Intent.DOWNLOAD_EXECUTE,
            obfuscation=reasoner.Obfuscation_categories.BASE64),
        atomic_tokens=reasoner.Atomic_Tokens(normalized_target_binaries=reasoner.Normalized_Target_Binaries(
                PROCESS_BINARY_NAME="powershell.exe",
                PARENT_BINARY_NAME="cmd.exe",
                EXECUTION_PRIVILEGE=reasoner.Execution_priviledges.STANDARD),
                sanitized_targets=[reasoner.Destination_network_observables(
                    IP_ADDRESS=ipaddress.ip_address("198.51.100.42"))]
        ))

def test_extractor_input_deterministic_hash():
    first_input = extractor.QuarantinedExtractorInput.model_validate(VALID_EXTRACTOR_PAYLOAD)
    second_input = extractor.QuarantinedExtractorInput.model_validate(VALID_EXTRACTOR_PAYLOAD)

    assert first_input.serial_hash == second_input.serial_hash
    altered_payload = deepcopy(VALID_EXTRACTOR_PAYLOAD)
    altered_payload["raw_event_payload"]["command_line"] = "powershell.exe -enc SQBFAFgaHIBddbxMeCOUElAeds"

    altered_input = extractor.QuarantinedExtractorInput.model_validate(altered_payload)
    assert first_input.serial_hash != altered_input.serial_hash
