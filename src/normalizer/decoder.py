import base64
import os
import re
from typing import Tuple


def decode_powershell_base64(command_line: str) -> Tuple[str, str]:
    """
    Decodifies powershell comands in Base64 UTF-16LE
    covering flags like -encodedcommand, -enc, -e, -ec  and their combined form -nope.
    """
    pattern = re.compile(
        r"(?:-(?:encodedcommand|encoded|enc|ec|nope|e))\s+([A-Za-z0-9+/=]+)",
        re.IGNORECASE,
    )
    match = pattern.search(command_line)
    if not match:
        return command_line, "None"

    b64_str = match.group(1)

    # padding ajustment
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)

    try:
        decoded_bytes = base64.b64decode(b64_str)
        decoded_cmd = decoded_bytes.decode("utf-16le").strip()
        return decoded_cmd, "Base64 (UTF-16LE)"
    except Exception:
        return command_line, "Malformed Base64"


def expand_environment_variables(command_line: str) -> str:
    return os.path.expandvars(command_line)
