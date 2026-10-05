"""Telemetry normalization and de-obfuscation decoder.

Provides deterministic decoding routines for obfuscated command-line telemetry,
including Base64-encoded UTF-16LE PowerShell payloads and environment variable
expansions.
"""

import base64
import binascii
import os
import re


def decode_powershell_base64(command_line: str) -> tuple[str, str]:
    """Decode obfuscated Base64 UTF-16LE encoded PowerShell commands.

    Inspects the command line for standard PowerShell encoded execution flags
    (e.g., `-encodedcommand`, `-enc`, `-e`, `-ec`, and `-nope`). When found,
    the Base64 payload is extracted, padded to a valid block boundary if necessary,
    and decoded from little-endian UTF-16 bytes into plaintext.

    Args:
        command_line: Raw command-line string from process telemetry.

    Returns:
        tuple[str, str]: A pair containing:
            - The decoded plaintext command line (or original command if not encoded).
            - The obfuscation category detected (e.g. 'Base64 (UTF-16LE)', 'None',
              or 'Malformed Base64').
    """
    # Regex matching PowerShell encoded flags and capturing the trailing Base64 token
    pattern = re.compile(
        r"(?:-(?:encodedcommand|encoded|enc|ec|nope|e))\s+([A-Za-z0-9+/=]+)",
        re.IGNORECASE,
    )
    match = pattern.search(command_line)
    if not match:
        return command_line, "None"

    b64_str = match.group(1)

    # Adjust missing Base64 '=' padding if truncated
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)

    try:
        decoded_bytes = base64.b64decode(b64_str)
        decoded_cmd = decoded_bytes.decode("utf-16le").strip()
        return decoded_cmd, "Base64 (UTF-16LE)"
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return command_line, "Malformed Base64"


def expand_environment_variables(command_line: str) -> str:
    """Expand system environment variables contained within a command string.

    Replaces occurrences of environment variable placeholders (e.g. `%SystemRoot%`
    or `$PATH`) with their corresponding runtime values.

    Args:
        command_line: Command string potentially containing environment variables.

    Returns:
        str: Expanded command string with variables substituted.
    """
    return os.path.expandvars(command_line)
