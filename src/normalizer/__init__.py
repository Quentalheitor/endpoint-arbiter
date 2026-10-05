"""Telemetry normalizer package.

Provides deterministic de-obfuscation and normalization utilities for endpoint
command lines, including Base64 UTF-16LE decoding and environment variable expansion.
"""

from src.normalizer.decoder import (
    decode_powershell_base64,
    expand_environment_variables,
)

__all__ = ["decode_powershell_base64", "expand_environment_variables"]
