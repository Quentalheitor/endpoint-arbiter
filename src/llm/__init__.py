"""Tier C LLM extraction package.

Provides quarantined LLM extraction capabilities designed to operate over
untrusted telemetry within strict schema boundaries, preventing adversarial
prompt injection from steering downstream privileged actions.
"""

# fmt: off
from .extractor import QuarantinedExtractorInput, QuarantinedExtractorOutput # noqa: F401
