"""Data schemas for Tier C Quarantined LLM extraction.

Defines structured output models for extracting suspicious constructs,
high-level attacker intent, and prompt injection indicators from untrusted
telemetry without allowing malicious inputs to influence downstream execution.
"""

from typing import Literal

from pydantic import BaseModel, Field


class ExtractorOutput(BaseModel):
    """Structured extraction output emitted by Tier C Quarantined Extractor.

    This model enforces strict schema constraints on the LLM's classification,
    ensuring untrusted command-line text is parsed into known categorical values
    and boolean indicators.

    Attributes:
        intent_category: High-level tactical objective deduced from the telemetry.
        suspicious_constructs: Specific hostile patterns or behaviors identified.
        instruction_like_content_flag: Flag indicating whether prompt-injection or
            instruction-like phrases were detected within the command text.
    """

    intent_category: Literal[
        "reconnaissance", "download_execute", "persistence", "benign_admin", "unknown"
    ] = Field(
        ...,
        description="Categorized intent of the observed activity.",
    )
    suspicious_constructs: list[
        Literal["encoded_command", "download_cradle", "credential_access", "none"]
    ] = Field(
        ...,
        description="List of detected suspicious constructs or mechanisms.",
    )
    instruction_like_content_flag: bool = Field(
        default=False,
        description="True if command text contains prompt-injection-like phrases.",
    )
