"""Data schemas for Tier C Quarantined LLM extraction.

Defines structured output models for extracting suspicious constructs,
high-level attacker intent, and prompt injection indicators from untrusted
telemetry without allowing malicious inputs to influence downstream execution.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ExtractorCostLog(BaseModel):
    """Token consumption and estimated cost log for Tier C extraction.

    Tracks token usage and estimated API cost per triage extraction event
    to satisfy FlyRank Concept 7 cost tracking requirements.
    """

    model_config = ConfigDict(extra="ignore")

    prompt_tokens: int = Field(
        default=0, ge=0, description="Number of tokens in prompt."
    )
    completion_tokens: int = Field(
        default=0, ge=0, description="Number of tokens in completion."
    )
    total_tokens: int = Field(default=0, ge=0, description="Total tokens consumed.")
    cost_usd: float = Field(
        default=0.0, ge=0.0, description="Estimated inference cost in USD."
    )


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
        cost_log: Token usage and calculated inference cost log for this job.
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
    cost_log: ExtractorCostLog = Field(
        default_factory=ExtractorCostLog,
        description="Token consumption and estimated inference cost log.",
    )
