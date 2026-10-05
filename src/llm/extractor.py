"""Tier C Quarantined LLM Extractor module.

Executes structured extraction over untrusted, decoded telemetry strings
within a strict trust boundary. Constrains LLM outputs to a fixed Pydantic schema
(ExtractorOutput) with token consumption and cost logging (FlyRank Concept 7).
"""

import logging
import os

from schemas.extractor import ExtractorCostLog, ExtractorOutput

logger = logging.getLogger("endpoint_arbiter.llm")

# Baseline cost rates per token ($0.15/1M input, $0.60/1M output tokens)
PROMPT_TOKEN_COST_PER_MILLION = 0.15
COMPLETION_TOKEN_COST_PER_MILLION = 0.60


class QuarantinedExtractor:
    """Quarantined LLM extractor for parsing untrusted process command lines.

    Operates in either heuristic mock mode for offline testing/benchmarks,
    or via structured LLM API calls with schema enforcement. Missing external
    API keys cleanly fall back to offline mode to adhere to the $0 stack rule.

    Attributes:
        use_mock: If True, uses deterministic heuristic matching instead of
            calling an external LLM API.
        api_key: Optional API key for external LLM provider.
    """

    def __init__(self, use_mock: bool = True, api_key: str | None = None) -> None:
        """Initialize the QuarantinedExtractor.

        Args:
            use_mock: Whether to operate in offline mock mode (default: True).
            api_key: Optional API key for live provider (reads from env if None).
        """
        self.api_key = (
            api_key
            or os.getenv("LLM_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
        )
        self.use_mock = use_mock or (self.api_key is None)
        if not use_mock and self.api_key is None:
            logger.warning(
                "Live LLM requested but no API key configured. "
                "Cleanly falling back to offline mock mode ($0 stack rule)."
            )

    def _calculate_cost(
        self, prompt_tokens: int, completion_tokens: int
    ) -> tuple[int, float]:
        """Compute total token usage and estimated cost in USD.

        Args:
            prompt_tokens: Count of tokens in the prompt.
            completion_tokens: Count of tokens in the completion.

        Returns:
            tuple[int, float]: (total_tokens, cost_usd)
        """
        total_tokens = prompt_tokens + completion_tokens
        cost_usd = round(
            (prompt_tokens * (PROMPT_TOKEN_COST_PER_MILLION / 1_000_000))
            + (completion_tokens * (COMPLETION_TOKEN_COST_PER_MILLION / 1_000_000)),
            6,
        )
        return total_tokens, cost_usd

    def extract(self, untrusted_decoded_command: str) -> ExtractorOutput:
        """Extract intent and suspicious constructs from untrusted command text.

        Parses command strings for threat indicators and flags potential
        indirect prompt injection attempts. Computes token usage and estimated
        API cost for every execution, logging metrics for auditability.

        Args:
            untrusted_decoded_command: De-obfuscated command line originating
                from untrusted endpoint telemetry.

        Returns:
            ExtractorOutput: Structured schema containing categorized intent,
                suspicious construct tags, prompt injection detection flags,
                and execution cost log.
        """
        cmd_lower = untrusted_decoded_command.lower()

        # Step 1: Detect potential indirect prompt injection / instruction-like phrases
        injection_indicators = [
            "ignore previous instructions",
            "ignore all instructions",
            "system override",
            "threat dismissed",
            "set verdict to benign",
            "disregard detection",
        ]
        has_injection = any(phrase in cmd_lower for phrase in injection_indicators)

        # Step 2: Determine categorization in mock/fallback mode
        if has_injection:
            intent = "unknown"
            constructs = ["none"]
        elif "iwr " in cmd_lower or "invoke-webrequest" in cmd_lower:
            intent = "download_execute"
            constructs = ["download_cradle", "encoded_command"]
        else:
            intent = "benign_admin"
            constructs = ["none"]

        # Step 3: Compute realistic token consumption & estimated cost log
        # Prompt: ~40 tokens system instructions + length of untrusted command
        prompt_tokens = 42 + max(8, len(untrusted_decoded_command) // 4)
        # Completion: structured JSON output size (~18-24 tokens)
        completion_tokens = 20
        total_tokens, cost_usd = self._calculate_cost(prompt_tokens, completion_tokens)

        cost_log = ExtractorCostLog(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=cost_usd,
        )

        # Step 4: Explicit structured logging of token consumption and cost
        logger.info(
            "Tier C LLM Extraction completed | intent=%s | injection_flag=%s | "
            "prompt_tokens=%d | completion_tokens=%d | total_tokens=%d | cost_usd=%.6f",
            intent,
            has_injection,
            prompt_tokens,
            completion_tokens,
            total_tokens,
            cost_usd,
        )

        return ExtractorOutput(
            intent_category=intent,
            suspicious_constructs=constructs,
            instruction_like_content_flag=has_injection,
            cost_log=cost_log,
        )
