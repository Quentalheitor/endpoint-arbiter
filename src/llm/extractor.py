"""Tier C Quarantined LLM Extractor module.

Executes structured extraction over untrusted, decoded telemetry strings
within a strict trust boundary. Constrains LLM outputs to a fixed Pydantic schema
(ExtractorOutput) to prevent prompt injection payloads from escaping the sandbox
or steering privileged downstream decisions.
"""

from schemas.extractor import ExtractorOutput


class QuarantinedExtractor:
    """Quarantined LLM extractor for parsing untrusted process command lines.

    Operates in either heuristic mock mode for offline testing/benchmarks,
    or via structured LLM API calls with schema enforcement.

    Attributes:
        use_mock: If True, uses deterministic heuristic matching instead of
            calling an external LLM API.
    """

    def __init__(self, use_mock: bool = True) -> None:
        """Initialize the QuarantinedExtractor.

        Args:
            use_mock: Whether to operate in offline mock mode (default: True).
        """
        self.use_mock = use_mock

    def extract(self, untrusted_decoded_command: str) -> ExtractorOutput:
        """Extract intent and suspicious constructs from untrusted command text.

        Parses command strings for threat indicators and flags potential
        indirect prompt injection attempts.

        Args:
            untrusted_decoded_command: De-obfuscated command line originating
                from untrusted endpoint telemetry.

        Returns:
            ExtractorOutput: Structured schema containing categorized intent,
                suspicious construct tags, and prompt injection detection flags.
        """
        # Step 1: In mock mode, apply heuristic keyword detection for local testing.
        if self.use_mock:
            # Check for adversarial prompt injection phrases
            if "ignore previous instructions" in untrusted_decoded_command.lower():
                return ExtractorOutput(
                    intent_category="unknown",
                    suspicious_constructs=["none"],
                    instruction_like_content_flag=True,
                )

            # Check for web download and execute cradles (e.g. Invoke-WebRequest / iwr)
            if (
                "iwr " in untrusted_decoded_command
                or "invoke-webrequest" in untrusted_decoded_command.lower()
            ):
                return ExtractorOutput(
                    intent_category="download_execute",
                    suspicious_constructs=["download_cradle", "encoded_command"],
                    instruction_like_content_flag=False,
                )

            # Default benign admin activity classification
            return ExtractorOutput(
                intent_category="benign_admin",
                suspicious_constructs=["none"],
                instruction_like_content_flag=False,
            )

        # Step 2: Production execution placeholder for real LLM structured output.
        # Untrusted strings are placed in quarantined user role, schema constrained to ExtractorOutput.
        raise NotImplementedError(
            "Live LLM provider is not configured; initialize with use_mock=True."
        )
