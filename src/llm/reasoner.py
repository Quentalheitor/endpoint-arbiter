from pathlib import PureWindowsPath
from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    Field,
    computed_field,
    field_validator,
    model_validator,
)
import re
import logging
from enum import StrEnum
from typing import Dict, List, Literal, Optional, Set, Any, Union
from pydantic.networks import IPvAnyAddress
import unicodedata


logger = logging.getLogger("endpoint_arbiter.privileged_reasoner")


STRICT_MODEL_CONFIG = ConfigDict(strict=True, extra="forbid")


class Intent(StrEnum):
    DOWNLOAD_EXECUTE = "DOWNLOAD_EXECUTE"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    DISCOVERY_RECONNAISSANCE = "DISCOVERY_RECONNAISSANCE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    PERSISTENCE_ESTABLISHMENT = "PERSISTENCE_ESTABLISHMENT"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    BENIGN_ADMINISTRATION = "BENIGN_ADMINISTRATION"


class Suspicious_Construct_Types(StrEnum):
    ENCODED_PAYLOAD_DETECTED = "ENCODED_PAYLOAD_DETECTED"
    VARIABLE_EXPANSION_USED = "VARIABLE_EXPANSION_USED"
    STRING_CONCATENATION_OBFUSCATION = "STRING_CONCATENATION_OBFUSCATION"
    UNUSUAL_PARENT_PROCESS_LINEAGE = "UNUSUAL_PARENT_PROCESS_LINEAGE"
    NONE = "NONE"


class Rule_Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    NONE = "NONE"


class MLReasonCode(StrEnum):
    HIGH_COMMAND_ENTROPY = "HIGH_COMMAND_ENTROPY"
    OFF_HOURS_EXECUTION = "OFF_HOURS_EXECUTION"
    ANOMALOUS_PARENT_CHILD_RELATION = "ANOMALOUS_PARENT_CHILD_RELATION"
    EXCESSIVE_FLAG_DENSITY = "EXCESSIVE_FLAG_DENSITY"
    KNOWN_ADMIN_PROFILE = "KNOWN_ADMIN_PROFILE"
    DEFAULT_BENIGN_SCORE = "DEFAULT_BENIGN_SCORE"


class Destination_network_observables(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    IP_ADDRESS: Optional[Union[IPvAnyAddress, str]] = None
    FQDN: Optional[str] = Field(
        default=None, max_length=253, pattern=r"^[a-zA-Z0-9.-]+$"
    )
    DESTINATION_PORT: int = Field(ge=1, le=65535)
    TRANSPORT_PROTOCOL: Literal["TCP", "UDP", "ICMP"]

    @model_validator(mode="after")
    def validate_destination_present(self) -> "Destination_network_observables":
        if self.IP_ADDRESS is None and self.FQDN is None:
            raise ValueError(
                "At least a single destination (IP or FQDN) must be mentioned"
            )
        return self


class Obfuscation_categories(StrEnum):
    NONE = "None"
    BASE64 = "Base64"
    CONCATENATION = "Concatenation"
    VARIABLE_EXPANSION = "Variable_Expansion"
    MIXED = "Mixed"


class TriageVerdict(StrEnum):
    MALICIOUS = "Malicious"
    BENIGN = "Benign"
    NEEDS_REVIEW = "Needs-Review"


class ResponsePriority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Normalized_Target_Binaries(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    PROCESS_BINARY_NAME: str
    PARENT_BINARY_NAME: Optional[str] = None
    EXECUTION_PRIVILEGE: bool

    @field_validator("PROCESS_BINARY_NAME", "PARENT_BINARY_NAME", mode="before")
    @classmethod
    def string_cleaning(cls, value: str) -> str:
        if not isinstance(value, str):
            return value
        clean_char = []
        for x in value:
            category = unicodedata.category(x)
            if category not in ("Cf", "Cc"):
                clean_char.append(x)
        clean_char = "".join(clean_char)
        leaf_filename = PureWindowsPath(clean_char.strip("\"'/\\ "))
        EXTENSOES_WIN_EXEC = {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".bin",
        }
        if leaf_filename.suffix.lower() in EXTENSOES_WIN_EXEC:
            return leaf_filename.name.lower()
        else:
            raise ValueError("Filename does not posses approved executable extension")

    @field_validator("PROCESS_BINARY_NAME", "PARENT_BINARY_NAME", mode="after")
    @classmethod
    def enforce_string_rules(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if re.match("^[a-z0-9._-]+$", value) and len(value) <= 64:
            return value
        else:
            raise ValueError(f"Filename '{value}' breaks regex constrictions")


class Execution_priviledges(StrEnum):
    ELEVATED = "ELEVATED"
    STANDART = "STANDART"
    SYSTEM = "SYSTEM"


SEVERITY_WEIGHTS: Dict[Rule_Severity, int] = {
    Rule_Severity.CRITICAL: 5,
    Rule_Severity.HIGH: 4,
    Rule_Severity.MEDIUM: 3,
    Rule_Severity.LOW: 2,
    Rule_Severity.INFORMATIONAL: 1,
    Rule_Severity.NONE: 0,
}

TECHNIQUE_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


class Rule_Match_TierA(BaseModel):
    RULE_IDENTIFIER: str = Field(..., pattern=r"^sigma-[a-z0-9_-]+$")
    RULE_SEVERITY: Rule_Severity
    MITRE_ATTACK_TECH: list[str] = Field(default_factory=list)
    RULE_TITLE: Optional[str] = None

    @field_validator("MITRE_ATTACK_TECH")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        for x in value:
            if not TECHNIQUE_REGEX.match(x):
                raise ValueError(f"Invalid MITRE ATT&CK ID: {x}")
        return value


class Aggregate_TierA_container(BaseModel):
    MATCHED_RULES: list[Rule_Match_TierA] = []

    @computed_field
    @property
    def max_sev(self) -> Rule_Severity:
        if not self.MATCHED_RULES:
            return Rule_Severity.NONE
        return max(
            (rule.RULE_SEVERITY for rule in self.MATCHED_RULES),
            key=lambda sev: SEVERITY_WEIGHTS[sev],
        )

    @computed_field
    @property
    def attack_techniques(self) -> list[str]:
        unique: Set[str] = set()
        for rule in self.MATCHED_RULES:
            unique.update(rule.MITRE_ATTACK_TECH)
        return sorted(list[unique])

    @computed_field
    @property
    def is_sev_high(self) -> bool:
        if self.max_sev == "HIGH" or self.max_sev == "CRITICAL":
            return True
        else:
            return False


class TierB_Classifier(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    MALICIOUS_PROBABILITY: float = Field(..., ge=0.0, le=1.0)
    REASON_CODES: List[MLReasonCode] = Field(default_factory=list)


class Enrichment_Observable(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    OBSERVABLE_VALUE: str
    OBSERVABLE_TYPE: Literal["ip_address", "domain", "file_hash"]
    REPUTATION_VERDICT: Literal[
        "Malicious", "Suspicious", "Neutral", "Benign", "Unknown"
    ]
    REPUTATION_SCORE: int = Field(..., ge=0, le=100)
    THREAT_CATEGORIES: List[str] = Field(default_factory=list)
    ASN: Optional[str] = None


class Valid_Target_Roster(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    HOSTS: List[str] = Field(default_factory=list)
    USERS: List[str] = Field(default_factory=list)
    IPS: List[str] = Field(default_factory=list)


class Provenance_Block(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    EVENT_ID: str = Field(..., pattern=r"^evt-[a-zA-Z0-9_-]+$")
    EVENT_HASH: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    TIMESTAMP: str


class Extractor_Signals(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    PRIMARY_INTENT: Intent
    SUB_INTENTS: List[Intent] = Field(default_factory=list)
    SUSPICIOUS_CONSTRUCTS: List[Suspicious_Construct_Types] = Field(
        default_factory=list
    )
    OBFUSCATION_TYPE: Obfuscation_categories


class Atomic_Tokens(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    NORMALIZED_PROCESS: Normalized_Target_Binaries
    SANITIZED_TARGETS: List[Destination_network_observables] = Field(
        default_factory=list
    )


class PriviledgedReasonerInput(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    provenance_block: Provenance_Block
    extractor_signal: Extractor_Signals
    atomic_tokens: Atomic_Tokens
    tier_a_container: Aggregate_TierA_container
    tier_b_classifier: TierB_Classifier
    context_enrichment: List[Enrichment_Observable] = Field(default_factory=list)
    target_roster: Valid_Target_Roster


class Technical_Mapping(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    FRAMEWORK: Literal["MITRE_ATTACK", "MITRE_ATLAS"] = "MITRE_ATTACK"
    ID: str = Field(..., pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")
    NAME: str


class Recommended_Response(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    ACTION: str
    TARGET: str
    PRIORITY: ResponsePriority


class Priviledged_Reasoner_Output(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    verdict: TriageVerdict
    risk_score: int = Field(..., ge=0, le=100)
    confidence_score: int = Field(..., ge=0, le=100)
    mapped_techniques: List[Technical_Mapping] = Field(default_factory=list)
    justification: str
    recommended_response: List[Recommended_Response] = Field(default_factory=list)

    def inspect_action_list(self, roster: Valid_Target_Roster) -> None:
        allow = set(roster.HOSTS + roster.USERS + roster.IPS)
        possible_actions: List[Recommended_Response] = []

        for x in self.recommended_response:
            if x.TARGET in allow:
                possible_actions.append(x)
            else:
                logger.warning(
                    "Invariant 5 triggered: Unauthorized target '%s' discarded from action '%s'.",
                    x.TARGET,
                    x.ACTION,
                )
        self.recommended_response = possible_actions


SYSTEM_PROMPT = """You are the Priviledged Reasoner of an endpoint security triage pipeline (SOC).
Your responsibility is to rate the structured behavior indicators, pre-computed deterministic rules, statistic
score and the intelligence of threats to deliver a final verdict, risk score, and MITRE ATT&CK mapping.

INVARIANTS AND SECURITY GUIDELINES:
1. You must receive only structured and verified data.
2. Do not attempt to guess raw command lines. Base your decisions strictly on the intention enums, tokens, and severities provided
3. If there is any divergence between the rules and the statistical inference, consider the Tier A severity
4. You MUST respond strictly with the solicited JSON schema"""


def user_prompt_constructor(input_data: PriviledgedReasonerInput) -> str:
    return (
        f"Analyze the following structured security event and emit the triage verdict: \n\n"
        f"{input_data.model_dump_json(indent=2)}"
    )


def priviledged_reasoner_executer(
    raw_input: Dict[str, Any], llm_client: Any = None, model_name: str = "gpt-4o"
) -> Dict[str, Any]:
    try:
        valid_input = PriviledgedReasonerInput.model_validate(raw_input)
    except (ValidationError, ValueError) as e:
        logger.exception(
            "Invariant 2 triggered: Input schema validation failure: %s", e
        )
        return {
            "verdict": TriageVerdict.NEEDS_REVIEW.value,
            "state": "degraded",
            "risk_score": 50,
            "confidence_score": 0,
            "justification": f"Automatic degradation due to schema violation or suspicious token: {str(e)}",
            "tier_trace": [
                {"tier": "C", "role": "reasoner", "status": "validation_failed"}
            ],
            "recommended_response": [],
            "techniques": [],
        }
    try:
        if llm_client is None:
            from openai import OpenAI

            llm_client = OpenAI()
        user_prompt = user_prompt_constructor(valid_input)
        response = llm_client.beta.chat.completions.parse(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format=Priviledged_Reasoner_Output,
            temperature=0.0,
            seed=42,
        )
        parsed_output: Priviledged_Reasoner_Output = response.choices[0].message.parsed
    except Exception as e:
        logger.error("Invariante 2 triggered: LLM provder failure: %s", e)
        return {
            "verdict": TriageVerdict.NEEDS_REVIEW.value,
            "state": "degraded",
            "risk_score": 60 if valid_input.tier_a_container.is_sev_high else 30,
            "confidence_score": 0,
            "justification": f"Degradation caused by unavailable service or bad output coming from LLM provider: {str(e)}",
            "tier_trace": [{"tier": "C", "role": "reasoner", "status": "llm_error"}],
            "recommended_response": [],
            "techniques": [],
        }
    if parsed_output is None:
        logger.error(
            "Invariant 12 triggered: Model refused processing or generated null output"
        )
        return {
            "verdict": TriageVerdict.NEEDS_REVIEW.value,
            "state": "degraded",
            "risk_score": 50,
            "confidence_score": 0,
            "justification": "Degradation due to refusal or null exit from the language model",
            "tier_trace": [
                {"tier": "C", "role": "reasoner", "status": "model_refusal"}
            ],
            "recommended_response": [],
            "techniques": [],
        }
    parsed_output.inspect_action_list(valid_input.target_roster)
    final_verdict = parsed_output.verdict
    if valid_input.tier_a_container.is_sev_high:
        if parsed_output.verdict == TriageVerdict.BENIGN:
            logger.warning(
                "Invariant 1 triggered: Downgrading attempt blocked. \n High confidence '%s' forces Malicious verdict",
                valid_input.tier_a_container.max_sev,
            )
            final_verdict = TriageVerdict.MALICIOUS

    result = parsed_output.model_dump()
    result["verdict"] = final_verdict.value
    result["state"] = "complete"
    result["tier_trace"] = [
        {"tier": "C", "role": "reasoner", "model_version": model_name}
    ]
    return result
