from pathlib import PureWindowsPath
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)
import re
import logging
from enum import StrEnum
from typing import Dict, List, Literal, Optional, Set
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


class MLReasonCode(StrEnum):
    HIGH_COMMAND_ENTROPY = "HIGH_COMMAND_ENTROPY"
    OFF_HOURS_EXECUTION = "OFF_HOURS_EXECUTION"
    ANOMALOUS_PARENT_CHILD_RELATION = "ANOMALOUS_PARENT_CHILD_RELATION"
    EXCESSIVE_FLAG_DENSITY = "EXCESSIVE_FLAG_DENSITY"
    KNOWN_ADMIN_PROFILE = "KNOWN_ADMIN_PROFILE"
    DEFAULT_BENIGN_SCORE = "DEFAULT_BENIGN_SCORE"


class Destination_network_observables(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    IP_ADRESS: IPvAnyAddress
    FQDN: str = Field(max_length=253, pattern=r"^[a-zA-Z0-9.-]+$")
    DESTINATION_PORT: int = Field(ge=1, le=65535)
    TRANSPORT_PROTOCOL: list[Literal["TCP", "UDP", "ICMP"]]


class Obfuscation_categories(StrEnum):
    BASE64_UTF16LE = "BASE_UTF16LE"
    BASE64_ASCII = "BASE64_ASCII"
    STRING_CONCAT = "STRING_CONCAT"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    NONE = "NONE"


class TriageVerdict(StrEnum):
    MALICIOUS = "Malicious"
    BENIGN = "Benign"
    NEEDS_REVIEW = "Needs-Review"


class ResponsePriority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Normalized_Target_Binariees(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    PROCESS_BINARY_NAME: str
    PARENT_BINARY_NAME: str
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
            ".bat",
            ".cmd",
            ".msi",
            ".com",
            ".pif",
            ".scr",
            ".vbs",
            ".wsf",
            ".ps1",
        }
        if leaf_filename.suffix.lower() in EXTENSOES_WIN_EXEC:
            return leaf_filename.suffix.lower()
        else:
            raise ValueError("Filename does not posses approved executable extension")

    @field_validator("PROCESS_BINARY_NAME", "PARENT_BINARY_NAME", mode="after")
    @classmethod
    def enforce_string_rules(cls, value: str) -> str:
        if re.match("^[a-z0-9._-]+$", value) and len(value) <= 64:
            return value
        else:
            raise ValueError(f"Filename '{value}' breaks regex constrictions")


class Execution_priviledges(StrEnum):
    ELEVATED = "ELEVATED"
    STANDART = "STANDART"
    SYSTEM = "SYSTEM"


class Obfuscation_signature(BaseModel):
    signature: Obfuscation_categories


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

    @field_validator("attack_techniques")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        for x in value:
            if not TECHNIQUE_REGEX.match:
                raise ValueError(f"Invalid MITRE ATT&CK ID: {x}")
        return value


class Aggregate_TierA_container(BaseModel):
    MATCHED_RULES: list[Rule_Match_TierA] = []

    @property
    @computed_field
    def max_sev(self) -> Rule_Severity:
        if not self.MATCHED_RULES:
            return Rule_Severity.NONE
        return max(
            (rule.severity for rule in self.MATCHED_RULES),
            key=lambda sev: SEVERITY_WEIGHTS[sev],
        )

    @property
    @computed_field
    def attack_techniques(self) -> list[str]:
        unique: Set[str] = set()
        for rule in self.MATCHED_RULES:
            unique.update(rule.MITRE_ATTACK_TECH)
        return sorted(list[unique])

    @property
    @computed_field
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
    REPUTATION_SCOR: int = Field(..., ge=0, le=100)
    THREATH_CATEGORIES: List[str] = Field(default_factory=list)
    ASN: Optional[str] = None


class Valid_Target_Roster(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    HOSTS: List[str] = Field(default_factory=list)
    USERS: List[str] = Field(default_factory=list)
    IPS: List[str] = Field(default_factory=list)


class Provenance_Block(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    EVENT_ID: str = Field(..., pattern=r"evt-[a-zA-Z0-9_-]+$")
    EVENT_HASH: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    TIMESTAMP: str


class Extractor_Signals(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    PRIMARY_INTENT: Intent
    SUB_INTENTS: List[Intent] = Field(default_factory=list)
    SUSPICIOUS_CONTRUCTS: List[Suspicious_Construct_Types] = Field(default_factory=list)
    OBFUSCATION_TYPE: Obfuscation_signature


class Atomic_Tokens(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    NORMALIZED_PROCESS: Normalized_Target_Binariees
    SANITIZED_TARGETS: List[Destination_network_observables] = Field(
        default_factory=list
    )


class PriviledgedReasonerInput(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    PROVENANCE_BLOCK: Provenance_Block
    EXTRACTOR_SIGNALS: Extractor_Signals
    ATOMIC_TOKENS: Atomic_Tokens
    TIER_A_CONTAINER: Aggregate_TierA_container
    TIER_B_CLASSIFIER: TierB_Classifier
    CONTEXT_ENRICHMENT: List[Enrichment_Observable] = Field(default_factory=list)
    TARGET_ROSTER: Valid_Target_Roster


class Technical_Mapping(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    FRAMEWORK: Literal["MITRE_ATTACK", "MITRE_ATLAS"] = "MITRE_ATTACK"
    ID: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    NAME: str


class Recommended_Response(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    ACTION: str
    TARGET: str
    PRIORITY: ResponsePriority


class Priviledged_Reasoner_Output(BaseModel):
    model_config = STRICT_MODEL_CONFIG
    VERDICT: TriageVerdict
    RISK_SCORE: int = Field(..., ge=0, le=100)
    CONFIDENCE_SCORE: int = Field(..., ge=0, le=100)
    MAPPED_TECHNIQUES: List[Technical_Mapping] = Field(default_factory=list)
    JUSTIFICATION: str
    RECOMMENDED_RESPONSE = List[Recommended_Response] = Field(default_factory=list)

    def inspect_action_list(self, roster=Valid_Target_Roster) -> None:
        allow = set(roster.HOSTS, roster.USERS, roster.IPS)
        possible_actions: List[Recommended_Response] = []

        for x in self.RECOMMENDED_RESPONSE:
            if x.TARGET in allow:
                possible_actions.append(x)
            else:
                logger.warning(
                    "Invariant 15 triggered: Unauthorized target '%s' discarded from action '%s'.",
                    x.TARGET,
                    x.ACTION,
                )
        self.RECOMMENDED_RESPONSE = possible_actions
