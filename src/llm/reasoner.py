from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
import unicodedata
from pathlib import PureWindowsPath
from pydantic.networks import IPvAnyAddress
import re
from pydantic import field_validator


STRICT_MODEL_CONFIG = ConfigDict(strict=True, extra="forbid")


class Primary_intent(StrEnum):
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


class Destination_network_observables(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    IP_ADRESS: IPvAnyAddress
    FQDN: str = Field(max_length=253, pattern=r"^[a-zA-Z0-9.-]+$")
    DESTINATION_PORT: int = Field(ge=1, le=65535)
    TRANSPORT_PROTOCOL: list[Literal["TCP", "UDP", "ICMP"]]


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


class Obfuscation_categories(StrEnum):
    BASE64_UTF16LE = "BASE_UTF16LE"
    BASE64_ASCII = "BASE64_ASCII"
    STRING_CONCAT = "STRING_CONCAT"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    NONE = "NONE"


class Obfuscation_signature(BaseModel):
    signature: Obfuscation_categories


class Rule_Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Rule_Match_TierA(BaseModel):
    RULE_IDENTIFIER: str
    RULE_SEVERITY: Rule_Severity
    MITRE_ATTACK_TECH: list[str]
    RULE_TITLE: str | None = None


class Maximum_severity_level(StrEnum):
    MAX = list[Rule_Match_TierA] = None
    # @field_validator
    # @classmethod


class Aggregate_TierA_container(BaseModel):
    MATCHED_RULES: list[Rule_Match_TierA] = []
    MAXIMUM_SEVERITY_LEVEL: str
