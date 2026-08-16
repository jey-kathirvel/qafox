"""Normalized contracts shared by smart-data adapters.

Contracts contain data only. Uploaded projects must never be imported or
executed to populate them; adapters inspect untrusted text or parsed ASTs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SemanticType(str, Enum):
    UNKNOWN = "unknown"
    EMAIL = "email"
    PHONE = "phone"
    HUMAN_NAME = "human-name"
    ENTITY_NAME = "entity-name"
    IDENTIFIER = "identifier"
    FOREIGN_KEY = "foreign-key"
    UUID = "uuid"
    INTEGER = "integer"
    DECIMAL = "decimal"
    CURRENCY = "currency"
    BOOLEAN = "boolean"
    DATE = "date"
    DATETIME = "datetime"
    URL = "url"
    FILE = "file"
    ENUM = "enum"
    OBJECT = "object"
    ARRAY = "array"
    CREDENTIAL = "credential"
    TOKEN = "token"
    SECRET = "secret"


class AuthenticationMode(str, Enum):
    UNKNOWN = "unknown"
    PUBLIC = "public"
    OPTIONAL = "optional-authentication"
    SESSION = "required-session"
    BEARER = "bearer-token"
    API_KEY = "api-key"
    BASIC = "basic-authentication"
    OAUTH2 = "oauth2"
    CREDENTIAL_SUBMISSION = "credential-submission"
    DYNAMIC_CSRF = "dynamic-csrf"
    COOKIE_SESSION = "cookie-session-establishment"
    MFA = "mfa-dependent"
    MULTI_STEP = "multi-step-authentication"


class ActionKind(str, Enum):
    SETUP = "setup"
    CLEANUP = "cleanup"


@dataclass(frozen=True, slots=True)
class ProjectRef:
    root: Path
    owner_user_id: int | None = None
    project_public_id: str = ""


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    source_file: str
    source_line: int | None = None
    source_column: int | None = None
    evidence_type: str = "source"
    excerpt: str = ""
    confidence_score: int = 0


@dataclass(frozen=True, slots=True)
class DetectionResult:
    framework: str
    detected: bool
    confidence_score: int
    version: str = ""
    evidence: tuple[SourceEvidence, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConstraintContract:
    name: str
    value: Any = None
    message: str = ""
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyRelationship:
    resource: str
    field: str
    relationship: str = "requires"
    confidence_score: int = 0


@dataclass(frozen=True, slots=True)
class FieldContract:
    name: str
    semantic_type: SemanticType = SemanticType.UNKNOWN
    data_type: str = "unknown"
    required: bool = False
    default_value: Any = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: str = ""
    format: str = ""
    enum_values: tuple[Any, ...] = ()
    nullable: bool = False
    secret: bool = False
    dependency: DependencyRelationship | None = None
    generation_strategy: str = ""
    generated_value: Any = None
    confidence_score: int = 0
    source_file: str = ""
    source_line: int | None = None
    editable: bool = True
    constraints: tuple[ConstraintContract, ...] = ()
    children: tuple[FieldContract, ...] = ()
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class SchemaContract:
    name: str
    schema_type: str
    fields: tuple[FieldContract, ...] = ()
    content_type: str = ""
    required: bool = False
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthFlowContract:
    name: str
    modes: tuple[AuthenticationMode, ...]
    required: bool = False
    configuration_reference: str = ""
    steps: tuple[str, ...] = ()
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class PrerequisiteContract:
    resource: str
    field: str = ""
    required: bool = True
    placeholder: str = ""
    reason: str = ""
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RuntimeVariableContract:
    name: str
    source_step: str
    extraction: str
    target_type: str = "string"
    secret: bool = False
    confidence_score: int = 0


@dataclass(frozen=True, slots=True)
class WorkflowActionContract:
    name: str
    kind: ActionKind
    route_reference: str
    produces: tuple[RuntimeVariableContract, ...] = ()
    requires_approval: bool = False
    same_run_only: bool = True
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RouteContract:
    method: str
    path: str
    framework: str
    operation_id: str = ""
    summary: str = ""
    request_schemas: tuple[SchemaContract, ...] = ()
    response_schemas: Mapping[str, SchemaContract] = field(default_factory=dict)
    authentication: tuple[AuthFlowContract, ...] = ()
    prerequisites: tuple[PrerequisiteContract, ...] = ()
    runtime_variables: tuple[RuntimeVariableContract, ...] = ()
    setup_actions: tuple[WorkflowActionContract, ...] = ()
    cleanup_actions: tuple[WorkflowActionContract, ...] = ()
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TestDataSource:
    name: str
    source_type: str
    values: Mapping[str, Any] = field(default_factory=dict)
    contains_secrets: bool = False
    confidence_score: int = 0
    evidence: tuple[SourceEvidence, ...] = ()
