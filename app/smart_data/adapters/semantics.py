"""Framework-neutral semantic classification for static adapter evidence.

Adapters map framework-specific type names and validators onto the same
FieldContract semantics. Uploaded source is never executed.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.smart_data.contracts import (
    ConstraintContract,
    DependencyRelationship,
    FieldContract,
    SemanticType,
    SourceEvidence,
)


EMAIL_TOKENS = (
    "emailstr",
    "email",
    "emailfield",
    "emailaddress",
    "isemail",
    "emailaddressattribute",
)
UUID_TOKENS = ("uuid", "uniqueidentifier", "guid", "isuuid")
DATE_TOKENS = ("datetime", "date-time", "timestamp", "isdate", "isdatetime")
URL_TOKENS = ("url", "uri", "httpurl", "anyhttpurl")


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "")


def token_set(*parts: Any) -> str:
    return " ".join(_norm(part) for part in parts if part)


def semantic_from_hints(
    name: str,
    type_hint: str = "",
    format_hint: str = "",
    validators: Iterable[str] = (),
) -> tuple[SemanticType, str]:
    """Return (semantic_type, canonical_format) shared across adapters."""
    lowered = _norm(name)
    blob = token_set(name, type_hint, format_hint, " ".join(validators))
    format_hint = _norm(format_hint)
    if format_hint == "email" or any(token in blob for token in EMAIL_TOKENS):
        return SemanticType.EMAIL, "email"
    if format_hint == "uuid" or any(token in blob for token in UUID_TOKENS):
        return SemanticType.UUID, "uuid"
    if format_hint in {"date-time", "datetime"} or "datetime" in blob or "timestamp" in blob:
        return SemanticType.DATETIME, "date-time"
    if format_hint == "date" or blob.endswith("date") or "isdate" in blob:
        return SemanticType.DATE, "date"
    if format_hint in {"uri", "url"} or any(token in blob for token in URL_TOKENS):
        return SemanticType.URL, "uri"
    if any(token in blob for token in ("password", "secret", "token", "credential", "apikey", "api_key")):
        if "token" in lowered or "token" in blob:
            return SemanticType.SECRET, "password"
        return SemanticType.SECRET, "password"
    if "bool" in blob:
        return SemanticType.BOOLEAN, ""
    if any(token in blob for token in ("int", "integer", "long", "bigint", "numberint")):
        if lowered.endswith("_id") or (lowered.endswith("id") and lowered != "id"):
            return SemanticType.FOREIGN_KEY, ""
        if lowered == "id":
            return SemanticType.IDENTIFIER, ""
        return SemanticType.INTEGER, ""
    if any(token in blob for token in ("float", "double", "decimal", "number")):
        return SemanticType.DECIMAL, ""
    if any(token in blob for token in ("list", "array", "vector", "iset")):
        return SemanticType.ARRAY, ""
    if "enum" in blob or "literal" in blob:
        return SemanticType.ENUM, ""
    if lowered.endswith("_id") or (lowered.endswith("id") and lowered != "id"):
        return SemanticType.FOREIGN_KEY, ""
    if lowered == "id":
        return SemanticType.IDENTIFIER, ""
    return SemanticType.UNKNOWN, format_hint


def constraint(name: str, value: Any, evidence: tuple[SourceEvidence, ...] = (), score: int = 90) -> ConstraintContract:
    return ConstraintContract(name, value, confidence_score=score, evidence=evidence)


def field_contract(
    name: str,
    *,
    type_hint: str = "string",
    format_hint: str = "",
    validators: Iterable[str] = (),
    required: bool = False,
    nullable: bool = False,
    default_value: Any = None,
    minimum: int | float | None = None,
    maximum: int | float | None = None,
    min_length: int | None = None,
    max_length: int | None = None,
    pattern: str = "",
    enum_values: tuple[Any, ...] = (),
    evidence: tuple[SourceEvidence, ...] = (),
    source_file: str = "",
    source_line: int | None = None,
    extra_constraints: tuple[ConstraintContract, ...] = (),
    children: tuple[FieldContract, ...] = (),
    confidence_score: int = 88,
    exclusive_minimum: int | float | bool | None = None,
    exclusive_maximum: int | float | bool | None = None,
) -> FieldContract:
    semantic, canonical_format = semantic_from_hints(name, type_hint, format_hint, validators)
    dependency = None
    if semantic is SemanticType.FOREIGN_KEY:
        dependency = DependencyRelationship(name.removesuffix("_id").removesuffix("Id").removesuffix("_ID"), "id", confidence_score=75)
    constraints = list(extra_constraints)
    if minimum is not None:
        constraints.append(constraint("minimum", minimum, evidence))
    if maximum is not None:
        constraints.append(constraint("maximum", maximum, evidence))
    if min_length is not None:
        constraints.append(constraint("minLength", min_length, evidence))
    if max_length is not None:
        constraints.append(constraint("maxLength", max_length, evidence))
    if pattern:
        constraints.append(constraint("pattern", pattern, evidence))
    if canonical_format:
        constraints.append(constraint("format", canonical_format, evidence))
    if enum_values:
        constraints.append(constraint("enum", list(enum_values), evidence))
    return FieldContract(
        name=name,
        semantic_type=semantic,
        data_type=type_hint or "unknown",
        required=required,
        default_value=default_value,
        minimum=minimum,
        maximum=maximum,
        min_length=min_length,
        max_length=max_length,
        pattern=pattern,
        format=canonical_format or format_hint,
        enum_values=enum_values,
        nullable=nullable,
        secret=semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN},
        dependency=dependency,
        confidence_score=confidence_score,
        source_file=source_file,
        source_line=source_line,
        constraints=tuple(constraints),
        children=children,
        evidence=evidence,
        exclusive_minimum=exclusive_minimum,
        exclusive_maximum=exclusive_maximum,
    )
