"""Project-agnostic semantic and constraint-driven synthetic data."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from app.smart_data.contracts import FieldContract, SemanticType
from app.smart_data.placeholders import PlaceholderKind, build_placeholder


@dataclass(frozen=True, slots=True)
class GenerationResult:
    value: Any
    semantic_type: SemanticType
    strategy: str
    reason: str
    confidence_score: int
    status: str = "ready"
    editable: bool = True


def classify_field(field: FieldContract) -> tuple[SemanticType, int, str]:
    if field.semantic_type is not SemanticType.UNKNOWN:
        return field.semantic_type, max(field.confidence_score, 85), "adapter schema evidence"
    kind = field.data_type.lower()
    schema_format = field.format.lower()
    name = field.name.lower()
    if schema_format == "email" or "email" in kind:
        return SemanticType.EMAIL, 98, "schema format"
    if schema_format == "uuid" or "uuid" in kind:
        return SemanticType.UUID, 98, "schema format"
    if schema_format == "date-time" or "datetime" in kind:
        return SemanticType.DATETIME, 98, "schema format"
    if schema_format == "date" or kind == "date":
        return SemanticType.DATE, 98, "schema format"
    if schema_format in {"uri", "url"}:
        return SemanticType.URL, 98, "schema format"
    if field.enum_values:
        return SemanticType.ENUM, 98, "documented enum"
    if any(token in kind for token in ("bool", "boolean")):
        return SemanticType.BOOLEAN, 92, "declared data type"
    if any(token in kind for token in ("int", "integer")):
        return SemanticType.INTEGER, 92, "declared data type"
    if any(token in kind for token in ("float", "decimal", "number")):
        return SemanticType.DECIMAL, 92, "declared data type"
    if any(token in kind for token in ("list", "array", "tuple", "set")):
        return SemanticType.ARRAY, 92, "declared data type"
    if any(token in kind for token in ("dict", "object", "mapping")) or field.children:
        return SemanticType.OBJECT, 92, "declared data type"
    # Names are deliberately a weaker fallback than schema/type evidence.
    if name.endswith("_id") or (name.endswith("id") and name != "id"):
        return SemanticType.FOREIGN_KEY, 70, "name-based fallback"
    if any(token in name for token in ("password", "secret", "token", "credential", "api_key")):
        return SemanticType.SECRET, 70, "name-based fallback"
    if "email" in name:
        return SemanticType.EMAIL, 68, "name-based fallback"
    if any(token in name for token in ("phone", "mobile", "telephone")):
        return SemanticType.PHONE, 65, "name-based fallback"
    if name in {"first_name", "last_name", "full_name", "display_name"}:
        return SemanticType.HUMAN_NAME, 65, "name-based fallback"
    if name in {"url", "uri", "website", "homepage"}:
        return SemanticType.URL, 65, "name-based fallback"
    return SemanticType.UNKNOWN, 55, "generic fallback"


def _number(field: FieldContract, decimal: bool) -> int | float:
    minimum = field.minimum
    maximum = field.maximum
    value: int | float = minimum if minimum is not None else 1
    if maximum is not None:
        value = min(value, maximum)
    if decimal:
        return float(Decimal(str(value)).quantize(Decimal("0.01")))
    return int(value)


def _string_constraints(value: str, field: FieldContract) -> str:
    if field.max_length is not None:
        value = value[: max(0, field.max_length)]
    if field.min_length is not None and len(value) < field.min_length:
        value += "x" * (field.min_length - len(value))
    return value


def _pattern_valid(value: Any, field: FieldContract) -> bool:
    if not field.pattern or not isinstance(value, str):
        return True
    try:
        return re.fullmatch(field.pattern, value) is not None
    except re.error:
        return False


def generate_field(field: FieldContract, resource: str = "request") -> GenerationResult:
    semantic, confidence, evidence_reason = classify_field(field)
    reference = f"{resource}.{field.name}".strip(".")
    if field.secret or semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN}:
        return GenerationResult(build_placeholder(PlaceholderKind.SECRET_REF, f"configuration.{field.name}"), semantic, "encrypted-vault-reference", "secret values must remain in the configuration vault", confidence, "secret-reference-required")
    if field.enum_values:
        value = field.default_value if field.default_value in field.enum_values else field.enum_values[0]
        return GenerationResult(value, SemanticType.ENUM, "documented-enum", evidence_reason, confidence)
    if field.default_value is not None:
        return GenerationResult(field.default_value, semantic, "documented-default", "documented default value", 99)
    if field.dependency is not None or semantic is SemanticType.FOREIGN_KEY:
        dependency_resource = field.dependency.resource if field.dependency else resource
        dependency_field = field.dependency.field if field.dependency else field.name
        return GenerationResult(build_placeholder(PlaceholderKind.REQUIRED, f"{dependency_resource}.{dependency_field}"), semantic, "editable-prerequisite", "related resource must be supplied or created", confidence, "prerequisite-required")
    if semantic is SemanticType.EMAIL:
        value: Any = f"qafox-{uuid.uuid4().hex[:12]}@example.test"
        strategy = "synthetic-email"
    elif semantic is SemanticType.PHONE:
        value, strategy = "+12025550100", "reserved-phone"
    elif semantic is SemanticType.HUMAN_NAME:
        value, strategy = "QAFox Synthetic User", "synthetic-human-name"
    elif semantic is SemanticType.ENTITY_NAME:
        value, strategy = f"QAFox Synthetic {uuid.uuid4().hex[:8]}", "unique-entity-name"
    elif semantic is SemanticType.UUID:
        value, strategy = str(uuid.uuid4()), "uuid4"
    elif semantic is SemanticType.INTEGER:
        value, strategy = _number(field, False), "constraint-valid-integer"
    elif semantic in {SemanticType.DECIMAL, SemanticType.CURRENCY}:
        value, strategy = _number(field, True), "constraint-valid-decimal"
    elif semantic is SemanticType.BOOLEAN:
        value, strategy = False, "safe-boolean"
    elif semantic is SemanticType.DATE:
        value, strategy = "2030-01-15", "synthetic-date"
    elif semantic is SemanticType.DATETIME:
        value, strategy = "2030-01-15T12:00:00+00:00", "timezone-aware-datetime"
    elif semantic is SemanticType.URL:
        value, strategy = "https://example.test/qafox-fixture", "safe-example-url"
    elif semantic is SemanticType.FILE:
        value, strategy = build_placeholder(PlaceholderKind.SYNTHETIC, "file"), "safe-generated-file"
    elif semantic is SemanticType.OBJECT:
        value = {child.name: generate_field(child, reference).value for child in field.children}
        strategy = "recursive-object"
    elif semantic is SemanticType.ARRAY:
        count = 1
        for constraint in field.constraints:
            if constraint.name == "minItems" and isinstance(constraint.value, int):
                count = max(1, constraint.value)
        child = field.children[0] if field.children else FieldContract("item")
        value = [generate_field(child, reference).value for _ in range(count)]
        strategy = "constraint-sized-array"
    else:
        value, strategy = f"QAFox synthetic {uuid.uuid4().hex[:8]}", "generic-editable-string"
    if isinstance(value, str) and semantic not in {SemanticType.FILE}:
        value = _string_constraints(value, field)
    if not _pattern_valid(value, field):
        marker = build_placeholder(PlaceholderKind.REQUIRED, reference)
        return GenerationResult(marker, semantic, "editable-pattern-value", "pattern could not be safely synthesized", min(confidence, 60), "review-recommended")
    return GenerationResult(value, semantic, strategy, evidence_reason, confidence)


def valid_boundary_values(field: FieldContract) -> tuple[Any, ...]:
    values: list[Any] = []
    semantic, _, _ = classify_field(field)
    if semantic in {SemanticType.INTEGER, SemanticType.DECIMAL, SemanticType.CURRENCY}:
        if field.minimum is not None:
            values.append(field.minimum)
        if field.maximum is not None and field.maximum != field.minimum:
            values.append(field.maximum)
    if semantic in {SemanticType.UNKNOWN, SemanticType.EMAIL, SemanticType.HUMAN_NAME, SemanticType.ENTITY_NAME}:
        if field.min_length is not None:
            values.append("x" * field.min_length)
        if field.max_length is not None and field.max_length != field.min_length:
            values.append("x" * field.max_length)
    return tuple(values)
