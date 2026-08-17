"""Framework-neutral semantic and constraint-driven synthetic data.

Generation consumes Universal FieldContract values only. Uploaded source is
never executed. Secrets are vault references; foreign keys are runtime
bindings. Candidate values are deterministic for a given contract + seed.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import uuid
from dataclasses import dataclass, replace
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any

from app.smart_data.contracts import ConstraintContract, FieldContract, SemanticType
from app.smart_data.placeholders import PlaceholderKind, build_placeholder

_SAFE_DOMAIN = "example.test"
_SAFE_ORIGIN = "https://example.test"
_DOC_IPV4 = "192.0.2.1"
_DOC_IPV6 = "2001:db8::1"
_MAX_REPEAT = 32
_UNSUPPORTED_PATTERN = re.compile(r"\(\?<?[=!]|\\[1-9]|\\k|\(\?P=|\(\?R|\(\?P<")


class CandidateClass(str, Enum):
    VALID = "VALID"
    BOUNDARY_MIN = "BOUNDARY_MIN"
    BOUNDARY_MAX = "BOUNDARY_MAX"
    INVALID_TYPE = "INVALID_TYPE"
    MISSING_REQUIRED = "MISSING_REQUIRED"
    NULL = "NULL"
    BELOW_MIN = "BELOW_MIN"
    ABOVE_MAX = "ABOVE_MAX"
    TOO_SHORT = "TOO_SHORT"
    TOO_LONG = "TOO_LONG"
    INVALID_PATTERN = "INVALID_PATTERN"
    INVALID_ENUM = "INVALID_ENUM"
    EMPTY = "EMPTY"
    SPECIAL_CHARACTERS = "SPECIAL_CHARACTERS"


@dataclass(frozen=True, slots=True)
class GenerationResult:
    value: Any
    semantic_type: SemanticType
    strategy: str
    reason: str
    confidence_score: int
    status: str = "ready"
    editable: bool = True
    candidate_class: str = CandidateClass.VALID.value
    seed: int | None = None
    source_constraint: str = ""
    semantic_inference: str = ""
    masked: bool = False
    secret_reference: str = ""
    runtime_dependency: str = ""


def classify_field(field: FieldContract) -> tuple[SemanticType, int, str]:
    if field.semantic_type is not SemanticType.UNKNOWN:
        return field.semantic_type, max(field.confidence_score, 85), "adapter schema evidence"
    kind = field.data_type.lower()
    schema_format = field.format.lower()
    name = _name_key(field.name)
    if schema_format == "email" or "email" in kind:
        return SemanticType.EMAIL, 98, "schema format"
    if schema_format == "uuid" or "uuid" in kind:
        return SemanticType.UUID, 98, "schema format"
    if schema_format in {"date-time", "datetime"} or "datetime" in kind or "timestamp" in kind:
        return SemanticType.DATETIME, 98, "schema format"
    if schema_format == "time" or kind == "time":
        return SemanticType.DATE, 96, "schema format"
    if schema_format == "date" or kind == "date":
        return SemanticType.DATE, 98, "schema format"
    if schema_format in {"uri", "url"}:
        return SemanticType.URL, 98, "schema format"
    if schema_format in {"ipv4", "ipv6", "ip"} or "ipaddress" in kind.replace("-", ""):
        return SemanticType.URL, 90, "schema format"
    if schema_format == "hostname":
        return SemanticType.URL, 90, "schema format"
    if field.enum_values:
        return SemanticType.ENUM, 98, "documented enum"
    if any(token in kind for token in ("bool", "boolean")):
        return SemanticType.BOOLEAN, 92, "declared data type"
    if any(token in kind for token in ("int", "integer")):
        return SemanticType.INTEGER, 92, "declared data type"
    if any(token in kind for token in ("float", "decimal", "number")):
        return SemanticType.DECIMAL, 92, "declared data type"
    if any(token in kind for token in ("list", "array", "tuple", "set")) or field.items is not None:
        return SemanticType.ARRAY, 92, "declared data type"
    if any(token in kind for token in ("dict", "object", "mapping")) or field.children:
        return SemanticType.OBJECT, 92, "declared data type"
    inferred = _infer_from_name(name)
    if inferred is not None:
        return inferred
    return SemanticType.UNKNOWN, 55, "generic fallback"


def _name_key(name: str) -> str:
    return str(name or "").strip().lower().replace("-", "_")


def _infer_from_name(name: str) -> tuple[SemanticType, int, str] | None:
    if name.endswith("_id") or (name.endswith("id") and name != "id"):
        return SemanticType.FOREIGN_KEY, 70, "name-based fallback"
    if name == "id":
        return SemanticType.IDENTIFIER, 72, "name-based fallback"
    if any(token in name for token in ("password", "secret", "token", "credential", "api_key")):
        return SemanticType.SECRET, 70, "name-based fallback"
    if "email" in name:
        return SemanticType.EMAIL, 68, "name-based fallback"
    if any(token in name for token in ("phone", "mobile", "telephone")):
        return SemanticType.PHONE, 65, "name-based fallback"
    if name in {"first_name", "last_name", "full_name", "display_name"}:
        return SemanticType.HUMAN_NAME, 65, "name-based fallback"
    if name in {"username", "user_name"}:
        return SemanticType.ENTITY_NAME, 64, "name-based fallback"
    if name in {"url", "uri", "website", "homepage"}:
        return SemanticType.URL, 65, "name-based fallback"
    if name in {"city", "state", "country", "address"}:
        return SemanticType.ENTITY_NAME, 64, "name-based fallback"
    if name in {"postal_code", "zip_code", "zip", "postcode"}:
        return SemanticType.ENTITY_NAME, 64, "name-based fallback"
    if name in {"currency"}:
        return SemanticType.CURRENCY, 66, "name-based fallback"
    if name in {"amount", "price"}:
        return SemanticType.CURRENCY, 66, "name-based fallback"
    if name in {"quantity"}:
        return SemanticType.INTEGER, 66, "name-based fallback"
    if name in {"latitude", "longitude"}:
        return SemanticType.DECIMAL, 66, "name-based fallback"
    if name in {"date"}:
        return SemanticType.DATE, 64, "name-based fallback"
    if name in {"timestamp"}:
        return SemanticType.DATETIME, 64, "name-based fallback"
    return None


def _constraints(field: FieldContract) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    aliases = {
        "minlength": "minLength",
        "maxlength": "maxLength",
        "minitems": "minItems",
        "maxitems": "maxItems",
        "uniqueitems": "uniqueItems",
        "multipleof": "multipleOf",
        "exclusiveminimum": "exclusiveMinimum",
        "exclusivemaximum": "exclusiveMaximum",
        "minexclusive": "exclusiveMinimum",
        "maxexclusive": "exclusiveMaximum",
    }
    for item in field.constraints:
        key = aliases.get(item.name.lower().replace("_", ""), item.name)
        mapping[key] = item.value
    if field.minimum is not None:
        mapping.setdefault("minimum", field.minimum)
    if field.maximum is not None:
        mapping.setdefault("maximum", field.maximum)
    if field.min_length is not None:
        mapping.setdefault("minLength", field.min_length)
    if field.max_length is not None:
        mapping.setdefault("maxLength", field.max_length)
    if field.pattern:
        mapping.setdefault("pattern", field.pattern)
    if field.enum_values:
        mapping.setdefault("enum", list(field.enum_values))
    if field.exclusive_minimum is not None:
        mapping.setdefault("exclusiveMinimum", field.exclusive_minimum)
    if field.exclusive_maximum is not None:
        mapping.setdefault("exclusiveMaximum", field.exclusive_maximum)
    if field.multiple_of is not None:
        mapping.setdefault("multipleOf", field.multiple_of)
    if field.min_items is not None:
        mapping.setdefault("minItems", field.min_items)
    if field.max_items is not None:
        mapping.setdefault("maxItems", field.max_items)
    if field.unique_items:
        mapping.setdefault("uniqueItems", True)
    if field.default_value is not None:
        mapping.setdefault("default", field.default_value)
    return mapping


def _bool_exclusive(raw: Any) -> bool:
    return raw is True


def _numeric_exclusive(raw: Any) -> int | float | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float, Decimal)):
        return float(raw)
    return None


def _bound(field: FieldContract, *, low: bool) -> tuple[int | float | None, bool]:
    constraints = _constraints(field)
    if low:
        exclusive_raw = constraints.get("exclusiveMinimum")
        inclusive = constraints.get("minimum")
        exclusive_num = _numeric_exclusive(exclusive_raw)
        if exclusive_num is not None:
            return exclusive_num, True
        return (None if inclusive is None else float(inclusive)), _bool_exclusive(exclusive_raw)
    exclusive_raw = constraints.get("exclusiveMaximum")
    inclusive = constraints.get("maximum")
    exclusive_num = _numeric_exclusive(exclusive_raw)
    if exclusive_num is not None:
        return exclusive_num, True
    return (None if inclusive is None else float(inclusive)), _bool_exclusive(exclusive_raw)


def _multiple_of(field: FieldContract) -> int | float | None:
    value = _constraints(field).get("multipleOf")
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    if float(value) == 0:
        return None
    return float(value)


def _rng(seed: int, *parts: Any) -> random.Random:
    material = f"{int(seed)}|" + "|".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _seeded_uuid(seed: int, *parts: Any) -> str:
    digest = hashlib.sha256(f"{int(seed)}|{ '|'.join(str(part) for part in parts)}".encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


def _fit_string(value: str, field: FieldContract) -> str:
    constraints = _constraints(field)
    max_length = constraints.get("maxLength")
    min_length = constraints.get("minLength")
    if isinstance(max_length, int):
        value = value[: max(0, max_length)]
    if isinstance(min_length, int) and len(value) < min_length:
        pad = "x" * (min_length - len(value))
        if isinstance(max_length, int):
            pad = pad[: max(0, max_length - len(value))]
        value += pad
    return value


def _pattern_valid(value: Any, field: FieldContract) -> bool:
    pattern = str(_constraints(field).get("pattern") or "")
    if not pattern or not isinstance(value, str):
        return True
    try:
        return re.fullmatch(pattern, value) is not None
    except re.error:
        return False


def _synthesize_pattern(pattern: str, rng: random.Random) -> str | None:
    if not pattern or _UNSUPPORTED_PATTERN.search(pattern):
        return None
    try:
        re.compile(pattern)
    except re.error:
        return None
    source = pattern.strip()
    if source.startswith("^"):
        source = source[1:]
    if source.endswith("$") and not source.endswith(r"\$"):
        source = source[:-1]
    try:
        value, rest = _emit_pattern(source, rng, 0)
    except (ValueError, RecursionError):
        return None
    if rest.strip():
        return None
    return value


def _emit_pattern(source: str, rng: random.Random, depth: int) -> tuple[str, str]:
    if depth > 12:
        raise ValueError("pattern too deep")
    output: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char == ")":
            return "".join(output), source[index:]
        if char == "|":
            return "".join(output), source[index:]
        atom, index = _atom(source, index, rng, depth)
        repeats = 1
        optional = False
        if index < len(source) and source[index] in "*+?{":
            marker = source[index]
            index += 1
            if marker == "*":
                repeats = 0
            elif marker == "+":
                repeats = 1
            elif marker == "?":
                optional = True
            elif marker == "{":
                end = source.find("}", index)
                if end < 0:
                    raise ValueError("unterminated quantifier")
                spec = source[index:end]
                index = end + 1
                if "," in spec:
                    low, high = spec.split(",", 1)
                    start = int(low or "0")
                    stop = int(high) if high else start + 2
                    repeats = min(_MAX_REPEAT, max(start, start))
                    if stop > start:
                        repeats = min(stop, max(start, 1 if start == 0 else start))
                else:
                    repeats = min(_MAX_REPEAT, int(spec or "1"))
        if optional:
            repeats = 1
        output.append(atom * repeats)
    return "".join(output), ""


def _atom(source: str, index: int, rng: random.Random, depth: int) -> tuple[str, int]:
    char = source[index]
    if char == "\\" and index + 1 < len(source):
        nxt = source[index + 1]
        mapping = {"d": "0", "w": "a", "s": " ", "t": "\t", "n": "n", "D": "A", "W": "!", "S": "x"}
        if nxt in mapping:
            return mapping[nxt], index + 2
        return nxt, index + 2
    if char == ".":
        return "a", index + 1
    if char == "[":
        end = source.find("]", index + 1)
        if end < 0:
            raise ValueError("unterminated class")
        body = source[index + 1 : end]
        negate = body.startswith("^")
        if negate:
            return "a", end + 1
        token = _class_char(body)
        return token, end + 1
    if char == "(":
        inner_start = index + 1
        if source.startswith("?:", inner_start):
            inner_start += 2
        inner, rest = _emit_pattern(source[inner_start:], rng, depth + 1)
        if not rest.startswith(")"):
            raise ValueError("unterminated group")
        consumed = len(source) - len(rest) + 1
        return inner, consumed
    if char in "^$":
        return "", index + 1
    return char, index + 1


def _class_char(body: str) -> str:
    if re.search(r"A-Z", body):
        return "A"
    if re.search(r"a-z", body):
        return "a"
    if re.search(r"0-9", body):
        return "0"
    cleaned = body.replace("\\d", "0").replace("\\w", "a")
    for item in cleaned:
        if item not in r"\^-[]":
            return item
    return "A"


def _snap_multiple(value: float, multiple: float | None, *, decimal: bool) -> int | float:
    if multiple is None:
        return float(value) if decimal else int(round(value))
    steps = math.ceil(value / multiple - 1e-12) if multiple > 0 else 0
    snapped = steps * multiple
    if snapped < value:
        snapped += multiple
    if decimal:
        quantized = Decimal(str(snapped)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return float(quantized)
    return int(round(snapped))


def _valid_number(field: FieldContract, *, decimal: bool) -> int | float:
    low, low_ex = _bound(field, low=True)
    high, high_ex = _bound(field, low=False)
    multiple = _multiple_of(field)
    step = 1 if not decimal else 0.01
    if low is None:
        value = 1.0
    else:
        value = low + (step if low_ex else 0)
    if high is not None:
        ceiling = high - (step if high_ex else 0)
        value = min(value, ceiling)
    value = _snap_multiple(value, multiple, decimal=decimal)
    if high is not None:
        ceiling = high - (1e-9 if high_ex else 0)
        if value > ceiling and low is not None:
            value = _snap_multiple(low if not low_ex else low + (multiple or step), multiple, decimal=decimal)
    return float(value) if decimal else int(value)


def _item_field(field: FieldContract) -> FieldContract:
    if field.items is not None:
        return field.items
    if field.children:
        return field.children[0]
    return FieldContract("item")


def _composed(field: FieldContract) -> FieldContract:
    if field.all_of:
        merged = field
        for part in field.all_of:
            merged = _merge_fields(merged, part)
        return merged
    if field.one_of:
        return _merge_fields(field, field.one_of[0], prefer_other=True)
    if field.any_of:
        return _merge_fields(field, field.any_of[0], prefer_other=True)
    return field


def _merge_fields(left: FieldContract, right: FieldContract, *, prefer_other: bool = False) -> FieldContract:
    children = {item.name: item for item in left.children}
    for item in right.children:
        children[item.name] = item
    enum_values = right.enum_values or left.enum_values
    pattern = right.pattern or left.pattern
    data_type = right.data_type if prefer_other and right.data_type != "unknown" else (left.data_type if left.data_type != "unknown" else right.data_type)
    semantic = right.semantic_type if prefer_other and right.semantic_type is not SemanticType.UNKNOWN else (
        left.semantic_type if left.semantic_type is not SemanticType.UNKNOWN else right.semantic_type
    )
    return replace(
        left if not prefer_other else right,
        name=left.name or right.name,
        semantic_type=semantic,
        data_type=data_type,
        required=left.required or right.required,
        minimum=_max_opt(left.minimum, right.minimum),
        maximum=_min_opt(left.maximum, right.maximum),
        min_length=_max_opt(left.min_length, right.min_length),
        max_length=_min_opt(left.max_length, right.max_length),
        pattern=pattern,
        format=left.format or right.format,
        enum_values=enum_values,
        nullable=left.nullable and right.nullable if prefer_other else left.nullable or right.nullable,
        secret=left.secret or right.secret,
        dependency=left.dependency or right.dependency,
        constraints=left.constraints + right.constraints,
        children=tuple(children.values()),
        exclusive_minimum=right.exclusive_minimum if right.exclusive_minimum is not None else left.exclusive_minimum,
        exclusive_maximum=right.exclusive_maximum if right.exclusive_maximum is not None else left.exclusive_maximum,
        multiple_of=right.multiple_of if right.multiple_of is not None else left.multiple_of,
        min_items=_max_opt(left.min_items, right.min_items),
        max_items=_min_opt(left.max_items, right.max_items),
        unique_items=left.unique_items or right.unique_items,
        items=right.items or left.items,
        one_of=(),
        any_of=(),
        all_of=(),
    )


def _max_opt(left: Any, right: Any) -> Any:
    values = [item for item in (left, right) if item is not None]
    return max(values) if values else None


def _min_opt(left: Any, right: Any) -> Any:
    values = [item for item in (left, right) if item is not None]
    return min(values) if values else None


def _location_value(name: str) -> str:
    key = _name_key(name)
    if key == "city":
        return "Example City"
    if key == "state":
        return "Example State"
    if key == "country":
        return "Exampleland"
    if key in {"postal_code", "zip_code", "zip", "postcode"}:
        return "00000"
    if key == "address":
        return "1 Example Way"
    if key in {"username", "user_name"}:
        return "qafox-user"
    if key == "currency":
        return "USD"
    return f"QAFox synthetic {key or 'value'}"


def _valid_value(field: FieldContract, resource: str, seed: int) -> tuple[Any, str]:
    semantic, _, _ = classify_field(field)
    constraints = _constraints(field)
    rng = _rng(seed, field.name, field.path, resource, "VALID")
    reference = f"{resource}.{field.name}".strip(".")
    if "const" in constraints:
        return constraints["const"], "documented-const"
    if field.enum_values:
        chosen = field.default_value if field.default_value in field.enum_values else field.enum_values[0]
        return chosen, "documented-enum"
    if field.default_value is not None and not field.secret:
        return field.default_value, "documented-default"
    pattern = str(constraints.get("pattern") or "")
    if pattern:
        synthesized = _synthesize_pattern(pattern, rng)
        if synthesized is not None:
            return _fit_string(synthesized, field), "pattern-synthesis"
    if semantic is SemanticType.EMAIL:
        return f"qafox-{_seeded_uuid(seed, reference).replace('-', '')[:12]}@{_SAFE_DOMAIN}", "synthetic-email"
    if semantic is SemanticType.PHONE:
        return "+12025550100", "reserved-phone"
    if semantic is SemanticType.HUMAN_NAME:
        key = _name_key(field.name)
        mapping = {"first_name": "Ada", "last_name": "Lovelace", "full_name": "QAFox Synthetic User", "display_name": "QAFox Synthetic User"}
        return mapping.get(key, "QAFox Synthetic User"), "synthetic-human-name"
    if semantic is SemanticType.ENTITY_NAME:
        return _fit_string(_location_value(field.name), field), "synthetic-entity-name"
    if semantic is SemanticType.UUID:
        return _seeded_uuid(seed, reference), "uuid4"
    if semantic is SemanticType.IDENTIFIER:
        if "uuid" in field.data_type.lower() or field.format.lower() == "uuid":
            return _seeded_uuid(seed, reference), "seeded-identifier"
        return _valid_number(field, decimal=False) if "int" in field.data_type.lower() else f"id-{_seeded_uuid(seed, reference)[:8]}", "synthetic-identifier"
    if semantic is SemanticType.INTEGER:
        return _valid_number(field, decimal=False), "constraint-valid-integer"
    if semantic in {SemanticType.DECIMAL, SemanticType.CURRENCY}:
        if _name_key(field.name) == "currency" and field.data_type.lower() in {"string", "unknown"}:
            return "USD", "iso-currency-code"
        return _valid_number(field, decimal=True), "constraint-valid-decimal"
    if semantic is SemanticType.BOOLEAN:
        return False, "safe-boolean"
    if semantic is SemanticType.DATE:
        if field.format.lower() == "time" or field.data_type.lower() == "time":
            return "12:00:00", "synthetic-time"
        return "2030-01-15", "synthetic-date"
    if semantic is SemanticType.DATETIME:
        return "2030-01-15T12:00:00+00:00", "timezone-aware-datetime"
    if semantic is SemanticType.URL:
        fmt = field.format.lower()
        if fmt in {"ipv4", "ip"}:
            return _DOC_IPV4, "documentation-ipv4"
        if fmt == "ipv6":
            return _DOC_IPV6, "documentation-ipv6"
        if fmt == "hostname":
            return _SAFE_DOMAIN, "safe-hostname"
        if fmt in {"uri", "url"} or "url" in _name_key(field.name) or "uri" in _name_key(field.name):
            return f"{_SAFE_ORIGIN}/qafox-fixture", "safe-example-url"
        if fmt in {"ipv4", "ipv6"}:
            return _DOC_IPV4, "documentation-ipv4"
        return f"{_SAFE_ORIGIN}/qafox-fixture", "safe-example-url"
    if semantic is SemanticType.FILE:
        return build_placeholder(PlaceholderKind.SYNTHETIC, "file"), "safe-generated-file"
    if semantic is SemanticType.OBJECT or field.children:
        value = {child.name: generate_field(child, reference, seed=seed).value for child in field.children}
        return value, "recursive-object"
    if semantic is SemanticType.ARRAY or field.items is not None or "array" in field.data_type.lower() or "list" in field.data_type.lower():
        minimum = constraints.get("minItems")
        count = int(minimum) if isinstance(minimum, int) and minimum > 0 else 1
        maximum = constraints.get("maxItems")
        if isinstance(maximum, int):
            count = min(count, max(0, maximum))
        child = _item_field(field)
        items = [generate_field(child, reference, seed=seed + index).value for index in range(count)]
        if constraints.get("uniqueItems") and len(set(map(str, items))) < len(items):
            items = list(dict.fromkeys(items))
            while len(items) < count:
                items.append(generate_field(child, reference, seed=seed + len(items) + 17).value)
        return items, "constraint-sized-array"
    if field.format.lower() in {"ipv4", "ip"}:
        return _DOC_IPV4, "documentation-ipv4"
    if field.format.lower() == "ipv6":
        return _DOC_IPV6, "documentation-ipv6"
    if field.format.lower() == "hostname":
        return _SAFE_DOMAIN, "safe-hostname"
    if field.format.lower() == "time":
        return "12:00:00", "synthetic-time"
    token = _seeded_uuid(seed, reference).replace("-", "")[:8]
    return _fit_string(f"QAFox synthetic {token}", field), "generic-editable-string"


def _result(
    field: FieldContract,
    value: Any,
    strategy: str,
    reason: str,
    confidence: int,
    *,
    candidate: CandidateClass,
    seed: int,
    status: str = "ready",
    editable: bool = True,
    source_constraint: str = "",
    masked: bool = False,
    secret_reference: str = "",
    runtime_dependency: str = "",
) -> GenerationResult:
    semantic, _, inference = classify_field(field)
    return GenerationResult(
        value,
        semantic,
        strategy,
        reason,
        confidence,
        status,
        editable,
        candidate.value,
        seed,
        source_constraint,
        inference,
        masked,
        secret_reference,
        runtime_dependency,
    )


def generate_field(field: FieldContract, resource: str = "request", *, seed: int = 0) -> GenerationResult:
    """VALID candidate used by existing smart-data and test-case generation."""
    field = _composed(field)
    semantic, confidence, evidence_reason = classify_field(field)
    reference = f"{resource}.{field.name}".strip(".")
    if field.secret or semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN}:
        secret = build_placeholder(PlaceholderKind.SECRET_REF, f"configuration.{field.name}")
        return _result(
            field,
            secret,
            "encrypted-vault-reference",
            "secret values must remain in the configuration vault",
            confidence,
            candidate=CandidateClass.VALID,
            seed=seed,
            status="secret-reference-required",
            masked=True,
            secret_reference=secret,
        )
    if field.dependency is not None or semantic is SemanticType.FOREIGN_KEY:
        dependency_resource = field.dependency.resource if field.dependency else resource
        dependency_field = field.dependency.field if field.dependency else field.name
        marker = build_placeholder(PlaceholderKind.REQUIRED, f"{dependency_resource}.{dependency_field}")
        return _result(
            field,
            marker,
            "editable-prerequisite",
            "related resource must be supplied or created",
            confidence,
            candidate=CandidateClass.VALID,
            seed=seed,
            status="prerequisite-required",
            runtime_dependency=f"{dependency_resource}.{dependency_field}",
        )
    value, strategy = _valid_value(field, resource, seed)
    if isinstance(value, str) and semantic not in {SemanticType.FILE}:
        if not str(_constraints(field).get("pattern") or ""):
            value = _fit_string(value, field)
    if not _pattern_valid(value, field):
        marker = build_placeholder(PlaceholderKind.REQUIRED, reference)
        return _result(
            field,
            marker,
            "editable-pattern-value",
            "pattern could not be safely synthesized",
            min(confidence, 60),
            candidate=CandidateClass.VALID,
            seed=seed,
            status="review-recommended",
            source_constraint="pattern",
        )
    return _result(field, value, strategy, evidence_reason, confidence, candidate=CandidateClass.VALID, seed=seed, source_constraint=_primary_constraint(field))


def _primary_constraint(field: FieldContract) -> str:
    constraints = _constraints(field)
    for key in ("pattern", "enum", "minimum", "maximum", "minLength", "maxLength", "multipleOf"):
        if key in constraints:
            return key
    return ""


def generate_candidates(field: FieldContract, resource: str = "request", *, seed: int = 0) -> tuple[GenerationResult, ...]:
    field = _composed(field)
    semantic, confidence, _ = classify_field(field)
    results = [generate_field(field, resource, seed=seed)]
    if field.secret or semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN}:
        if field.required:
            results.append(
                _result(
                    field,
                    None,
                    "omit-required-secret",
                    "required secret is unresolved until configuration is bound",
                    confidence,
                    candidate=CandidateClass.MISSING_REQUIRED,
                    seed=seed,
                    status="secret-reference-required",
                    masked=True,
                    secret_reference=results[0].secret_reference,
                )
            )
        return tuple(results)
    if semantic is SemanticType.FOREIGN_KEY or field.dependency is not None:
        return tuple(results)
    constraints = _constraints(field)
    reference = f"{resource}.{field.name}".strip(".")
    if field.required:
        results.append(
            _result(
                field,
                None,
                "omit-required",
                "required field omitted",
                confidence,
                candidate=CandidateClass.MISSING_REQUIRED,
                seed=seed,
                status="negative",
            )
        )
    results.append(
        _result(
            field,
            None,
            "null-candidate",
            "null candidate",
            confidence,
            candidate=CandidateClass.NULL,
            seed=seed,
            status="negative" if not field.nullable else "ready",
        )
    )
    if field.enum_values:
        results.append(
            _result(field, 0, "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative")
        )
        results.append(
            _result(
                field,
                "not-in-enum",
                "invalid-enum",
                "value is not an allowed enum member",
                90,
                candidate=CandidateClass.INVALID_ENUM,
                seed=seed,
                status="negative",
                source_constraint="enum",
            )
        )
        return tuple(results)
    if semantic in {SemanticType.INTEGER, SemanticType.DECIMAL, SemanticType.CURRENCY} and _name_key(field.name) != "currency":
        results.append(
            _result(field, "not-a-number", "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative")
        )
        low, low_ex = _bound(field, low=True)
        high, high_ex = _bound(field, low=False)
        decimal = semantic is not SemanticType.INTEGER
        if low is not None:
            boundary = low + (0.01 if decimal and low_ex else (1 if low_ex and not decimal else 0))
            results.append(
                _result(
                    field,
                    _snap_multiple(boundary, _multiple_of(field), decimal=decimal),
                    "boundary-min",
                    "minimum boundary",
                    confidence,
                    candidate=CandidateClass.BOUNDARY_MIN,
                    seed=seed,
                    source_constraint="minimum",
                )
            )
            below = low - (1 if not decimal else 0.01)
            results.append(
                _result(field, int(below) if not decimal else below, "below-min", "below minimum", 90, candidate=CandidateClass.BELOW_MIN, seed=seed, status="negative", source_constraint="minimum")
            )
        if high is not None:
            boundary = high - (0.01 if decimal and high_ex else (1 if high_ex and not decimal else 0))
            results.append(
                _result(
                    field,
                    _snap_multiple(boundary, _multiple_of(field), decimal=decimal) if not high_ex else (int(boundary) if not decimal else boundary),
                    "boundary-max",
                    "maximum boundary",
                    confidence,
                    candidate=CandidateClass.BOUNDARY_MAX,
                    seed=seed,
                    source_constraint="maximum",
                )
            )
            above = high + (1 if not decimal else 0.01)
            results.append(
                _result(field, int(above) if not decimal else above, "above-max", "above maximum", 90, candidate=CandidateClass.ABOVE_MAX, seed=seed, status="negative", source_constraint="maximum")
            )
    elif semantic is SemanticType.BOOLEAN:
        results.append(_result(field, "not-a-boolean", "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative"))
    elif semantic is SemanticType.ARRAY or field.items is not None:
        results.append(_result(field, "not-an-array", "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative"))
        results.append(_result(field, [], "empty-array", "empty array", confidence, candidate=CandidateClass.EMPTY, seed=seed, status="negative" if int(constraints.get("minItems") or 0) > 0 else "ready", source_constraint="minItems"))
        minimum = constraints.get("minItems")
        maximum = constraints.get("maxItems")
        child = _item_field(field)
        if isinstance(minimum, int) and minimum > 0:
            items = [generate_field(child, reference, seed=seed + index).value for index in range(minimum)]
            results.append(_result(field, items, "boundary-min-items", "minItems boundary", confidence, candidate=CandidateClass.BOUNDARY_MIN, seed=seed, source_constraint="minItems"))
            results.append(_result(field, items[: minimum - 1], "below-min-items", "fewer than minItems", 90, candidate=CandidateClass.BELOW_MIN, seed=seed, status="negative", source_constraint="minItems"))
        if isinstance(maximum, int):
            items = [generate_field(child, reference, seed=seed + index).value for index in range(max(0, maximum))]
            results.append(_result(field, items, "boundary-max-items", "maxItems boundary", confidence, candidate=CandidateClass.BOUNDARY_MAX, seed=seed, source_constraint="maxItems"))
            extra = items + [generate_field(child, reference, seed=seed + 99).value]
            results.append(_result(field, extra, "above-max-items", "more than maxItems", 90, candidate=CandidateClass.ABOVE_MAX, seed=seed, status="negative", source_constraint="maxItems"))
    elif semantic is SemanticType.OBJECT:
        results.append(_result(field, [], "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative"))
        results.append(_result(field, {}, "empty-object", "empty object", confidence, candidate=CandidateClass.EMPTY, seed=seed, status="negative" if field.required else "ready"))
    else:
        results.append(_result(field, 0, "invalid-type", "type mismatch", 90, candidate=CandidateClass.INVALID_TYPE, seed=seed, status="negative"))
        min_length = constraints.get("minLength")
        max_length = constraints.get("maxLength")
        if isinstance(min_length, int):
            results.append(_result(field, "x" * min_length, "boundary-min-length", "minLength boundary", confidence, candidate=CandidateClass.BOUNDARY_MIN, seed=seed, source_constraint="minLength"))
            results.append(_result(field, "x" * max(0, min_length - 1), "too-short", "below minLength", 90, candidate=CandidateClass.TOO_SHORT, seed=seed, status="negative", source_constraint="minLength"))
        if isinstance(max_length, int):
            results.append(_result(field, "x" * max_length, "boundary-max-length", "maxLength boundary", confidence, candidate=CandidateClass.BOUNDARY_MAX, seed=seed, source_constraint="maxLength"))
            results.append(_result(field, "x" * (max_length + 1), "too-long", "above maxLength", 90, candidate=CandidateClass.TOO_LONG, seed=seed, status="negative", source_constraint="maxLength"))
        results.append(_result(field, "", "empty-string", "empty string", 80, candidate=CandidateClass.EMPTY, seed=seed, status="negative" if int(min_length or 0) > 0 or field.required else "ready"))
        special = _fit_string("A.-_~", field)
        results.append(_result(field, special, "special-characters", "safe punctuation", 80, candidate=CandidateClass.SPECIAL_CHARACTERS, seed=seed, source_constraint="minLength" if min_length else ""))
        pattern = str(constraints.get("pattern") or "")
        if pattern:
            results.append(_result(field, "!!!", "invalid-pattern", "does not match pattern", 90, candidate=CandidateClass.INVALID_PATTERN, seed=seed, status="negative", source_constraint="pattern"))
        if field.enum_values:
            results.append(_result(field, "not-in-enum", "invalid-enum", "value is not an allowed enum member", 90, candidate=CandidateClass.INVALID_ENUM, seed=seed, status="negative", source_constraint="enum"))
    return tuple(results)


def valid_boundary_values(field: FieldContract) -> tuple[Any, ...]:
    field = _composed(field)
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
