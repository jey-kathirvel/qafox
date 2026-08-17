"""Static text extractors for non-Python REST adapters.

Patterns inspect source as text only. Nothing is imported or executed.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from app.smart_data.adapters.semantics import field_contract
from app.smart_data.contracts import (
    AuthenticationMode,
    FieldContract,
    SchemaContract,
    SourceEvidence,
)

_IDENT = r"[A-Za-z_][\w]*"


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        if char == sep and depth == 0:
            piece = "".join(current).strip()
            if piece:
                parts.append(piece)
            current = []
            continue
        current.append(char)
    piece = "".join(current).strip()
    if piece:
        parts.append(piece)
    return parts


def _balanced_inner(text: str, open_paren_index: int) -> str:
    if open_paren_index < 0 or open_paren_index >= len(text) or text[open_paren_index] != "(":
        return ""
    depth = 0
    for index in range(open_paren_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_index + 1 : index]
    return ""


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, max(0, index)) + 1


def evidence(relative: str, text: str, index: int, kind: str, score: int = 88) -> tuple[SourceEvidence, ...]:
    excerpt = text[index : index + 160].replace("\n", " ").strip()
    return (
        SourceEvidence(
            relative,
            line_of(text, index),
            evidence_type=kind,
            excerpt=excerpt,
            confidence_score=score,
        ),
    )


def _int_kw(blob: str, *names: str) -> int | None:
    for name in names:
        match = re.search(rf"{name}\s*=\s*(-?\d+)", blob, re.I)
        if match:
            return int(match.group(1))
    return None


def _schema(name: str, fields: Iterable[FieldContract], content_type: str = "", score: int = 86) -> SchemaContract | None:
    items = tuple(fields)
    if not items:
        return None
    return SchemaContract(name, "object", items, content_type, confidence_score=score)


# --- Express / Node request access and validators ---

REQ_ACCESS_RE = re.compile(
    r"""req\.(params|query|body|headers)(?:\.([A-Za-z_][\w]*)|\[['"]([^'"]+)['"]\])""",
    re.I,
)
ZOD_FIELD_RE = re.compile(
    r"""['"]?([A-Za-z_][\w]*)['"]?\s*:\s*z\.([A-Za-z]+)\(([^)]*)\)([^,}]*)""",
    re.I,
)
JOI_FIELD_RE = re.compile(
    r"""['"]?([A-Za-z_][\w]*)['"]?\s*:\s*Joi\.([A-Za-z]+)\(([^)]*)\)([^,}]*)""",
    re.I,
)
YUP_FIELD_RE = re.compile(
    r"""['"]?([A-Za-z_][\w]*)['"]?\s*:\s*(?:yup\.)?([A-Za-z]+)\(([^)]*)\)([^,}]*)""",
    re.I,
)
EXPRESS_VALIDATOR_RE = re.compile(
    r"""\b(?:body|query|param|header)\(\s*['"]([^'"]+)['"]\s*\)([^;]*)""",
    re.I,
)
MONGOOSE_FIELD_RE = re.compile(
    r"""['"]?([A-Za-z_][\w]*)['"]?\s*:\s*\{([^}]+)\}""",
)
PRISMA_FIELD_RE = re.compile(
    r"""^\s*([A-Za-z_][\w]*)\s+([A-Za-z_][\w?]*)""",
    re.M,
)
SEQUELIZE_FIELD_RE = re.compile(
    r"""([A-Za-z_][\w]*)\s*:\s*\{\s*type:\s*(?:DataTypes|Sequelize)\.([A-Za-z]+)""",
    re.I,
)


def express_request_fields(text: str, relative: str) -> dict[str, list[FieldContract]]:
    buckets: dict[str, dict[str, FieldContract]] = {
        "path-parameters": {},
        "query-parameters": {},
        "header-parameters": {},
        "request-body": {},
    }
    location_map = {
        "params": "path-parameters",
        "query": "query-parameters",
        "headers": "header-parameters",
        "body": "request-body",
    }
    for match in REQ_ACCESS_RE.finditer(text):
        location, dotted, quoted = match.groups()
        name = dotted or quoted
        if not name:
            continue
        bag = location_map[location.lower()]
        buckets[bag][name] = field_contract(
            name,
            required=location.lower() == "params",
            evidence=evidence(relative, text, match.start(), "express-request-field"),
            source_file=relative,
            source_line=line_of(text, match.start()),
        )
    return {key: list(value.values()) for key, value in buckets.items() if value}


def _chain_constraints(name: str, type_name: str, chain: str, relative: str, index: int, text: str) -> FieldContract:
    lowered = chain.lower()
    required = ".optional" not in lowered
    email = "email" in lowered or type_name.lower() == "email"
    uuid = "uuid" in lowered
    min_length = _int_kw(chain, "min") if type_name.lower() in {"string"} else None
    max_length = _int_kw(chain, "max") if type_name.lower() in {"string"} else None
    minimum = _int_kw(chain, "min", "gte", "gt") if type_name.lower() in {"number", "int", "integer"} else None
    maximum = _int_kw(chain, "max", "lte", "lt") if type_name.lower() in {"number", "int", "integer"} else None
    if ".min(" in lowered and type_name.lower() == "string":
        found = re.search(r"\.min\(\s*(\d+)", chain)
        min_length = int(found.group(1)) if found else min_length
    if ".max(" in lowered and type_name.lower() == "string":
        found = re.search(r"\.max\(\s*(\d+)", chain)
        max_length = int(found.group(1)) if found else max_length
    if ".min(" in lowered and type_name.lower() in {"number", "int", "integer"}:
        found = re.search(r"\.min\(\s*(-?\d+)", chain)
        minimum = int(found.group(1)) if found else minimum
    validators = [type_name]
    if email:
        validators.append("email")
    if uuid:
        validators.append("uuid")
    return field_contract(
        name,
        type_hint=type_name.lower(),
        format_hint="email" if email else "uuid" if uuid else "",
        validators=validators,
        required=required,
        min_length=min_length,
        max_length=max_length,
        minimum=minimum,
        maximum=maximum,
        evidence=evidence(relative, text, index, "js-validator"),
        source_file=relative,
        source_line=line_of(text, index),
        confidence_score=90,
    )


def js_validator_fields(text: str, relative: str) -> list[FieldContract]:
    fields: dict[str, FieldContract] = {}
    for pattern in (ZOD_FIELD_RE, JOI_FIELD_RE, YUP_FIELD_RE):
        for match in pattern.finditer(text):
            name, type_name, _args, chain = match.groups()
            if name in {"object", "array", "lazy"}:
                continue
            fields[name] = _chain_constraints(name, type_name, chain, relative, match.start(), text)
    for match in EXPRESS_VALIDATOR_RE.finditer(text):
        name, chain = match.groups()
        fields[name] = _chain_constraints(name, "string", chain, relative, match.start(), text)
    return list(fields.values())


def mongoose_fields(text: str, relative: str) -> list[FieldContract]:
    fields: list[FieldContract] = []
    for match in MONGOOSE_FIELD_RE.finditer(text):
        name, body = match.groups()
        if name in {"type", "ref", "default"}:
            continue
        type_match = re.search(r"type\s*:\s*([A-Za-z.]+)", body)
        ref_match = re.search(r"ref\s*:\s*['\"]([^'\"]+)['\"]", body)
        required = bool(re.search(r"required\s*:\s*true", body, re.I))
        type_hint = type_match.group(1) if type_match else "string"
        validators = ["mongoose", ref_match.group(1) if ref_match else ""]
        field = field_contract(
            name if not ref_match else f"{name}_id" if not name.endswith("Id") else name,
            type_hint=type_hint,
            validators=validators,
            required=required,
            evidence=evidence(relative, text, match.start(), "mongoose-field"),
            source_file=relative,
            source_line=line_of(text, match.start()),
        )
        fields.append(field)
    return fields


def prisma_fields(text: str, relative: str) -> list[FieldContract]:
    if "model " not in text:
        return []
    fields: list[FieldContract] = []
    for match in PRISMA_FIELD_RE.finditer(text):
        name, type_name = match.groups()
        if name in {"model", "datasource", "generator"} or type_name in {"model"}:
            continue
        if type_name[0].isupper() and type_name.lower() not in {"string", "int", "boolean", "datetime", "float", "json", "decimal"}:
            name = name if name.endswith("_id") or name.endswith("Id") else f"{name}_id"
        fields.append(
            field_contract(
                name,
                type_hint=type_name.rstrip("?"),
                validators=["prisma"],
                nullable=type_name.endswith("?"),
                evidence=evidence(relative, text, match.start(), "prisma-field"),
                source_file=relative,
                source_line=line_of(text, match.start()),
            )
        )
    return fields


def sequelize_fields(text: str, relative: str) -> list[FieldContract]:
    return [
        field_contract(
            match.group(1),
            type_hint=match.group(2).lower(),
            validators=["sequelize"],
            evidence=evidence(relative, text, match.start(), "sequelize-field"),
            source_file=relative,
            source_line=line_of(text, match.start()),
        )
        for match in SEQUELIZE_FIELD_RE.finditer(text)
    ]


def js_auth_modes(text: str) -> tuple[AuthenticationMode, ...]:
    lowered = text.lower()
    modes: list[AuthenticationMode] = []
    if any(token in lowered for token in ("passport", "jwt", "bearer", "authguard", "authenticate")):
        modes.append(AuthenticationMode.BEARER)
    if "apikey" in lowered or "api-key" in lowered or "api_key" in lowered:
        modes.append(AuthenticationMode.API_KEY)
    if "session" in lowered or "cookie" in lowered:
        modes.append(AuthenticationMode.SESSION)
    if "oauth" in lowered:
        modes.append(AuthenticationMode.OAUTH2)
    return tuple(dict.fromkeys(modes))


# --- NestJS / class-validator / Swagger ---

NEST_PARAM_RE = re.compile(
    r"""@(Body|Param|Query|Headers|Header)\(\s*(?:['"]([^'"]+)['"])?""",
    re.I,
)
NEST_CLASS_RE = re.compile(r"""export\s+class\s+(\w+)""", re.I)
DECORATED_PROP_RE = re.compile(
    r"""((?:@[A-Za-z][\w.]*(?:\([^)]*\))?\s*)+)(?:readonly\s+)?(?:public\s+|private\s+|protected\s+)?(\w+)\s*\??\s*(?::\s*([^;=\n]+))?""",
    re.M,
)


def nest_parameter_locations(snippet: str) -> list[tuple[str, str]]:
    found = []
    for match in NEST_PARAM_RE.finditer(snippet):
        kind, name = match.groups()
        found.append((kind.lower(), name or ""))
    return found


def class_validator_fields(text: str, relative: str) -> dict[str, list[FieldContract]]:
    classes: dict[str, list[FieldContract]] = {}
    for class_match in NEST_CLASS_RE.finditer(text):
        name = class_match.group(1)
        start = class_match.end()
        next_class = NEST_CLASS_RE.search(text, start)
        body = text[start : next_class.start() if next_class else len(text)]
        fields: list[FieldContract] = []
        for match in DECORATED_PROP_RE.finditer(body):
            decorators, field_name, type_hint = match.groups()
            lowered = decorators.lower()
            required = "@isoptional" not in lowered.replace(" ", "")
            min_length = _int_kw(decorators, "minLength", "MinLength")
            max_length = _int_kw(decorators, "maxLength", "MaxLength")
            if min_length is None:
                min_match = re.search(r"@MinLength\(\s*(\d+)", decorators)
                min_length = int(min_match.group(1)) if min_match else None
            if max_length is None:
                max_match = re.search(r"@MaxLength\(\s*(\d+)", decorators)
                max_length = int(max_match.group(1)) if max_match else None
            minimum = None
            maximum = None
            min_n = re.search(r"@Min\(\s*(-?\d+)", decorators)
            max_n = re.search(r"@Max\(\s*(-?\d+)", decorators)
            if min_n:
                minimum = int(min_n.group(1))
            if max_n:
                maximum = int(max_n.group(1))
            pattern = ""
            matches = re.search(r"@Matches\(\s*[/'\"]([^'\"]+)['\"]", decorators)
            if matches:
                pattern = matches.group(1)
            validators = re.findall(r"@([A-Za-z]+)", decorators)
            fields.append(
                field_contract(
                    field_name,
                    type_hint=(type_hint or "string").strip(),
                    validators=validators,
                    required=required,
                    min_length=min_length,
                    max_length=max_length,
                    minimum=minimum,
                    maximum=maximum,
                    pattern=pattern,
                    evidence=evidence(relative, body, match.start() + start, "class-validator-field"),
                    source_file=relative,
                    source_line=line_of(text, start + match.start()),
                    confidence_score=91,
                )
            )
        if fields:
            classes[name] = fields
    return classes


# --- Spring ---

SPRING_METHOD_SIG_RE = re.compile(
    r"""@(Get|Post|Put|Patch|Delete)Mapping\([^;]*?\)\s*(?:public\s+)?([\w<>,\s]+)\s+(\w+)\s*\((.*?)\)""",
    re.S | re.I,
)
SPRING_PARAM_RE = re.compile(
    r"""@(PathVariable|RequestParam|RequestHeader|RequestBody)(?:\(([^)]*)\))?\s+(?:final\s+)?([\w<>,.]+)\s+(\w+)""",
    re.I,
)
JAVA_CLASS_RE = re.compile(r"""(?:public\s+|private\s+|protected\s+)?(?:record|class)\s+(\w+)""", re.I)
JAVA_FIELD_RE = re.compile(
    r"""((?:@[A-Za-z][\w.]*(?:\([^)]*\))?\s*)+)(?:private\s+|public\s+|protected\s+)?([\w<>,.]+)\s+(\w+)\s*[;(]""",
    re.M,
)
JAVA_RECORD_COMPONENTS_RE = re.compile(
    r"""record\s+\w+\s*\((.*)\)""",
    re.S,
)


def spring_method_parameters(text: str, relative: str) -> list[tuple[str, str, str, FieldContract]]:
    """Return (http_method, handler, annotation_kind, field)."""
    results: list[tuple[str, str, str, FieldContract]] = []
    for match in SPRING_METHOD_SIG_RE.finditer(text):
        http_method, _returns, handler, params = match.groups()
        for param in SPRING_PARAM_RE.finditer(params):
            kind, args, type_hint, name = param.groups()
            required = "required = false" not in (args or "").lower()
            explicit = re.search(r"""(?:value|name)\s*=\s*['"]([^'"]+)['"]""", args or "")
            field_name = explicit.group(1) if explicit else name
            quoted = re.match(r"""['"]([^'"]+)['"]""", (args or "").strip())
            if quoted:
                field_name = quoted.group(1)
            results.append(
                (
                    http_method.upper(),
                    handler,
                    kind,
                    field_contract(
                        field_name,
                        type_hint=type_hint,
                        required=required,
                        evidence=evidence(relative, text, match.start() + param.start(), "spring-parameter"),
                        source_file=relative,
                        source_line=line_of(text, match.start()),
                    ),
                )
            )
    return results


def bean_validation_classes(text: str, relative: str) -> dict[str, list[FieldContract]]:
    classes: dict[str, list[FieldContract]] = {}
    for class_match in JAVA_CLASS_RE.finditer(text):
        name = class_match.group(1)
        start = class_match.end()
        nxt = JAVA_CLASS_RE.search(text, start)
        body = text[start : nxt.start() if nxt else len(text)]
        fields: list[FieldContract] = []
        for match in JAVA_FIELD_RE.finditer(body):
            decorators, type_hint, field_name = match.groups()
            fields.append(_bean_field(field_name, type_hint, decorators, relative, text, start + match.start()))
        paren_at = text.find("(", class_match.end() - 1, class_match.end() + 80)
        if "record" in text[max(0, class_match.start() - 20) : class_match.end()].lower() and paren_at != -1:
            for component in _split_top_level(_balanced_inner(text, paren_at)):
                decos = " ".join(re.findall(r"@[A-Za-z][\w.]*(?:\([^)]*\))?", component))
                parts = re.sub(r"@[A-Za-z][\w.]*(?:\([^)]*\))?", "", component).strip().split()
                if len(parts) >= 2:
                    fields.append(_bean_field(parts[-1], parts[-2], decos, relative, text, class_match.start()))
        if fields:
            classes[name] = fields
    return classes


def _bean_field(name: str, type_hint: str, decorators: str, relative: str, text: str, index: int) -> FieldContract:
    lowered = decorators.lower()
    required = any(token in lowered for token in ("@notnull", "@notblank", "@notempty", "@notblank"))
    email = "@email" in lowered
    min_length = max_length = None
    size = re.search(r"@Size\(([^)]*)\)", decorators)
    if size:
        min_length = _int_kw(size.group(1), "min")
        max_length = _int_kw(size.group(1), "max")
    minimum = maximum = None
    min_n = re.search(r"@Min\(\s*value\s*=\s*(-?\d+)|@Min\(\s*(-?\d+)|@Positive", decorators)
    max_n = re.search(r"@Max\(\s*value\s*=\s*(-?\d+)|@Max\(\s*(-?\d+)", decorators)
    if "@Positive" in decorators:
        minimum = 1
    if "@Negative" in decorators:
        maximum = -1
    if min_n:
        minimum = int(next(g for g in min_n.groups() if g and g.lstrip("-").isdigit())) if any(min_n.groups()) else minimum
        try:
            minimum = int(next(g for g in min_n.groups() if g is not None))
        except StopIteration:
            pass
    if max_n:
        try:
            maximum = int(next(g for g in max_n.groups() if g is not None))
        except StopIteration:
            pass
    pattern = ""
    pat = re.search(r"@Pattern\(\s*(?:regexp\s*=\s*)?\"([^\"]+)\"", decorators)
    if pat:
        pattern = pat.group(1)
    validators = re.findall(r"@([A-Za-z]+)", decorators)
    if email:
        validators.append("email")
    return field_contract(
        name,
        type_hint=type_hint,
        validators=validators,
        required=required or email,
        min_length=min_length,
        max_length=max_length,
        minimum=minimum,
        maximum=maximum,
        pattern=pattern,
        evidence=evidence(relative, text, index, "bean-validation"),
        source_file=relative,
        source_line=line_of(text, index),
        confidence_score=90,
    )


# --- Laravel ---

LARAVEL_RULES_RE = re.compile(
    r"""['"]([A-Za-z_][\w.]*)['"]\s*=>\s*['"]([^'"]+)['"]""",
)
LARAVEL_VALIDATE_RE = re.compile(
    r"""(?:\$request->validate|Validator::make)\(\s*[^,]*?,\s*\[(.*?)\]""",
    re.S,
)
LARAVEL_RESOURCE_RE = re.compile(
    r"""Route::(apiResource|resource)\(\s*['"]([^'"]+)['"]""",
    re.I,
)
ELOQUENT_REL_RE = re.compile(
    r"""function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\b(belongsTo|hasMany|hasOne|belongsToMany)\s*\(\s*([A-Za-z:\\]+)::""",
    re.S,
)


def laravel_validation_fields(text: str, relative: str) -> list[FieldContract]:
    fields: dict[str, FieldContract] = {}
    blobs = [match.group(1) for match in LARAVEL_VALIDATE_RE.finditer(text)]
    blobs.append(text)
    for blob in blobs:
        for match in LARAVEL_RULES_RE.finditer(blob):
            name, rules = match.groups()
            tokens = [part.strip() for part in rules.split("|")]
            min_length = max_length = minimum = maximum = None
            pattern = ""
            for token in tokens:
                if token.startswith("min:"):
                    try:
                        value = int(token.split(":", 1)[1])
                    except ValueError:
                        continue
                    if "string" in tokens:
                        min_length = value
                    else:
                        minimum = value
                elif token.startswith("max:"):
                    try:
                        value = int(token.split(":", 1)[1])
                    except ValueError:
                        continue
                    if "string" in tokens:
                        max_length = value
                    else:
                        maximum = value
                elif token.startswith("regex:"):
                    pattern = token.split(":", 1)[1]
            fields[name] = field_contract(
                name,
                type_hint="string",
                validators=tokens,
                required="required" in tokens,
                min_length=min_length,
                max_length=max_length,
                minimum=minimum,
                maximum=maximum,
                pattern=pattern,
                evidence=evidence(relative, text, match.start(), "laravel-validation"),
                source_file=relative,
                source_line=line_of(text, match.start()),
                confidence_score=90,
            )
    return list(fields.values())


def laravel_resource_routes(name: str, api: bool) -> list[tuple[str, str]]:
    base = "/" + name.strip("/")
    param = name.strip("/").rstrip("s") or "id"
    item = f"{base}/{{{param}}}"
    routes = [
        ("GET", base),
        ("POST", base),
        ("GET", item),
        ("PUT", item),
        ("PATCH", item),
        ("DELETE", item),
    ]
    if not api:
        routes.extend(
            [
                ("GET", f"{base}/create"),
                ("GET", f"{item}/edit"),
            ]
        )
    return routes


def eloquent_relationships(text: str, relative: str) -> list[FieldContract]:
    fields: list[FieldContract] = []
    for match in ELOQUENT_REL_RE.finditer(text):
        method, rel, model = match.groups()
        name = f"{method}_id" if rel in {"belongsTo", "hasOne"} else method
        fields.append(
            field_contract(
                name,
                type_hint="integer",
                validators=[rel, model],
                required=rel == "belongsTo",
                evidence=evidence(relative, text, match.start(), "eloquent-relationship"),
                source_file=relative,
                source_line=line_of(text, match.start()),
                confidence_score=80,
            )
        )
    return fields


def laravel_auth_modes(text: str) -> tuple[AuthenticationMode, ...]:
    lowered = text.lower()
    modes: list[AuthenticationMode] = []
    if "auth:sanctum" in lowered or "auth:api" in lowered or "middleware('auth" in lowered or 'middleware("auth' in lowered:
        modes.append(AuthenticationMode.BEARER)
    if "auth" in lowered and not modes:
        modes.append(AuthenticationMode.SESSION)
    return tuple(dict.fromkeys(modes))


# --- ASP.NET ---

ASPNET_PARAM_RE = re.compile(
    r"""\[(FromBody|FromQuery|FromRoute|FromHeader)(?:\([^)]*\))?\]\s*(?:required\s+)?([\w<>,.?]+)\s+(\w+)""",
    re.I,
)
ASPNET_CLASS_RE = re.compile(r"""(?:public\s+)?(?:sealed\s+|partial\s+)?(?:record|class)\s+(\w+)""", re.I)
ASPNET_PROP_RE = re.compile(
    r"""((?:\[[A-Za-z][\w.]*(?:\([^)]*\))?\]\s*)+)public\s+([\w<>,.?]+)\s+(\w+)\s*\{""",
    re.M,
)
ASPNET_RECORD_RE = re.compile(
    r"""record\s+\w+\s*\((.*)\)""",
    re.S,
)


def aspnet_action_parameters(text: str, relative: str) -> list[tuple[str, FieldContract]]:
    results: list[tuple[str, FieldContract]] = []
    for match in ASPNET_PARAM_RE.finditer(text):
        kind, type_hint, name = match.groups()
        results.append(
            (
                kind,
                field_contract(
                    name,
                    type_hint=type_hint,
                    required=kind.lower() in {"frombody", "fromroute"},
                    evidence=evidence(relative, text, match.start(), "aspnet-parameter"),
                    source_file=relative,
                    source_line=line_of(text, match.start()),
                ),
            )
        )
    return results


def dataannotation_classes(text: str, relative: str) -> dict[str, list[FieldContract]]:
    classes: dict[str, list[FieldContract]] = {}
    for class_match in ASPNET_CLASS_RE.finditer(text):
        name = class_match.group(1)
        start = class_match.end()
        nxt = ASPNET_CLASS_RE.search(text, start)
        body = text[start : nxt.start() if nxt else len(text)]
        fields: list[FieldContract] = []
        for match in ASPNET_PROP_RE.finditer(body):
            decorators, type_hint, field_name = match.groups()
            fields.append(_annotation_field(field_name, type_hint, decorators, relative, text, start + match.start()))
        header = text[max(0, class_match.start() - 20) : class_match.end()]
        paren_at = text.find("(", class_match.end() - 1, class_match.end() + 80)
        if "record" in header.lower() and paren_at != -1:
            for component in _split_top_level(_balanced_inner(text, paren_at)):
                decos = " ".join(re.findall(r"\[[A-Za-z][\w.]*(?:\([^)]*\))?\]", component))
                cleaned = re.sub(r"\[[A-Za-z][\w.]*(?:\([^)]*\))?\]", "", component).strip()
                parts = cleaned.split()
                if len(parts) >= 2:
                    fields.append(_annotation_field(parts[-1], parts[-2], decos, relative, text, class_match.start()))
        if fields:
            classes[name] = fields
    return classes


def _annotation_field(name: str, type_hint: str, decorators: str, relative: str, text: str, index: int) -> FieldContract:
    lowered = decorators.lower()
    required = "[required]" in lowered
    min_length = max_length = None
    sl = re.search(r"StringLength\(\s*(\d+)(?:\s*,\s*MinimumLength\s*=\s*(\d+))?", decorators)
    if sl:
        max_length = int(sl.group(1))
        if sl.group(2):
            min_length = int(sl.group(2))
    mn = re.search(r"MinLength\(\s*(\d+)", decorators)
    mx = re.search(r"MaxLength\(\s*(\d+)", decorators)
    if mn:
        min_length = int(mn.group(1))
    if mx:
        max_length = int(mx.group(1))
    minimum = maximum = None
    rng = re.search(r"Range\(\s*(-?\d+)\s*,\s*(-?\d+)", decorators)
    if rng:
        minimum, maximum = int(rng.group(1)), int(rng.group(2))
    pattern = ""
    rx = re.search(r"""RegularExpression\(\s*"([^"]+)" """, decorators)
    if rx:
        pattern = rx.group(1)
    validators = re.findall(r"\[([A-Za-z]+)", decorators)
    return field_contract(
        name,
        type_hint=type_hint,
        validators=validators,
        required=required,
        min_length=min_length,
        max_length=max_length,
        minimum=minimum,
        maximum=maximum,
        pattern=pattern,
        evidence=evidence(relative, text, index, "dataannotations"),
        source_file=relative,
        source_line=line_of(text, index),
        confidence_score=90,
    )


def aspnet_auth_modes(text: str) -> tuple[tuple[AuthenticationMode, ...], bool]:
    if "[AllowAnonymous]" in text:
        return (AuthenticationMode.PUBLIC,), False
    if "[Authorize" in text:
        return (AuthenticationMode.BEARER,), True
    return (AuthenticationMode.UNKNOWN,), False


def schemas_from_fields(groups: dict[str, list[FieldContract]], content_types: dict[str, str] | None = None) -> tuple[SchemaContract, ...]:
    content_types = content_types or {}
    items = []
    for name, fields in groups.items():
        schema = _schema(name, fields, content_types.get(name, "application/json" if name == "request-body" else ""))
        if schema is not None:
            items.append(schema)
    return tuple(items)
