"""Contract, schema, security, and performance response assertions.

PATCH-QAFOX-004B1A-9. Specs are data only. The hardened runner still owns
TLS, SSRF, masking, and one-run plan consumption. Assertions never execute
uploaded code.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from app.smart_data.placeholders import parse_placeholder


ASSERTION_VERSION = "qafox-assertions-v1"
STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)"
    r"|File \"[^\"]+\", line \d+"
    r"|\bat [\w.$]+\([^)]*\)"
    r"|System\.(Exception|NullReferenceException)"
    r"|panic:",
    re.IGNORECASE | re.MULTILINE,
)
SCALAR_TYPES = {
    "string": str,
    "uuid": str,
    "email": str,
    "date": str,
    "datetime": str,
    "url": str,
    "file": str,
    "enum": str,
    "unknown": None,
    "integer": int,
    "int": int,
    "decimal": (int, float),
    "number": (int, float),
    "float": (int, float),
    "currency": (int, float),
    "boolean": bool,
    "bool": bool,
    "object": dict,
    "array": list,
}


@dataclass(frozen=True, slots=True)
class AssertionOutcome:
    assertion_id: str
    kind: str
    passed: bool
    summary: str

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.assertion_id,
            "kind": self.kind,
            "passed": self.passed,
            "summary": self.summary,
        }


def status_matches(actual: int, expected: str) -> bool:
    exact = set()
    ranges = []
    for token in re.split(r"[\s,]+", str(expected or "")):
        token = token.strip().lower()
        if re.fullmatch(r"[1-5][0-9]{2}", token):
            exact.add(int(token))
        elif re.fullmatch(r"[1-5]xx", token):
            ranges.append(int(token[0]))
    if not exact and not ranges:
        return 200 <= actual < 300
    return actual in exact or actual // 100 in ranges


def _json_object(raw: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def default_assertions(
    *,
    case_type: str = "positive",
    expected_status_codes: str = "",
    response_fields: Iterable[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = [
        {
            "id": "status",
            "kind": "status",
            "expected_status_codes": expected_status_codes,
        },
        {"id": "security.no-stack-trace", "kind": "security.no_stack_trace"},
        {"id": "security.no-secret-leak", "kind": "security.no_secrets"},
        {"id": "performance.duration", "kind": "performance.duration"},
    ]
    if str(case_type) == "positive":
        fields = [
            {
                "name": str(field.get("name") or "").strip(),
                "data_type": str(field.get("data_type") or field.get("type") or "unknown"),
                "required": bool(field.get("required", False)),
            }
            for field in response_fields
            if str(field.get("name") or "").strip()
        ]
        if fields:
            specs.append(
                {
                    "id": "schema.response-fields",
                    "kind": "schema.fields",
                    "fields": fields,
                }
            )
    return specs


def assertions_from_evidence(evidence: Any, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = evidence if isinstance(evidence, list) else []
    for item in items:
        if isinstance(item, Mapping) and item.get("type") == "assertions":
            specs = item.get("specs")
            if isinstance(specs, list) and specs:
                return [dict(spec) for spec in specs if isinstance(spec, Mapping)]
    return fallback


def success_response_fields(schema: Mapping[str, Any] | None) -> tuple[dict[str, Any], ...]:
    if not isinstance(schema, Mapping):
        return ()
    responses = schema.get("responses")
    if not isinstance(responses, Mapping):
        return ()
    preferred = None
    for code in ("200", "201", "202", "204"):
        if code in responses:
            preferred = responses[code]
            break
    if preferred is None:
        for code, payload in responses.items():
            if str(code).startswith("2"):
                preferred = payload
                break
    if isinstance(preferred, Mapping):
        fields = preferred.get("fields")
        if isinstance(fields, list):
            return tuple(item for item in fields if isinstance(item, Mapping))
    if isinstance(preferred, list):
        return tuple(item for item in preferred if isinstance(item, Mapping))
    return ()


def evaluate_assertions(
    specs: Iterable[Mapping[str, Any]],
    *,
    status_code: int,
    body: str,
    headers: Mapping[str, Any] | None = None,
    duration_ms: int | None = None,
    secret_values: Iterable[str] = (),
    timeout_ms: int | None = None,
    expected_status_codes: str = "",
) -> tuple[bool, str, tuple[AssertionOutcome, ...]]:
    outcomes: list[AssertionOutcome] = []
    headers = headers or {}
    secrets = [
        value
        for value in secret_values
        if isinstance(value, str) and len(value.strip()) >= 8
    ]

    parsed_body = _json_object(body)
    for spec in specs:
        kind = str(spec.get("kind") or "")
        assertion_id = str(spec.get("id") or kind)
        if kind == "status":
            expected = str(spec.get("expected_status_codes") or expected_status_codes)
            passed = status_matches(status_code, expected)
            summary = (
                "Actual status matched expected status."
                if passed
                else f"Expected {expected or '2xx'}; received {status_code}."
            )
        elif kind == "security.no_stack_trace":
            passed = STACK_TRACE_RE.search(str(body or "")) is None
            summary = (
                "Response does not include a stack trace."
                if passed
                else "Response appears to include an implementation stack trace."
            )
        elif kind == "security.no_secrets":
            text = str(body or "")
            leaked = any(value and value in text for value in secrets)
            passed = not leaked
            summary = (
                "Response does not echo secret values."
                if passed
                else "Response body echoed a secret or credential value."
            )
        elif kind == "performance.duration":
            budget = spec.get("max_ms", timeout_ms)
            if duration_ms is None or budget is None:
                passed = True
                summary = "Performance budget was not evaluated."
            else:
                passed = int(duration_ms) <= int(budget)
                summary = (
                    f"Duration {duration_ms}ms is within {budget}ms."
                    if passed
                    else f"Duration {duration_ms}ms exceeded the {budget}ms budget."
                )
        elif kind == "schema.fields":
            passed, summary = _evaluate_schema_fields(spec.get("fields") or [], parsed_body)
        else:
            passed = True
            summary = f"Unknown assertion kind '{kind}' was ignored."
        outcomes.append(AssertionOutcome(assertion_id, kind, passed, summary))

    failed = [item for item in outcomes if not item.passed]
    all_passed = not failed
    if all_passed:
        headline = "All contract, security and performance assertions passed."
    else:
        headline = failed[0].summary
        if len(failed) > 1:
            headline += f" ({len(failed)} assertions failed.)"
    return all_passed, headline, tuple(outcomes)


def _evaluate_schema_fields(fields: Iterable[Any], parsed: Any) -> tuple[bool, str]:
    required = [
        field
        for field in fields
        if isinstance(field, Mapping)
        and field.get("required")
        and str(field.get("name") or "").strip()
    ]
    if not required:
        return True, "No required response fields were documented."
    if parsed is None:
        return False, "Documented JSON response fields could not be parsed."
    if isinstance(parsed, list):
        if not parsed:
            return False, "Documented JSON array response was empty."
        parsed = parsed[0]
    if not isinstance(parsed, Mapping):
        return False, "Documented JSON object response was not an object."
    missing = []
    wrong_type = []
    for field in required:
        name = str(field.get("name"))
        if name not in parsed:
            missing.append(name)
            continue
        expected = str(field.get("data_type") or "unknown").lower()
        python_type = SCALAR_TYPES.get(expected)
        value = parsed[name]
        if python_type is None:
            continue
        if python_type is int and isinstance(value, bool):
            wrong_type.append(name)
            continue
        if not isinstance(value, python_type):
            wrong_type.append(name)
    if missing:
        return False, "Missing required response field(s): " + ", ".join(missing[:6])
    if wrong_type:
        return False, "Response field type mismatch: " + ", ".join(wrong_type[:6])
    return True, "Required response fields matched the documented contract."


def sanitize_assertion_specs(specs: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for spec in specs:
        if not isinstance(spec, Mapping):
            continue
        item = {str(key): value for key, value in spec.items() if key != "value"}
        for key, value in list(item.items()):
            if isinstance(value, str) and parse_placeholder(value) is None and "secret" in key.lower():
                item[key] = "[REDACTED]"
        cleaned.append(item)
    return cleaned
