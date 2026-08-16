import json
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.smart_data.assertions import (
    ASSERTION_VERSION,
    default_assertions,
    success_response_fields,
)
from app.smart_data.contracts import (
    DependencyRelationship,
    FieldContract,
    SemanticType,
)
from app.smart_data.generator import generate_field
from app.smart_data.placeholders import (
    PlaceholderKind,
    apply_placeholder_safety,
    approval_blockers,
    build_placeholder,
    parse_placeholder,
    request_payload as case_request_payload,
)

from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)

router = APIRouter()

SAFE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}

ALLOWED_CASE_TYPES = {
    "positive",
    "authentication",
    "authorization",
    "validation",
    "boundary",
    "path-parameter",
    "content-type",
    "security",
    "performance",
    "manual",
}

ALLOWED_STATUS_VALUES = re.compile(
    r"^[0-9xX,\-\s]+$"
)


def utc_now():
    return datetime.now(timezone.utc)


def owned_project(
    db: Session,
    owner_user_id: int,
    public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM projects
                WHERE public_id = :public_id
                  AND owner_user_id = :owner_user_id
                  AND deleted_at IS NULL
                LIMIT 1
                """
            ),
            {
                "public_id": public_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def latest_inventory(
    db: Session,
    owner_user_id: int,
    project_id: int,
):
    run = (
        db.execute(
            text(
                """
                SELECT id
                FROM api_discovery_runs
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND status = 'completed'
                ORDER BY completed_at DESC NULLS LAST,
                         started_at DESC
                LIMIT 1
                """
            ),
            {
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )

    if not run:
        return []

    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_inventory
                WHERE discovery_run_id = :run_id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND is_duplicate = FALSE
                ORDER BY endpoint_path, http_method
                """
            ),
            {
                "run_id": run["id"],
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .all()
    )


def owned_case(
    db: Session,
    owner_user_id: int,
    project_id: int,
    case_public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_test_cases
                WHERE public_id = :public_id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                LIMIT 1
                """
            ),
            {
                "public_id": case_public_id,
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def parse_json_object(
    raw: str,
    field_name: str,
):
    raw = raw.strip()

    if not raw:
        return {}

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{field_name} must be valid JSON."
        ) from exc

    if not isinstance(value, dict):
        raise ValueError(
            f"{field_name} must be a JSON object."
        )

    return value


def documented_statuses(endpoint) -> str:
    raw = str(
        endpoint["response_codes"] or ""
    ).strip()

    codes = re.findall(
        r"\b[1-5][0-9xX]{2}\b",
        raw,
    )

    success = [
        code
        for code in codes
        if code.startswith("2")
    ]

    if success:
        return ",".join(dict.fromkeys(success))

    method = endpoint["http_method"].upper()

    if method == "POST":
        return "200,201,202"

    if method == "DELETE":
        return "200,202,204"

    return "200,204"


def authentication_required(endpoint) -> bool:
    value = str(
        endpoint["authentication"] or ""
    ).lower()

    return not any(
        token in value
        for token in {
            "public",
            "none",
            "not declared",
            "unknown",
        }
    )


def parameter_names(path: str) -> list[str]:
    names = re.findall(
        r"\{([^}:]+)(?::[^}]+)?\}|:([A-Za-z_][A-Za-z0-9_]*)",
        path,
    )

    result = []

    for first, second in names:
        value = first or second

        if value and value not in result:
            result.append(value)

    return result


def schema_has_request_input(endpoint) -> bool:
    raw = str(
        endpoint["request_schema"] or ""
    ).strip()

    if not raw or raw in {"{}", "null"}:
        return False

    try:
        parsed = json.loads(raw)
    except Exception:
        return True

    if not isinstance(parsed, dict):
        return bool(parsed)

    return bool(
        parsed.get("parameters")
        or parsed.get("requestBody")
        or parsed.get("body")
    )


def make_case(
    endpoint,
    case_type: str,
    title: str,
    description: str,
    expected_status_codes: str,
    expected_behavior: str,
    confidence: int,
    request_headers=None,
    request_query=None,
    request_body=None,
):
    method = endpoint["http_method"].upper()

    safe = method in SAFE_METHODS

    return {
        "public_id": str(uuid.uuid4()),
        "inventory_id": endpoint["id"],
        "title": title,
        "description": description,
        "case_type": case_type,
        "http_method": method,
        "endpoint_path": endpoint["endpoint_path"],
        "request_headers": json.dumps(
            request_headers or {},
            ensure_ascii=False,
        ),
        "request_query": json.dumps(
            request_query or {},
            ensure_ascii=False,
        ),
        "request_body": (
            json.dumps(
                request_body,
                ensure_ascii=False,
            )
            if request_body is not None
            else None
        ),
        "expected_status_codes": expected_status_codes,
        "expected_behavior": expected_behavior,
        "confidence": confidence,
        "generation_source": (
            "Qubi contract and static-analysis inference"
        ),
        "safe_to_execute": safe,
        "requires_approval": not safe,
    }




def parse_intelligence_json(
    raw,
    fallback,
):
    if isinstance(raw, dict):
        return raw

    if not raw:
        return fallback

    try:
        parsed = json.loads(str(raw))
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return fallback

    return (
        parsed
        if isinstance(parsed, type(fallback))
        else fallback
    )

def source_evidence(endpoint) -> dict:
    return parse_intelligence_json(
        endpoint.get(
            "input_evidence",
            "{}",
        ),
        {},
    )


def smart_schema(endpoint) -> dict:
    return parse_intelligence_json(
        endpoint.get(
            "smart_data_schema",
            "{}",
        ),
        {},
    )


def field_contract(field: dict) -> FieldContract:
    name = str(field.get("name", "")).strip()
    semantic_raw = str(field.get("semantic_type", "unknown"))
    try:
        semantic = SemanticType(semantic_raw)
    except ValueError:
        semantic = SemanticType.UNKNOWN
    dependency = None
    dependency_raw = field.get("dependency")
    if isinstance(dependency_raw, dict):
        dependency = DependencyRelationship(
            str(dependency_raw.get("resource", name.removesuffix("_id"))),
            str(dependency_raw.get("field", "id")),
            confidence_score=int(dependency_raw.get("confidence_score", 70)),
        )
    children = tuple(
        field_contract(item)
        for item in field.get("children", [])
        if isinstance(item, dict)
    )
    enum_values = field.get("enum_values", field.get("enum", []))
    return FieldContract(
        name=name,
        semantic_type=semantic,
        data_type=str(field.get("data_type", field.get("type", "unknown"))),
        required=bool(field.get("required", False)),
        default_value=field.get("default_value", field.get("default")),
        minimum=field.get("minimum"),
        maximum=field.get("maximum"),
        min_length=field.get("min_length", field.get("minLength")),
        max_length=field.get("max_length", field.get("maxLength")),
        pattern=str(field.get("pattern", "")),
        format=str(field.get("format", "")),
        enum_values=tuple(enum_values) if isinstance(enum_values, list) else (),
        nullable=bool(field.get("nullable", False)),
        secret=bool(field.get("secret", False)),
        dependency=dependency,
        confidence_score=int(field.get("confidence_score", 0)),
        source_file=str(field.get("source_file", "")),
        source_line=field.get("source_line"),
        children=children,
    )


def enrich_with_smart_test_data(
    endpoint,
    cases,
):
    path = endpoint["endpoint_path"]
    method = endpoint["http_method"].upper()
    schema = smart_schema(endpoint)
    evidence = source_evidence(endpoint)

    fields = schema.get("fields", [])

    if not isinstance(fields, list):
        fields = []

    synthetic_data = {}
    generation_details = {}

    for field in fields:
        if not isinstance(field, dict):
            continue

        name = str(
            field.get("name", "")
        ).strip()

        if not name:
            continue

        result = generate_field(
            field_contract(field),
            "request",
        )
        synthetic_data[name] = result.value
        generation_details[name] = {
            "semantic_type": result.semantic_type.value,
            "strategy": result.strategy,
            "reason": result.reason,
            "confidence_score": result.confidence_score,
            "status": result.status,
            "editable": result.editable,
        }

    authentication = str(
        endpoint.get(
            "authentication",
            "",
        )
    ).lower()

    session_required = (
        "session" in authentication
    )

    path_parameters = parameter_names(path)

    for case in cases:
        prerequisites = []
        case_evidence = []

        route_prefix = endpoint.get(
            "route_prefix",
            "",
        )

        if route_prefix:
            case_evidence.append(
                {
                    "type": "route-prefix",
                    "value": route_prefix,
                    "source": endpoint.get(
                        "source_file",
                        "",
                    ),
                }
            )

        for item in evidence.get(
            "authentication_evidence",
            [],
        ):
            case_evidence.append(
                {
                    "type": "authentication",
                    "value": item,
                    "source": endpoint.get(
                        "source_file",
                        "",
                    ),
                }
            )

        positive = (
            case["case_type"] == "positive"
        )

        if positive and session_required:
            prerequisites.append(
                {
                    "name": "authenticated_admin_session",
                    "status": "required",
                    "reason": (
                        "Source route checks the admin session."
                    ),
                }
            )

        if positive:
            for parameter in path_parameters:
                marker = build_placeholder(
                    PlaceholderKind.REQUIRED,
                    "resource." + parameter,
                )

                case["endpoint_path"] = re.sub(
                    rf"\{{{re.escape(parameter)}"
                    rf"(?:\:[^}}]+)?\}}",
                    marker,
                    case["endpoint_path"],
                )

                prerequisites.append(
                    {
                        "name": parameter,
                        "status": "required",
                        "reason": (
                            "Positive resource test requires "
                            "an existing resource identifier."
                        ),
                    }
                )

        if (
            positive
            and method in {
                "POST",
                "PUT",
                "PATCH",
            }
            and synthetic_data
        ):
            case["request_body"] = json.dumps(
                synthetic_data,
                ensure_ascii=False,
            )

            case["request_headers"] = json.dumps(
                {
                    "Content-Type": (
                        schema.get("content_type")
                        or "application/json"
                    )
                },
                ensure_ascii=False,
            )

        for name, value in synthetic_data.items():
            placeholder = (
                parse_placeholder(value)
                if isinstance(value, str)
                else None
            )
            if placeholder and placeholder.blocks_approval:
                prerequisites.append(
                    {
                        "name": name,
                        "status": "required",
                        "reason": generation_details[name]["reason"],
                    }
                )

        generation_statuses = {
            item["status"]
            for item in generation_details.values()
        }
        if "secret-reference-required" in generation_statuses:
            case["data_status"] = "secret-reference-required"
        elif prerequisites:
            case["data_status"] = "prerequisite-required"
        elif "review-recommended" in generation_statuses:
            case["data_status"] = "review-recommended"
        else:
            case["data_status"] = "ready"

        case["prerequisites"] = prerequisites
        case["evidence"] = case_evidence
        case["evidence"].append(
            {
                "type": "semantic-generation",
                "fields": generation_details,
            }
        )
        case["synthetic_data"] = (
            synthetic_data
            if positive
            else {}
        )

        stored_headers = parse_intelligence_json(
            case.get(
                "request_headers",
                "{}",
            ),
            {},
        )

        case["request_content_type"] = (
            stored_headers.get(
                "Content-Type"
            )
        )

        if prerequisites:
            case["description"] += (
                " Qubi detected prerequisite data; "
                "review and replace editable placeholders "
                "before execution."
            )

        case["generation_source"] = (
            "Qubi source-aware route, schema, validation "
            "and form intelligence"
        )

        apply_placeholder_safety(case)
        specs = default_assertions(
            case_type=case["case_type"],
            expected_status_codes=case["expected_status_codes"],
            response_fields=success_response_fields(schema)
            if case["case_type"] == "positive"
            else (),
        )
        case["assertions"] = specs
        case["evidence"].append(
            {
                "type": "assertions",
                "version": ASSERTION_VERSION,
                "specs": specs,
            }
        )

    return cases

def generate_for_endpoint(endpoint):
    method = endpoint["http_method"].upper()
    path = endpoint["endpoint_path"]
    auth_required = authentication_required(
        endpoint
    )

    cases = [
        make_case(
            endpoint,
            "positive",
            f"{method} {path} — valid request",
            (
                "Verify that the endpoint accepts a structurally "
                "valid request and returns its documented success response."
            ),
            documented_statuses(endpoint),
            (
                "The API should return a successful response without "
                "exposing secrets, stack traces or internal implementation."
            ),
            max(
                70,
                int(endpoint["confidence_score"] or 70),
            ),
        )
    ]

    if auth_required:
        cases.append(
            make_case(
                endpoint,
                "authentication",
                f"{method} {path} — missing credentials",
                (
                    "Send the request without authentication credentials."
                ),
                "401,403",
                (
                    "Access must be rejected without returning protected data."
                ),
                94,
            )
        )

        cases.append(
            make_case(
                endpoint,
                "authorization",
                f"{method} {path} — invalid credentials",
                (
                    "Send an invalid or expired authentication value."
                ),
                "401,403",
                (
                    "Access must be rejected and the credential value "
                    "must not appear in the response."
                ),
                92,
                request_headers={
                    "Authorization": "Bearer {{INVALID_TOKEN}}",
                },
            )
        )

    for name in parameter_names(path):
        invalid_path = re.sub(
            rf"\{{{re.escape(name)}(?:\:[^}}]+)?\}}|:{re.escape(name)}\b",
            "{{INVALID_" + name.upper() + "}}",
            path,
        )

        case = make_case(
            endpoint,
            "path-parameter",
            f"{method} {path} — invalid {name}",
            (
                f"Send an invalid value for path parameter '{name}'."
            ),
            "400,404,422",
            (
                "The API should reject the invalid identifier without "
                "revealing another tenant's resource."
            ),
            88,
        )

        case["endpoint_path"] = invalid_path
        cases.append(case)

    if schema_has_request_input(endpoint):
        cases.append(
            make_case(
                endpoint,
                "validation",
                f"{method} {path} — missing required input",
                (
                    "Omit required request fields or parameters."
                ),
                "400,422",
                (
                    "The API should return a structured validation error "
                    "without a server exception."
                ),
                88,
                request_body={},
            )
        )

        cases.append(
            make_case(
                endpoint,
                "boundary",
                f"{method} {path} — oversized input",
                (
                    "Supply an over-limit string value in a request field."
                ),
                "400,413,422",
                (
                    "The API should safely reject values exceeding "
                    "documented or platform limits."
                ),
                80,
                request_body={
                    "_qafox_boundary_value": "{{OVERSIZED_STRING}}",
                },
            )
        )

    if method in {
        "POST",
        "PUT",
        "PATCH",
    }:
        cases.append(
            make_case(
                endpoint,
                "content-type",
                f"{method} {path} — unsupported content type",
                (
                    "Send a request body using an unsupported media type."
                ),
                "400,415,422",
                (
                    "The API should reject the request cleanly and must "
                    "not partially modify data."
                ),
                85,
                request_headers={
                    "Content-Type": "text/plain",
                },
                request_body={
                    "_qafox_value": "invalid-content-type",
                },
            )
        )

    return enrich_with_smart_test_data(
        endpoint,
        cases,
    )


def insert_generated_case(
    db: Session,
    project_id: int,
    owner_user_id: int,
    item: dict,
):
    db.execute(
        text(
            """
            INSERT INTO api_test_cases (
                public_id,
                project_id,
                owner_user_id,
                inventory_id,
                title,
                description,
                case_type,
                http_method,
                endpoint_path,
                request_headers,
                request_query,
                request_body,
                expected_status_codes,
                expected_behavior,
                confidence,
                generation_source,
                is_enabled,
                safe_to_execute,
                requires_approval,
                data_status,
                prerequisites_json,
                evidence_json,
                synthetic_data_json,
                request_content_type,
                original_endpoint_path,
                created_at,
                updated_at
            )
            VALUES (
                :public_id,
                :project_id,
                :owner_user_id,
                :inventory_id,
                :title,
                :description,
                :case_type,
                :http_method,
                :endpoint_path,
                :request_headers,
                :request_query,
                :request_body,
                :expected_status_codes,
                :expected_behavior,
                :confidence,
                :generation_source,
                TRUE,
                :safe_to_execute,
                :requires_approval,
                :data_status,
                :prerequisites_json,
                :evidence_json,
                :synthetic_data_json,
                :request_content_type,
                :original_endpoint_path,
                :created_at,
                :updated_at
            )
            ON CONFLICT (
                owner_user_id,
                project_id,
                inventory_id,
                case_type
            )
            DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                http_method = EXCLUDED.http_method,
                endpoint_path = EXCLUDED.endpoint_path,
                request_headers = EXCLUDED.request_headers,
                request_query = EXCLUDED.request_query,
                request_body = EXCLUDED.request_body,
                expected_status_codes =
                    EXCLUDED.expected_status_codes,
                expected_behavior =
                    EXCLUDED.expected_behavior,
                confidence = EXCLUDED.confidence,
                generation_source =
                    EXCLUDED.generation_source,
                safe_to_execute =
                    EXCLUDED.safe_to_execute,
                requires_approval =
                    EXCLUDED.requires_approval,
                data_status =
                    EXCLUDED.data_status,
                prerequisites_json =
                    EXCLUDED.prerequisites_json,
                evidence_json =
                    EXCLUDED.evidence_json,
                synthetic_data_json =
                    EXCLUDED.synthetic_data_json,
                request_content_type =
                    EXCLUDED.request_content_type,
                original_endpoint_path =
                    EXCLUDED.original_endpoint_path,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            **item,
            "project_id": project_id,
            "owner_user_id": owner_user_id,
            "data_status": item.get(
                "data_status",
                "ready",
            ),
            "prerequisites_json": json.dumps(
                item.get("prerequisites", []),
                ensure_ascii=False,
            ),
            "evidence_json": json.dumps(
                item.get("evidence", []),
                ensure_ascii=False,
            ),
            "synthetic_data_json": json.dumps(
                item.get("synthetic_data", {}),
                ensure_ascii=False,
            ),
            "request_content_type": item.get(
                "request_content_type",
            ),
            "original_endpoint_path": endpoint_original
                if (endpoint_original := item.get(
                    "original_endpoint_path"
                ))
                else item.get("endpoint_path"),
            "created_at": utc_now(),
            "updated_at": utc_now(),
        },
    )


@router.post(
    "/projects/{public_id}/test-cases/generate"
)
def generate_test_cases(
    request: Request,
    public_id: str,
    csrf: str = Form(...),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            f"/projects/{public_id}/test-cases"
            "?error=Security+validation+failed.",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        inventory = latest_inventory(
            db,
            user.id,
            project["id"],
        )

        if not inventory:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases"
                "?error=Run+API+discovery+before+generating+test+cases.",
                status_code=303,
            )

        generated_count = 0

        for endpoint in inventory:
            for item in generate_for_endpoint(
                endpoint
            ):
                insert_generated_case(
                    db,
                    project["id"],
                    user.id,
                    item,
                )
                generated_count += 1

        db.execute(
            text(
                """
                INSERT INTO project_audit_events (
                    project_id,
                    owner_user_id,
                    event_type,
                    event_summary,
                    created_at
                )
                VALUES (
                    :project_id,
                    :owner_user_id,
                    'api-test-cases-generated',
                    :summary,
                    :created_at
                )
                """
            ),
            {
                "project_id": project["id"],
                "owner_user_id": user.id,
                "summary": (
                    f"Qubi generated or refreshed "
                    f"{generated_count} API test-case suggestions."
                ),
                "created_at": utc_now(),
            },
        )

        db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/test-cases"
        f"?message={generated_count}+test-case+suggestions+generated.",
        status_code=303,
    )


@router.post(
    "/projects/{public_id}/test-cases/manual"
)
def create_manual_test_case(
    request: Request,
    public_id: str,
    csrf: str = Form(...),
    inventory_id: str = Form(...),
    title: str = Form(...),
    expected_status_codes: str = Form("200"),
    expected_behavior: str = Form(...),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            f"/projects/{public_id}/test-cases"
            "?error=Security+validation+failed.",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
        endpoint_id = int(inventory_id)
    except ValueError:
        return RedirectResponse(
            f"/projects/{public_id}/test-cases"
            "?error=Select+a+discovered+endpoint.",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        inventory = latest_inventory(
            db,
            user.id,
            project["id"],
        )
        endpoint = next(
            (
                item
                for item in inventory
                if int(item["id"]) == endpoint_id
            ),
            None,
        )

        if not endpoint:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases"
                "?error=That+endpoint+is+not+in+the+current+inventory.",
                status_code=303,
            )

        title = title.strip()
        expected_behavior = expected_behavior.strip()
        expected_status_codes = expected_status_codes.strip() or "200"

        if len(title) < 2:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases"
                "?error=Enter+a+manual+case+title.",
                status_code=303,
            )

        if not ALLOWED_STATUS_VALUES.fullmatch(expected_status_codes):
            return RedirectResponse(
                f"/projects/{public_id}/test-cases"
                "?error=Expected+status+codes+are+invalid.",
                status_code=303,
            )

        item = make_case(
            endpoint,
            "manual",
            title[:200],
            "Human-authored case for UAT coverage.",
            expected_status_codes,
            expected_behavior[:400],
            100,
        )
        item["generation_source"] = "human"
        insert_generated_case(
            db,
            project["id"],
            user.id,
            item,
        )
        db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/test-cases"
        "?message=Manual+test+case+saved.",
        status_code=303,
    )


@router.get(
    "/projects/{public_id}/test-cases",
    response_class=HTMLResponse,
)
def test_case_list(
    request: Request,
    public_id: str,
    type: str = "",
    enabled: str = "",
    message: str = "",
    error: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        conditions = [
            "project_id = :project_id",
            "owner_user_id = :owner_user_id",
        ]

        parameters = {
            "project_id": project["id"],
            "owner_user_id": user.id,
        }

        if type in ALLOWED_CASE_TYPES:
            conditions.append(
                "case_type = :case_type"
            )
            parameters["case_type"] = type

        if enabled in {"yes", "no"}:
            conditions.append(
                "is_enabled = :is_enabled"
            )
            parameters["is_enabled"] = (
                enabled == "yes"
            )

        cases = (
            db.execute(
                text(
                    f"""
                    SELECT *
                    FROM api_test_cases
                    WHERE {' AND '.join(conditions)}
                    ORDER BY
                        endpoint_path,
                        http_method,
                        case_type
                    """
                ),
                parameters,
            )
            .mappings()
            .all()
        )

        total = db.execute(
            text(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (
                        WHERE is_enabled = TRUE
                    ) AS enabled,
                    COUNT(*) FILTER (
                        WHERE safe_to_execute = TRUE
                    ) AS safe,
                    COUNT(*) FILTER (
                        WHERE requires_approval = TRUE
                    ) AS approval
                FROM api_test_cases
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                """
            ),
            parameters,
        ).mappings().one()

        inventory = latest_inventory(
            db,
            user.id,
            project["id"],
        )

    csrf = csrf_token(request)

    inventory_options = "".join(
        f'<option value="{esc(str(item["id"]))}">'
        f'{esc(item["http_method"])} {esc(item["endpoint_path"])}'
        f"</option>"
        for item in inventory
    )

    rows = ""

    for case in cases:
        safety = (
            '<span class="case-safe">Safe</span>'
            if case["safe_to_execute"]
            else '<span class="case-approval">Approval required</span>'
        )

        enabled_badge = (
            '<span class="case-enabled">Enabled</span>'
            if case["is_enabled"]
            else '<span class="case-disabled">Disabled</span>'
        )

        rows += f"""
        <tr>
            <td>
                <span class="method-badge method-{esc(case["http_method"].lower())}">
                    {esc(case["http_method"])}
                </span>
            </td>
            <td>
                <strong>{esc(case["title"])}</strong>
                <code>{esc(case["endpoint_path"])}</code>
            </td>
            <td>
                <span class="case-type">{esc(case["case_type"])}</span>
            </td>
            <td>
                <strong>{esc(str(case["confidence"]))}%</strong>
            </td>
            <td>
                {safety}
                {enabled_badge}
            </td>
            <td>
                <a class="case-edit-button"
                   href="/projects/{esc(public_id)}/test-cases/{esc(case["public_id"])}/edit">
                    Review / Edit
                </a>
            </td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="6" class="case-empty-row">
                No test cases found. Ask Qubi to generate them.
            </td>
        </tr>
        """

    notice = ""

    if message:
        notice = (
            f'<div class="case-notice success">'
            f'{esc(message)}</div>'
        )
    elif error:
        notice = (
            f'<div class="case-notice error">'
            f'{esc(error)}</div>'
        )

    content = f"""
<section class="test-case-shell">
    <div class="test-case-heading">
        <div>
            <a href="/projects/{esc(public_id)}/api-inventory">
                ← API inventory
            </a>
            <span>QUBI AI TEST DESIGN</span>
            <h1>Generated API test cases</h1>
            <p>
                Intelligent, editable scenarios generated from the
                discovered API contract and source evidence.
            </p>
        </div>

        <form method="post"
              action="/projects/{esc(public_id)}/test-cases/generate">
            <input type="hidden"
                   name="csrf"
                   value="{esc(csrf)}">

            <button class="primary-button"
                    type="submit">
                ✨ Generate / refresh
            </button>
        </form>
    </div>

    {notice}

    <div class="qubi-safety-banner">
        <div>🦊</div>
        <div>
            <strong>Qubi generated suggestions—not execution.</strong>
            <p>
                Safe read-only cases are identified automatically.
                State-changing cases require explicit approval in the
                execution patch.
            </p>
        </div>
    </div>

    <div class="test-case-stats">
        <article>
            <strong>{esc(str(total["total"]))}</strong>
            <span>Total cases</span>
        </article>
        <article>
            <strong>{esc(str(total["enabled"]))}</strong>
            <span>Enabled</span>
        </article>
        <article>
            <strong>{esc(str(total["safe"]))}</strong>
            <span>Safe/read-only</span>
        </article>
        <article>
            <strong>{esc(str(total["approval"]))}</strong>
            <span>Approval required</span>
        </article>
    </div>

    <form class="test-case-filters"
          method="get">
        <select name="type">
            <option value="">All case types</option>
            {
                "".join(
                    f'<option value="{esc(item)}"'
                    + (
                        " selected"
                        if type == item
                        else ""
                    )
                    + f'>{esc(item.title())}</option>'
                    for item in sorted(ALLOWED_CASE_TYPES)
                )
            }
        </select>

        <select name="enabled">
            <option value="">All states</option>
            <option value="yes" {
                "selected" if enabled == "yes" else ""
            }>Enabled</option>
            <option value="no" {
                "selected" if enabled == "no" else ""
            }>Disabled</option>
        </select>

        <button class="outline-dark-button"
                type="submit">
            Apply filters
        </button>
    </form>

    <form class="test-case-filters"
          method="post"
          action="/projects/{esc(public_id)}/test-cases/manual">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <select name="inventory_id" required>
            <option value="">Inventory endpoint</option>
            {inventory_options}
        </select>
        <input name="title" required maxlength="200" placeholder="Manual case title">
        <input name="expected_status_codes" maxlength="40" value="200" placeholder="Expected status">
        <input name="expected_behavior" required maxlength="400" placeholder="Expected behaviour">
        <button class="outline-dark-button" type="submit">
            Add manual case
        </button>
    </form>

    <div class="test-case-table-wrap">
        <table class="test-case-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Test case</th>
                    <th>Type</th>
                    <th>Confidence</th>
                    <th>Execution class</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
</section>
"""

    return layout(
        "Generated API test cases",
        content,
        request,
        public=False,
    )


def edit_form(
    request: Request,
    project,
    case,
    error: str = "",
):
    csrf = csrf_token(request)

    notice = (
        f'<div class="case-notice error">{esc(error)}</div>'
        if error
        else ""
    )

    content = f"""
<section class="case-editor-shell">
    <a href="/projects/{esc(project["public_id"])}/test-cases">
        ← Generated test cases
    </a>

    <span>HUMAN-REVIEWABLE AI</span>
    <h1>Review test case</h1>
    <p>
        Qubi’s generated values remain fully editable. Secret values
        should use placeholders and must not be entered here.
    </p>

    {notice}

    <form class="case-editor"
          method="post"
          action="/projects/{esc(project["public_id"])}/test-cases/{esc(case["public_id"])}/edit">

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <label>
            Title
            <input name="title"
                   maxlength="240"
                   required
                   value="{esc(case["title"])}">
        </label>

        <label>
            Description
            <textarea name="description"
                      rows="3">{esc(case["description"])}</textarea>
        </label>

        <div class="case-editor-grid">
            <label>
                Method
                <input value="{esc(case["http_method"])}"
                       readonly>
            </label>

            <label>
                Case type
                <select name="case_type">
                    {
                        "".join(
                            f'<option value="{esc(item)}"'
                            + (
                                " selected"
                                if case["case_type"] == item
                                else ""
                            )
                            + f'>{esc(item.title())}</option>'
                            for item in sorted(ALLOWED_CASE_TYPES)
                        )
                    }
                </select>
            </label>
        </div>

        <label>
            Endpoint path
            <input name="endpoint_path"
                   maxlength="2048"
                   required
                   value="{esc(case["endpoint_path"])}">
        </label>

        <div class="case-editor-grid">
            <label>
                Request headers — JSON
                <textarea name="request_headers"
                          rows="6">{esc(case["request_headers"])}</textarea>
            </label>

            <label>
                Query parameters — JSON
                <textarea name="request_query"
                          rows="6">{esc(case["request_query"])}</textarea>
            </label>
        </div>

        <label>
            Request body — JSON
            <textarea name="request_body"
                      rows="7">{esc(case["request_body"] or "")}</textarea>
        </label>

        <label>
            Expected status codes
            <input name="expected_status_codes"
                   maxlength="120"
                   required
                   value="{esc(case["expected_status_codes"])}">
        </label>

        <label>
            Expected behaviour
            <textarea name="expected_behavior"
                      rows="4"
                      required>{esc(case["expected_behavior"])}</textarea>
        </label>

        <label class="case-enable-check">
            <input type="checkbox"
                   name="is_enabled"
                   value="true"
                   {
                       "checked"
                       if case["is_enabled"]
                       else ""
                   }>
            <span>
                <strong>Enable this test case</strong>
                <small>
                    Disabled cases will not be included in execution.
                </small>
            </span>
        </label>

        <div class="case-execution-warning">
            {
                "✓ Classified as safe/read-only."
                if case["safe_to_execute"]
                else "⚠ State-changing method: explicit execution approval required."
            }
        </div>

        <button class="primary-button"
                type="submit">
            Save reviewed test case
        </button>
    </form>
</section>
"""

    return layout(
        "Review test case",
        content,
        request,
        public=False,
    )


@router.get(
    "/projects/{public_id}/test-cases/{case_public_id}/edit",
    response_class=HTMLResponse,
)
def edit_test_case_page(
    request: Request,
    public_id: str,
    case_public_id: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
        uuid.UUID(case_public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        case = owned_case(
            db,
            user.id,
            project["id"],
            case_public_id,
        )

        if not case:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases",
                status_code=303,
            )

    return edit_form(
        request,
        project,
        case,
    )


@router.post(
    "/projects/{public_id}/test-cases/{case_public_id}/edit",
    response_class=HTMLResponse,
)
def update_test_case(
    request: Request,
    public_id: str,
    case_public_id: str,
    csrf: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    case_type: str = Form(...),
    endpoint_path: str = Form(...),
    request_headers: str = Form("{}"),
    request_query: str = Form("{}"),
    request_body: str = Form(""),
    expected_status_codes: str = Form(...),
    expected_behavior: str = Form(...),
    is_enabled: str | None = Form(None),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
        uuid.UUID(case_public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        case = owned_case(
            db,
            user.id,
            project["id"],
            case_public_id,
        )

        if not case:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases",
                status_code=303,
            )

        if not csrf_valid(request, csrf):
            return edit_form(
                request,
                project,
                case,
                "Security validation failed.",
            )

        try:
            parsed_headers = parse_json_object(
                request_headers,
                "Request headers",
            )

            parsed_query = parse_json_object(
                request_query,
                "Query parameters",
            )

            parsed_body = None

            if request_body.strip():
                parsed_body = json.loads(
                    request_body
                )

            if case_type not in ALLOWED_CASE_TYPES:
                raise ValueError(
                    "Select a valid test-case type."
                )

            if (
                not endpoint_path.startswith("/")
                or len(endpoint_path) > 2048
            ):
                raise ValueError(
                    "Endpoint path must start with '/'."
                )

            if not title.strip():
                raise ValueError(
                    "Test-case title is required."
                )

            if not expected_behavior.strip():
                raise ValueError(
                    "Expected behaviour is required."
                )

            if not ALLOWED_STATUS_VALUES.fullmatch(
                expected_status_codes.strip()
            ):
                raise ValueError(
                    "Expected status codes are invalid."
                )

            draft = {
                "endpoint_path": endpoint_path.strip(),
                "request_headers": json.dumps(
                    parsed_headers,
                    ensure_ascii=False,
                ),
                "request_query": json.dumps(
                    parsed_query,
                    ensure_ascii=False,
                ),
                "request_body": (
                    json.dumps(
                        parsed_body,
                        ensure_ascii=False,
                    )
                    if parsed_body is not None
                    else None
                ),
            }
            unresolved = approval_blockers(
                case_request_payload(draft)
            )
            method = str(case["http_method"]).upper()
            safe = method in SAFE_METHODS and not unresolved

        except (
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            editable_case = dict(case)
            editable_case.update(
                {
                    "title": title,
                    "description": description,
                    "case_type": case_type,
                    "endpoint_path": endpoint_path,
                    "request_headers": request_headers,
                    "request_query": request_query,
                    "request_body": request_body,
                    "expected_status_codes":
                        expected_status_codes,
                    "expected_behavior":
                        expected_behavior,
                    "is_enabled": bool(is_enabled),
                }
            )

            return edit_form(
                request,
                project,
                editable_case,
                str(exc),
            )

        db.execute(
            text(
                """
                UPDATE api_test_cases
                SET
                    title = :title,
                    description = :description,
                    case_type = :case_type,
                    endpoint_path = :endpoint_path,
                    request_headers = :request_headers,
                    request_query = :request_query,
                    request_body = :request_body,
                    expected_status_codes =
                        :expected_status_codes,
                    expected_behavior =
                        :expected_behavior,
                    is_enabled = :is_enabled,
                    safe_to_execute = :safe_to_execute,
                    requires_approval = :requires_approval,
                    updated_at = :updated_at
                WHERE id = :id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                """
            ),
            {
                "title": title.strip(),
                "description": description.strip(),
                "case_type": case_type,
                "endpoint_path": endpoint_path.strip(),
                "request_headers": json.dumps(
                    parsed_headers,
                    ensure_ascii=False,
                ),
                "request_query": json.dumps(
                    parsed_query,
                    ensure_ascii=False,
                ),
                "request_body": (
                    json.dumps(
                        parsed_body,
                        ensure_ascii=False,
                    )
                    if parsed_body is not None
                    else None
                ),
                "expected_status_codes":
                    expected_status_codes.strip(),
                "expected_behavior":
                    expected_behavior.strip(),
                "is_enabled": bool(is_enabled),
                "safe_to_execute": safe,
                "requires_approval": not safe,
                "updated_at": utc_now(),
                "id": case["id"],
                "project_id": project["id"],
                "owner_user_id": user.id,
            },
        )

        db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/test-cases"
        "?message=Reviewed+test+case+saved.",
        status_code=303,
    )
