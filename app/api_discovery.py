import csv
import io
import json
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, Form, Request
from fastapi.responses import (
    RedirectResponse,
    StreamingResponse,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.smart_data.compatibility import (
    AdapterCollection,
    ComparisonReport,
)
from app.smart_data.contracts import ProjectRef
from app.smart_data.persistence import PersistenceIsolationError, persist_contracts
from app.smart_data.serialization import UnsafeSecretError
from app.route_discovery import discover_normalized_routes

from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)

router = APIRouter()

PROJECT_ROOT = Path("/opt/qafox/data/projects")

MAX_FILES_SCANNED = 10_000
MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".venv",
    "venv",
    "env",
    "target",
    "bin",
    "obj",
}

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".php",
    ".cs",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".go",
    ".rb",
    ".kt",
}

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
}


def utc_now():
    return datetime.now(timezone.utc)


def normalize_endpoint_path(value: str) -> str:
    value = (value or "").strip()

    if not value:
        return "/"

    value = value.replace("\\", "/")
    value = re.sub(r"/+", "/", value)

    if not value.startswith("/"):
        value = "/" + value

    if len(value) > 1 and value.endswith("/"):
        value = value[:-1]

    return value


def confidence_label(score: int) -> str:
    if score >= 90:
        return "high"

    if score >= 65:
        return "medium"

    return "low"


def endpoint(
    method: str,
    path: str,
    framework: str,
    source_file: str = "",
    source_line: int | None = None,
    operation_id: str = "",
    summary: str = "",
    authentication: str = "Unknown",
    request_schema: str = "",
    response_codes: str = "",
    confidence_score: int = 70,
    warnings: list[str] | None = None,
):
    method = method.upper().strip()

    if method not in HTTP_METHODS:
        method = "ANY"

    return {
        "public_id": str(uuid.uuid4()),
        "http_method": method,
        "endpoint_path": normalize_endpoint_path(path),
        "framework": framework,
        "source_file": source_file,
        "source_line": source_line,
        "operation_id": operation_id,
        "summary": summary,
        "authentication": authentication or "Unknown",
        "request_schema": request_schema,
        "response_codes": response_codes,
        "confidence": confidence_label(
            confidence_score
        ),
        "confidence_score": confidence_score,
        "is_duplicate": False,
        "warnings": warnings or [],
    }


def line_number(content: str, position: int) -> int:
    return content.count("\n", 0, position) + 1


def safe_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def auth_from_openapi(operation: dict, document: dict) -> str:
    security = operation.get("security")

    if security is None:
        security = document.get("security")

    if security == []:
        return "Public"

    if not security:
        return "Not declared"

    schemes = []

    for item in security:
        if isinstance(item, dict):
            schemes.extend(item.keys())

    return ", ".join(sorted(set(schemes))) or "Protected"


def parse_openapi_document(
    document: dict,
    source_file: str,
) -> list[dict]:
    if not isinstance(document, dict):
        return []

    if not (
        "openapi" in document
        or "swagger" in document
        or "paths" in document
    ):
        return []

    results = []
    paths = document.get("paths", {})

    if not isinstance(paths, dict):
        return []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            upper_method = method.upper()

            if upper_method not in HTTP_METHODS:
                continue

            operation = (
                operation
                if isinstance(operation, dict)
                else {}
            )

            parameters = operation.get(
                "parameters",
                path_item.get("parameters", []),
            )

            request_body = operation.get("requestBody")
            schema_summary = {
                "parameters": parameters,
                "requestBody": request_body,
            }

            responses = operation.get("responses", {})

            warnings = []

            if not operation.get("summary"):
                warnings.append("Missing endpoint summary")

            if not responses:
                warnings.append("No responses documented")

            results.append(
                endpoint(
                    method=upper_method,
                    path=str(path),
                    framework="OpenAPI",
                    source_file=source_file,
                    operation_id=str(
                        operation.get("operationId", "")
                    ),
                    summary=str(
                        operation.get(
                            "summary",
                            operation.get("description", ""),
                        )
                    )[:500],
                    authentication=auth_from_openapi(
                        operation,
                        document,
                    ),
                    request_schema=safe_json(
                        schema_summary
                    ),
                    response_codes=", ".join(
                        str(code)
                        for code in responses.keys()
                    ),
                    confidence_score=98,
                    warnings=warnings,
                )
            )

    return results


def walk_postman_items(
    items: list,
    source_file: str,
    parent: str = "",
) -> list[dict]:
    results = []

    for item in items:
        if not isinstance(item, dict):
            continue

        item_name = str(item.get("name", "")).strip()
        full_name = (
            f"{parent} / {item_name}".strip(" /")
        )

        nested = item.get("item")

        if isinstance(nested, list):
            results.extend(
                walk_postman_items(
                    nested,
                    source_file,
                    full_name,
                )
            )
            continue

        request = item.get("request")

        if not isinstance(request, dict):
            continue

        method = str(
            request.get("method", "GET")
        ).upper()

        url = request.get("url", "")
        path = "/"

        if isinstance(url, dict):
            raw = str(url.get("raw", ""))
            path_parts = url.get("path")

            if isinstance(path_parts, list):
                path = "/" + "/".join(
                    str(part)
                    for part in path_parts
                )
            elif raw:
                path = re.sub(
                    r"^[a-zA-Z]+://[^/]+",
                    "",
                    raw,
                )
        else:
            raw = str(url)
            path = re.sub(
                r"^[a-zA-Z]+://[^/]+",
                "",
                raw,
            )

        path = path.split("?")[0] or "/"

        auth = request.get("auth")
        auth_type = "Not declared"

        if isinstance(auth, dict):
            auth_type = str(
                auth.get("type", "Protected")
            )

        body = request.get("body", {})

        results.append(
            endpoint(
                method=method,
                path=path,
                framework="Postman",
                source_file=source_file,
                summary=full_name,
                authentication=auth_type,
                request_schema=safe_json(body),
                confidence_score=96,
                warnings=(
                    []
                    if path != "/"
                    else ["Request URL could not be resolved"]
                ),
            )
        )

    return results


def parse_structured_file(
    file_path: Path,
    relative_path: str,
) -> list[dict]:
    try:
        content = file_path.read_text(
            encoding="utf-8",
        )

        if file_path.suffix.lower() == ".json":
            document = json.loads(content)
        else:
            document = yaml.safe_load(content)
    except Exception:
        return []

    if not isinstance(document, dict):
        return []

    openapi_results = parse_openapi_document(
        document,
        relative_path,
    )

    if openapi_results:
        return openapi_results

    if isinstance(document.get("item"), list):
        return walk_postman_items(
            document["item"],
            relative_path,
        )

    return []


def regex_results(
    content: str,
    relative_path: str,
    pattern: str,
    framework: str,
    method_group: int,
    path_group: int,
    confidence_score: int,
    flags: int = 0,
) -> list[dict]:
    results = []

    for match in re.finditer(
        pattern,
        content,
        flags,
    ):
        method = match.group(method_group)
        path = match.group(path_group)

        results.append(
            endpoint(
                method=method,
                path=path,
                framework=framework,
                source_file=relative_path,
                source_line=line_number(
                    content,
                    match.start(),
                ),
                confidence_score=confidence_score,
                warnings=[
                    "Authentication not determined by static pattern"
                ],
            )
        )

    return results


def parse_source_file(
    file_path: Path,
    relative_path: str,
) -> list[dict]:
    try:
        content = file_path.read_text(
            encoding="utf-8",
        )
    except (UnicodeDecodeError, OSError):
        return []

    suffix = file_path.suffix.lower()
    results = []

    if suffix == ".py":
        # FastAPI / Flask method decorators
        results.extend(
            regex_results(
                content,
                relative_path,
                r'@\w+\.(get|post|put|patch|delete|head|options)'
                r'\s*\(\s*["\']([^"\']+)["\']',
                "FastAPI/Flask",
                1,
                2,
                92,
                re.IGNORECASE,
            )
        )

        # Flask route with explicit methods
        for match in re.finditer(
            r'@\w+\.route\s*\(\s*["\']([^"\']+)["\']'
            r'[\s\S]{0,300}?methods\s*=\s*\[([^\]]+)\]',
            content,
            re.IGNORECASE,
        ):
            methods = re.findall(
                r'["\']([A-Za-z]+)["\']',
                match.group(2),
            )

            for method in methods or ["ANY"]:
                results.append(
                    endpoint(
                        method,
                        match.group(1),
                        "Flask",
                        relative_path,
                        line_number(
                            content,
                            match.start(),
                        ),
                        confidence_score=90,
                    )
                )

        # Django path / re_path
        for match in re.finditer(
            r'\b(?:path|re_path)\s*\(\s*'
            r'["\']([^"\']+)["\']',
            content,
        ):
            results.append(
                endpoint(
                    "ANY",
                    match.group(1),
                    "Django",
                    relative_path,
                    line_number(
                        content,
                        match.start(),
                    ),
                    confidence_score=66,
                    warnings=[
                        "HTTP method requires view analysis"
                    ],
                )
            )

    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        # Express and common Node routers
        results.extend(
            regex_results(
                content,
                relative_path,
                r'\b(?:app|router|server|api)'
                r'\.(get|post|put|patch|delete|head|options)'
                r'\s*\(\s*["\'`]([^"\'`]+)["\'`]',
                "Express.js",
                1,
                2,
                91,
                re.IGNORECASE,
            )
        )

        # NestJS decorators
        results.extend(
            regex_results(
                content,
                relative_path,
                r'@(Get|Post|Put|Patch|Delete|Head|Options)'
                r'\s*\(\s*["\'`]([^"\'`]*)["\'`]\s*\)',
                "NestJS",
                1,
                2,
                86,
                re.IGNORECASE,
            )
        )

        # Next.js route handlers
        if (
            "/app/api/" in "/" + relative_path.replace("\\", "/")
            or "/pages/api/" in "/" + relative_path.replace("\\", "/")
        ):
            route_match = re.search(
                r'export\s+(?:async\s+)?function\s+'
                r'(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b',
                content,
            )

            if route_match:
                parts = Path(relative_path).parts

                try:
                    api_index = parts.index("api")
                    route_parts = list(
                        parts[api_index + 1:-1]
                    )
                    route_path = "/api/" + "/".join(
                        route_parts
                    )
                except ValueError:
                    route_path = "/api"

                results.append(
                    endpoint(
                        route_match.group(1),
                        route_path,
                        "Next.js",
                        relative_path,
                        line_number(
                            content,
                            route_match.start(),
                        ),
                        confidence_score=88,
                    )
                )

    if suffix in {".java", ".kt"}:
        annotation_methods = {
            "Get": "GET",
            "Post": "POST",
            "Put": "PUT",
            "Patch": "PATCH",
            "Delete": "DELETE",
        }

        for match in re.finditer(
            r'@(Get|Post|Put|Patch|Delete)Mapping'
            r'\s*\(\s*(?:value\s*=\s*)?'
            r'["\']([^"\']*)["\']',
            content,
        ):
            results.append(
                endpoint(
                    annotation_methods[match.group(1)],
                    match.group(2),
                    "Spring Boot",
                    relative_path,
                    line_number(
                        content,
                        match.start(),
                    ),
                    confidence_score=88,
                )
            )

        for match in re.finditer(
            r'@RequestMapping\s*\(\s*'
            r'(?:value\s*=\s*)?["\']([^"\']+)["\']'
            r'[\s\S]{0,250}?RequestMethod\.(GET|POST|PUT|PATCH|DELETE)',
            content,
        ):
            results.append(
                endpoint(
                    match.group(2),
                    match.group(1),
                    "Spring Boot",
                    relative_path,
                    line_number(
                        content,
                        match.start(),
                    ),
                    confidence_score=87,
                )
            )

    if suffix == ".php":
        results.extend(
            regex_results(
                content,
                relative_path,
                r'Route::(get|post|put|patch|delete|options)'
                r'\s*\(\s*["\']([^"\']+)["\']',
                "Laravel",
                1,
                2,
                91,
                re.IGNORECASE,
            )
        )

    if suffix == ".cs":
        for match in re.finditer(
            r'\[Http(Get|Post|Put|Patch|Delete)'
            r'(?:\s*\(\s*["\']([^"\']*)["\']\s*\))?\]',
            content,
            re.IGNORECASE,
        ):
            results.append(
                endpoint(
                    match.group(1),
                    match.group(2) or "/",
                    "ASP.NET Core",
                    relative_path,
                    line_number(
                        content,
                        match.start(),
                    ),
                    confidence_score=83,
                    warnings=[
                        "Controller route prefix may require combination"
                    ],
                )
            )

    return results



def join_route_prefix(
    prefix: str,
    endpoint_path: str,
) -> str:
    prefix = normalize_endpoint_path(
        prefix
    )

    endpoint_path = normalize_endpoint_path(
        endpoint_path
    )

    if prefix == "/":
        prefix = ""

    if endpoint_path == "/":
        endpoint_path = ""

    combined = (
        f"{prefix}/{endpoint_path.lstrip('/')}"
    )

    return normalize_endpoint_path(
        combined or "/"
    )


def python_router_prefix(content: str) -> str:
    patterns = [
        r'APIRouter\s*\([\s\S]{0,600}?'
        r'prefix\s*=\s*["\']([^"\']+)["\']',

        r'Blueprint\s*\([\s\S]{0,600}?'
        r'url_prefix\s*=\s*["\']([^"\']+)["\']',
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            content,
            re.IGNORECASE,
        )

        if match:
            return normalize_endpoint_path(
                match.group(1)
            )

    return ""


def route_function_block(
    content: str,
    source_line: int | None,
) -> str:
    if not source_line:
        return ""

    lines = content.splitlines()
    start = max(0, source_line - 1)
    selected = []

    for line in lines[start:start + 180]:
        if (
            selected
            and re.match(
                r"\s*@(?:app|router|bp|blueprint)\.",
                line,
            )
        ):
            break

        selected.append(line)

    return "\n".join(selected)


def form_field_evidence(
    content: str,
    block: str,
) -> list[dict]:
    haystack = block or content
    fields = []

    form_parameters = re.finditer(
        r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'
        r'([^=\n,]+?)\s*=\s*Form\s*\('
        r'\s*(\.\.\.|[^,\)]*)',
        haystack,
    )

    for match in form_parameters:
        fields.append(
            {
                "name": match.group(1),
                "type": match.group(2).strip(),
                "required": (
                    match.group(3).strip()
                    == "..."
                ),
                "source": "FastAPI Form parameter",
            }
        )

    for match in re.finditer(
        r'form\.get\(\s*["\']'
        r'([A-Za-z_][A-Za-z0-9_]*)'
        r'["\']\s*\)',
        haystack,
    ):
        name = match.group(1)

        if not any(
            item["name"] == name
            for item in fields
        ):
            fields.append(
                {
                    "name": name,
                    "type": "form-field",
                    "required": bool(
                        re.search(
                            rf"if\s+not\s+{re.escape(name)}\b",
                            haystack,
                        )
                    ),
                    "source": "request.form() access",
                }
            )

    return fields


def query_parameter_evidence(
    block: str,
) -> list[dict]:
    fields = []

    function_match = re.search(
        r'def\s+\w+\s*\(([\s\S]{0,2500}?)\)\s*(?:->[^:]*)?:',
        block,
    )

    if not function_match:
        return fields

    parameters = function_match.group(1)

    for match in re.finditer(
        r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'
        r'([^=,\n]+)'
        r'(?:\s*=\s*([^,\n]+))?',
        parameters,
    ):
        name = match.group(1)

        if name in {
            "request",
            "db",
            "self",
        }:
            continue

        value_type = match.group(2).strip()
        default = (
            match.group(3).strip()
            if match.group(3)
            else None
        )

        fields.append(
            {
                "name": name,
                "type": value_type,
                "required": default is None,
                "default": default,
                "source": "route function signature",
            }
        )

    return fields


def apply_python_source_intelligence(
    file_path: Path,
    discovered: list[dict],
) -> list[dict]:
    if file_path.suffix.lower() != ".py":
        return discovered

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return discovered

    prefix = python_router_prefix(
        content
    )

    for item in discovered:
        item["original_endpoint_path"] = (
            item["endpoint_path"]
        )

        if prefix:
            item["endpoint_path"] = (
                join_route_prefix(
                    prefix,
                    item["endpoint_path"],
                )
            )

            item["route_prefix"] = prefix
            item["confidence_score"] = min(
                99,
                int(
                    item.get(
                        "confidence_score",
                        70,
                    )
                ) + 5,
            )

            item["confidence"] = (
                confidence_label(
                    item["confidence_score"]
                )
            )
        else:
            item["route_prefix"] = ""

        block = route_function_block(
            content,
            item.get("source_line"),
        )

        form_fields = form_field_evidence(
            content,
            block,
        )

        query_fields = query_parameter_evidence(
            block
        )

        if (
            item["http_method"]
            in {"POST", "PUT", "PATCH"}
            and not form_fields
            and (
                "/create" in item["endpoint_path"]
                or "/edit" in item["endpoint_path"]
            )
        ):
            form_fields = form_field_evidence(
                content,
                content,
            )

        evidence = {
            "route_prefix": prefix,
            "form_fields": form_fields,
            "query_or_path_fields": query_fields,
            "authentication_evidence": [],
        }

        if (
            "require_admin(request)" in block
            or "get_current_admin(" in block
        ):
            item["authentication"] = (
                "Session authentication"
            )

            evidence[
                "authentication_evidence"
            ].append(
                "Route verifies an authenticated admin session."
            )

        item["input_evidence"] = safe_json(
            evidence
        )

        item["smart_data_schema"] = safe_json(
            {
                "content_type": (
                    "application/x-www-form-urlencoded"
                    if form_fields
                    else None
                ),
                "fields": (
                    form_fields
                    if form_fields
                    else query_fields
                ),
            }
        )

        if prefix:
            item["warnings"] = [
                warning
                for warning in item["warnings"]
                if warning
                != "Authentication is not explicitly documented"
            ]

    return discovered

def discover_source(source_root: Path):
    endpoints = []
    files_scanned = 0
    files_skipped = 0
    frameworks = Counter()

    for file_path in source_root.rglob("*"):
        if not file_path.is_file():
            continue

        relative_parts = file_path.relative_to(
            source_root
        ).parts

        if any(
            part in SKIP_DIRECTORIES
            for part in relative_parts
        ):
            files_skipped += 1
            continue

        if file_path.suffix.lower() not in TEXT_SUFFIXES:
            files_skipped += 1
            continue

        try:
            size = file_path.stat().st_size
        except OSError:
            files_skipped += 1
            continue

        if size > MAX_TEXT_FILE_BYTES:
            files_skipped += 1
            continue

        if files_scanned >= MAX_FILES_SCANNED:
            files_skipped += 1
            continue

        files_scanned += 1
        relative_path = str(
            file_path.relative_to(source_root)
        )

        structured = []

        if file_path.suffix.lower() in {
            ".json",
            ".yaml",
            ".yml",
        }:
            structured = parse_structured_file(
                file_path,
                relative_path,
            )

        discovered = (
            structured
            if structured
            else parse_source_file(
                file_path,
                relative_path,
            )
        )

        discovered = apply_python_source_intelligence(
            file_path,
            discovered,
        )

        for item in discovered:
            frameworks[item["framework"]] += 1

        endpoints.extend(discovered)

    duplicate_keys = Counter(
        (
            item["http_method"],
            item["endpoint_path"],
        )
        for item in endpoints
    )

    for item in endpoints:
        key = (
            item["http_method"],
            item["endpoint_path"],
        )

        if duplicate_keys[key] > 1:
            item["is_duplicate"] = True
            item["warnings"].append(
                "Duplicate method and endpoint path"
            )

        if item["authentication"] in {
            "Unknown",
            "Not declared",
        }:
            item["warnings"].append(
                "Authentication is not explicitly documented"
            )

    return {
        "endpoints": endpoints,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "frameworks": frameworks,
    }


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


def latest_run(
    db: Session,
    owner_user_id: int,
    project_id: int,
    *,
    status: str | None = None,
):
    conditions = [
        "project_id = :project_id",
        "owner_user_id = :owner_user_id",
    ]
    parameters = {
        "project_id": project_id,
        "owner_user_id": owner_user_id,
    }
    if status:
        conditions.append("status = :status")
        parameters["status"] = status
    return (
        db.execute(
            text(
                f"""
                SELECT *
                FROM api_discovery_runs
                WHERE {' AND '.join(conditions)}
                ORDER BY started_at DESC
                LIMIT 1
                """
            ),
            parameters,
        )
        .mappings()
        .first()
    )


def inventory_display_run(
    db: Session,
    owner_user_id: int,
    project_id: int,
):
    latest = latest_run(db, owner_user_id, project_id)
    if latest and str(latest["status"]) == "failed":
        completed = latest_run(
            db,
            owner_user_id,
            project_id,
            status="completed",
        )
        if completed:
            return latest, completed
    return latest, latest


@router.post("/projects/{public_id}/api-discovery")
def run_api_discovery(
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
            f"/projects/{public_id}",
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

        project_root = Path(
            project["storage_directory"]
        ).resolve()

        expected_root = (
            PROJECT_ROOT / str(user.id)
        ).resolve()

        try:
            project_root.relative_to(expected_root)
        except ValueError:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        source_root = project_root / "source"

        if not source_root.is_dir():
            return RedirectResponse(
                f"/projects/{public_id}",
                status_code=303,
            )

        run_public_id = str(uuid.uuid4())
        started_at = utc_now()

        run_id = db.execute(
            text(
                """
                INSERT INTO api_discovery_runs (
                    public_id,
                    project_id,
                    owner_user_id,
                    status,
                    started_at
                )
                VALUES (
                    :public_id,
                    :project_id,
                    :owner_user_id,
                    'running',
                    :started_at
                )
                RETURNING id
                """
            ),
            {
                "public_id": run_public_id,
                "project_id": project["id"],
                "owner_user_id": user.id,
                "started_at": started_at,
            },
        ).scalar_one()

        db.commit()

        try:
            discovery = discover_source(source_root)
            project_ref = ProjectRef(
                source_root,
                owner_user_id=user.id,
                project_public_id=public_id,
            )
            try:
                route_report = discover_normalized_routes(
                    project_ref,
                    discovery["endpoints"],
                )
                endpoints = list(route_report.inventory)
                comparison = route_report.comparison
                routes_to_persist = route_report.routes
                fixtures_to_persist = route_report.fixtures
                adapter_names = route_report.adapter_names
            except Exception:
                adapter_collection = AdapterCollection()
                endpoints = list(discovery["endpoints"])
                comparison = ComparisonReport(
                    legacy_only=len(endpoints),
                )
                routes_to_persist = ()
                fixtures_to_persist = ()
                adapter_names = ()
            frameworks = Counter(
                item["framework"]
                for item in endpoints
            )

            for item in endpoints:
                db.execute(
                    text(
                        """
                        INSERT INTO api_inventory (
                            public_id,
                            discovery_run_id,
                            project_id,
                            owner_user_id,
                            http_method,
                            endpoint_path,
                            framework,
                            source_file,
                            source_line,
                            operation_id,
                            summary,
                            authentication,
                            request_schema,
                            response_codes,
                            confidence,
                            confidence_score,
                            is_duplicate,
                            warnings,
                            route_prefix,
                            input_evidence,
                            smart_data_schema,
                            created_at
                        )
                        VALUES (
                            :public_id,
                            :discovery_run_id,
                            :project_id,
                            :owner_user_id,
                            :http_method,
                            :endpoint_path,
                            :framework,
                            :source_file,
                            :source_line,
                            :operation_id,
                            :summary,
                            :authentication,
                            :request_schema,
                            :response_codes,
                            :confidence,
                            :confidence_score,
                            :is_duplicate,
                            :warnings,
                            :route_prefix,
                            :input_evidence,
                            :smart_data_schema,
                            :created_at
                        )
                        """
                    ),
                    {
                        "public_id": item["public_id"],
                        "http_method": item["http_method"],
                        "endpoint_path": item["endpoint_path"],
                        "framework": item["framework"],
                        "source_file": item.get("source_file", ""),
                        "source_line": item.get("source_line"),
                        "operation_id": item.get("operation_id", ""),
                        "summary": item.get("summary", ""),
                        "authentication": item.get(
                            "authentication",
                            "Unknown",
                        ),
                        "request_schema": item.get(
                            "request_schema",
                            "",
                        ),
                        "response_codes": item.get(
                            "response_codes",
                            "",
                        ),
                        "confidence": item["confidence"],
                        "confidence_score": item[
                            "confidence_score"
                        ],
                        "is_duplicate": item.get(
                            "is_duplicate",
                            False,
                        ),
                        "discovery_run_id": run_id,
                        "project_id": project["id"],
                        "owner_user_id": user.id,
                        "warnings": json.dumps(
                            item.get("warnings") or []
                        ),
                        "route_prefix": item.get(
                            "route_prefix",
                            "",
                        ),
                        "input_evidence": item.get(
                            "input_evidence",
                            "{}",
                        ),
                        "smart_data_schema": item.get(
                            "smart_data_schema",
                            "{}",
                        ),
                        "created_at": utc_now(),
                    },
                )

            persist_note = ""
            try:
                with db.begin_nested():
                    persist_contracts(
                        db,
                        owner_user_id=user.id,
                        project_id=project["id"],
                        discovery_run_id=int(run_id),
                        routes=routes_to_persist,
                        fixtures=fixtures_to_persist,
                        adapter_names=adapter_names,
                    )
            except (
                SQLAlchemyError,
                UnsafeSecretError,
                PersistenceIsolationError,
                ValueError,
            ):
                persist_note = (
                    " Adapter contracts were not persisted; "
                    "legacy inventory was still saved."
                )

            duplicate_count = sum(
                1
                for item in endpoints
                if item["is_duplicate"]
            )

            warning_count = sum(
                len(item["warnings"])
                for item in endpoints
            )

            framework_summary = ", ".join(
                f"{name}: {count}"
                for name, count in frameworks.most_common()
            ) or "No supported framework detected"
            framework_summary = (
                f"{framework_summary}. {comparison.summary()}{persist_note}"
            )

            completed_at = utc_now()

            db.execute(
                text(
                    """
                    UPDATE api_discovery_runs
                    SET
                        status = 'completed',
                        framework_summary = :framework_summary,
                        files_scanned = :files_scanned,
                        files_skipped = :files_skipped,
                        endpoints_discovered = :endpoint_count,
                        duplicate_count = :duplicate_count,
                        warning_count = :warning_count,
                        completed_at = :completed_at
                    WHERE id = :run_id
                      AND owner_user_id = :owner_user_id
                    """
                ),
                {
                    "framework_summary": framework_summary,
                    "files_scanned": discovery["files_scanned"],
                    "files_skipped": discovery["files_skipped"],
                    "endpoint_count": len(endpoints),
                    "duplicate_count": duplicate_count,
                    "warning_count": warning_count,
                    "completed_at": completed_at,
                    "run_id": run_id,
                    "owner_user_id": user.id,
                },
            )

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
                        'api-discovery-completed',
                        :summary,
                        :created_at
                    )
                    """
                ),
                {
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                    "summary": (
                        f"API discovery completed: "
                        f"{len(endpoints)} endpoints found. "
                        f"{comparison.summary()}."
                    ),
                    "created_at": completed_at,
                },
            )

            db.commit()

        except Exception as exc:
            db.rollback()

            db.execute(
                text(
                    """
                    UPDATE api_discovery_runs
                    SET
                        status = 'failed',
                        error_message = :error_message,
                        completed_at = :completed_at
                    WHERE id = :run_id
                      AND owner_user_id = :owner_user_id
                    """
                ),
                {
                    "error_message": (
                        "Discovery could not be completed "
                        f"({type(exc).__name__})."
                    ),
                    "completed_at": utc_now(),
                    "run_id": run_id,
                    "owner_user_id": user.id,
                },
            )
            db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/api-inventory",
        status_code=303,
    )


@router.get("/projects/{public_id}/api-inventory")
def api_inventory_page(
    request: Request,
    public_id: str,
    method: str = "",
    confidence: str = "",
    q: str = "",
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

        attempt, run = inventory_display_run(
            db,
            user.id,
            project["id"],
        )

        if not run:
            return RedirectResponse(
                f"/projects/{public_id}",
                status_code=303,
            )

        conditions = [
            "discovery_run_id = :run_id",
            "owner_user_id = :owner_user_id",
        ]

        parameters = {
            "run_id": run["id"],
            "owner_user_id": user.id,
        }

        if method.upper() in HTTP_METHODS:
            conditions.append(
                "http_method = :http_method"
            )
            parameters["http_method"] = method.upper()

        if confidence in {"high", "medium", "low"}:
            conditions.append(
                "confidence = :confidence"
            )
            parameters["confidence"] = confidence

        if q.strip():
            conditions.append(
                """
                (
                    endpoint_path ILIKE :search
                    OR summary ILIKE :search
                    OR source_file ILIKE :search
                )
                """
            )
            parameters["search"] = f"%{q.strip()}%"

        inventory = (
            db.execute(
                text(
                    f"""
                    SELECT *
                    FROM api_inventory
                    WHERE {' AND '.join(conditions)}
                    ORDER BY
                        endpoint_path,
                        http_method,
                        source_file
                    """
                ),
                parameters,
            )
            .mappings()
            .all()
        )

    rows = ""

    for item in inventory:
        warnings = []

        try:
            warnings = json.loads(
                item["warnings"] or "[]"
            )
        except Exception:
            pass

        warning_html = (
            "".join(
                f"<li>{esc(warning)}</li>"
                for warning in warnings
            )
            if warnings
            else "<li>No static-analysis warnings</li>"
        )

        method_class = item["http_method"].lower()
        endpoint_id = f'endpoint-{item["public_id"]}'

        rows += f"""
        <tr>
            <td>
                <span class="http-method {esc(method_class)}">
                    {esc(item["http_method"])}
                </span>
            </td>
            <td>
                <div class="inventory-endpoint">
                    <code id="{esc(endpoint_id)}">
                        {esc(item["endpoint_path"])}
                    </code>
                    <button type="button"
                            class="copy-code-button"
                            data-copy-target="#{esc(endpoint_id)}">
                        ⧉ Copy
                    </button>
                </div>
            </td>
            <td>
                <strong>{esc(item["framework"])}</strong>
                <small>{esc(item["summary"] or "No summary")}</small>
            </td>
            <td>
                <span class="auth-badge">
                    {esc(item["authentication"])}
                </span>
            </td>
            <td>
                <span class="confidence {esc(item["confidence"])}">
                    {esc(item["confidence"].title())}
                    · {esc(str(item["confidence_score"]))}%
                </span>
            </td>
            <td>
                <span class="source-reference">
                    {esc(item["source_file"] or "Document")}
                    {
                        ":" + esc(str(item["source_line"]))
                        if item["source_line"]
                        else ""
                    }
                </span>
            </td>
            <td>
                <details class="inventory-warnings">
                    <summary>
                        {len(warnings)} warning(s)
                    </summary>
                    <ul>{warning_html}</ul>
                </details>
            </td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="7" class="inventory-empty">
                No APIs match the selected filters.
            </td>
        </tr>
        """

    csrf = csrf_token(request)
    failed_notice = ""
    if attempt is not None and str(attempt["status"]) == "failed":
        failed_notice = f"""
        <div class="case-notice error">
            The latest discovery attempt did not finish
            ({esc(attempt["error_message"] or "unknown error")}).
            Showing the last completed inventory. Run again after the fix.
        </div>
        """

    content = f"""
<section class="inventory-shell">
    <div class="inventory-heading">
        <div>
            <a href="/projects/{esc(public_id)}">
                ← {esc(project["name"])}
            </a>
            <span>API DISCOVERY</span>
            <h1>API inventory</h1>
            {failed_notice}
            <p>{esc(run["framework_summary"] or "")}</p>
        </div>

        <div class="inventory-actions">
            <a class="outline-dark-button"
               href="/projects/{esc(public_id)}/smart-data">
                Review smart data
            </a>
            <a class="outline-dark-button"
               href="/projects/{esc(public_id)}/api-inventory.json">
                Download JSON
            </a>
            <a class="outline-dark-button"
               href="/projects/{esc(public_id)}/api-inventory.csv">
                Download CSV
            </a>
            <form method="post"
                  action="/projects/{esc(public_id)}/api-discovery">
                <input type="hidden"
                       name="csrf"
                       value="{esc(csrf)}">
                <button class="primary-button"
                        type="submit">
                    Run again
                </button>
            </form>
        </div>
    </div>

    <div class="inventory-stats">
        <article>
            <strong>{esc(str(run["endpoints_discovered"]))}</strong>
            <span>APIs discovered</span>
        </article>
        <article>
            <strong>{esc(str(run["files_scanned"]))}</strong>
            <span>Files scanned</span>
        </article>
        <article>
            <strong>{esc(str(run["duplicate_count"]))}</strong>
            <span>Duplicates</span>
        </article>
        <article>
            <strong>{esc(str(run["warning_count"]))}</strong>
            <span>Warnings</span>
        </article>
    </div>

    <form class="inventory-filters"
          method="get">

        <input name="q"
               value="{esc(q)}"
               placeholder="Search path, summary or source file">

        <select name="method">
            <option value="">All methods</option>
            {
                "".join(
                    f'<option value="{item}"'
                    + (
                        " selected"
                        if method.upper() == item
                        else ""
                    )
                    + f'>{item}</option>'
                    for item in sorted(HTTP_METHODS)
                )
            }
        </select>

        <select name="confidence">
            <option value="">All confidence</option>
            <option value="high"
                {"selected" if confidence == "high" else ""}>
                High
            </option>
            <option value="medium"
                {"selected" if confidence == "medium" else ""}>
                Medium
            </option>
            <option value="low"
                {"selected" if confidence == "low" else ""}>
                Low
            </option>
        </select>

        <button type="submit">
            Apply filters
        </button>
    </form>

    <div class="inventory-table-wrap">
        <table class="inventory-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Endpoint</th>
                    <th>Framework</th>
                    <th>Authentication</th>
                    <th>Confidence</th>
                    <th>Source</th>
                    <th>Audit</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <div class="static-analysis-note">
        <strong>Static-analysis notice</strong>
        <p>
            QAFox did not execute uploaded application code.
            Dynamic routes, runtime prefixes and generated APIs
            may require confirmation before testing.
        </p>
    </div>
</section>
"""

    return layout(
        "API inventory",
        content,
        request,
        public=False,
    )


def inventory_export_data(
    user_id: int,
    public_id: str,
):
    with Session(engine) as db:
        project = owned_project(
            db,
            user_id,
            public_id,
        )

        if not project:
            return None, []

        run = inventory_display_run(
            db,
            user_id,
            project["id"],
        )[1]

        if not run:
            return project, []

        inventory = (
            db.execute(
                text(
                    """
                    SELECT
                        public_id,
                        http_method,
                        endpoint_path,
                        framework,
                        source_file,
                        source_line,
                        operation_id,
                        summary,
                        authentication,
                        request_schema,
                        response_codes,
                        confidence,
                        confidence_score,
                        is_duplicate,
                        warnings
                    FROM api_inventory
                    WHERE discovery_run_id = :run_id
                      AND owner_user_id = :owner_user_id
                    ORDER BY endpoint_path, http_method
                    """
                ),
                {
                    "run_id": run["id"],
                    "owner_user_id": user_id,
                },
            )
            .mappings()
            .all()
        )

    return project, [
        dict(item)
        for item in inventory
    ]


@router.get("/projects/{public_id}/api-inventory.json")
def download_inventory_json(
    request: Request,
    public_id: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    project, inventory = inventory_export_data(
        user.id,
        public_id,
    )

    if not project:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    payload = {
        "product": "QAFox",
        "project": project["name"],
        "generated_at": utc_now().isoformat(),
        "endpoint_count": len(inventory),
        "inventory": inventory,
    }

    data = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        default=str,
    ).encode("utf-8")

    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="'
                f'qafox-{public_id}-api-inventory.json"'
            ),
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/projects/{public_id}/api-inventory.csv")
def download_inventory_csv(
    request: Request,
    public_id: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    project, inventory = inventory_export_data(
        user.id,
        public_id,
    )

    if not project:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    output = io.StringIO()
    fieldnames = [
        "http_method",
        "endpoint_path",
        "framework",
        "source_file",
        "source_line",
        "operation_id",
        "summary",
        "authentication",
        "response_codes",
        "confidence",
        "confidence_score",
        "is_duplicate",
        "warnings",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )
    writer.writeheader()

    for item in inventory:
        writer.writerow(item)

    data = output.getvalue().encode(
        "utf-8-sig"
    )

    return StreamingResponse(
        io.BytesIO(data),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="'
                f'qafox-{public_id}-api-inventory.csv"'
            ),
            "Cache-Control": "private, no-store",
        },
    )
