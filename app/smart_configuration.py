import http.client
import ipaddress
import json
import re
import socket
import ssl
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.main import (
    csrf_valid,
    current_user,
    engine,
)

router = APIRouter()

PROJECT_ROOT = Path("/opt/qafox/data/projects")

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
}

STRUCTURED_SUFFIXES = {
    ".json",
    ".yaml",
    ".yml",
}

RESERVED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}

COMMON_NON_PREFIXES = {
    "health",
    "login",
    "logout",
    "signup",
    "register",
    "create",
    "docs",
    "redoc",
    "openapi.json",
    "status",
    "metrics",
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


def public_addresses(hostname: str, port: int) -> list[str]:
    hostname = hostname.lower().rstrip(".")

    if (
        hostname in RESERVED_HOSTNAMES
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise ValueError("Internal targets are blocked.")

    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            "Hostname could not be resolved."
        ) from exc

    addresses = sorted(
        {
            result[4][0]
            for result in results
            if result and result[4]
        }
    )

    if not addresses:
        raise ValueError(
            "Hostname did not resolve to an address."
        )

    for address in addresses:
        parsed = ipaddress.ip_address(address)

        if not (
            parsed.is_global
            and not parsed.is_private
            and not parsed.is_loopback
            and not parsed.is_link_local
            and not parsed.is_multicast
            and not parsed.is_reserved
            and not parsed.is_unspecified
        ):
            raise ValueError(
                "Private, loopback and reserved targets are blocked."
            )

    return addresses


def normalize_public_https_url(value: str) -> str:
    value = str(value or "").strip()

    if len(value) > 2048:
        raise ValueError("URL is too long.")

    parsed = urlsplit(value)

    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are allowed.")

    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("Enter a valid public HTTPS URL.")

    port = parsed.port or 443

    if port < 1 or port > 65535:
        raise ValueError("Invalid HTTPS port.")

    public_addresses(parsed.hostname, port)

    path = re.sub(r"/+", "/", parsed.path or "/")

    if path != "/":
        path = path.rstrip("/")

    return urlunsplit(
        (
            "https",
            parsed.netloc.lower(),
            path,
            "",
            "",
        )
    )


def normalize_prefix(value: str) -> str:
    value = str(value or "").strip()

    if not value or value == "/":
        return ""

    value = re.sub(r"/+", "/", value)

    if not value.startswith("/"):
        value = "/" + value

    return value.rstrip("/")


def infer_prefix(paths: list[str]) -> tuple[str, int, str]:
    cleaned = []

    for path in paths:
        path = str(path or "").split("?")[0].strip()

        if not path.startswith("/"):
            continue

        segments = [
            segment
            for segment in path.split("/")
            if segment
            and not segment.startswith("{")
            and not segment.startswith(":")
        ]

        if segments:
            cleaned.append(segments)

    if not cleaned:
        return "", 35, "No common API prefix was detected."

    first_segments = Counter(
        parts[0]
        for parts in cleaned
    )

    candidate, count = first_segments.most_common(1)[0]
    coverage = count / len(cleaned)

    if (
        candidate.lower() in COMMON_NON_PREFIXES
        or coverage < 0.60
    ):
        return (
            "",
            max(40, round(coverage * 100)),
            "Endpoints do not share a reliable API prefix.",
        )

    prefix = "/" + candidate
    confidence = min(96, max(60, round(coverage * 100)))

    second_segments = Counter(
        parts[1]
        for parts in cleaned
        if len(parts) > 1
        and parts[0] == candidate
    )

    if second_segments:
        second, second_count = second_segments.most_common(1)[0]
        second_coverage = second_count / count

        if (
            second_coverage >= 0.80
            and re.fullmatch(
                r"v[0-9]+(?:\.[0-9]+)?",
                second,
                re.IGNORECASE,
            )
        ):
            prefix += "/" + second
            confidence = min(
                98,
                round(second_coverage * 100),
            )

    return (
        prefix,
        confidence,
        (
            f"{count} of {len(cleaned)} discovered endpoint paths "
            f"support this prefix."
        ),
    )


def add_url_candidate(
    candidates: list[dict],
    seen: set[str],
    value,
    source: str,
    confidence: int,
):
    value = str(value or "").strip()

    if not value:
        return

    value = value.replace(
        "{{baseUrl}}",
        "",
    ).replace(
        "{{base_url}}",
        "",
    )

    if not value.startswith("https://"):
        return

    try:
        parsed = urlsplit(value)
    except ValueError:
        return

    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return

    normalized = urlunsplit(
        (
            "https",
            parsed.netloc.lower(),
            re.sub(
                r"/+",
                "/",
                parsed.path or "/",
            ).rstrip("/") or "",
            "",
            "",
        )
    )

    if normalized in seen:
        return

    seen.add(normalized)

    candidates.append(
        {
            "url": normalized,
            "source": source,
            "confidence": confidence,
        }
    )


def inspect_structured_documents(
    source_root: Path,
) -> tuple[list[dict], list[dict], list[str]]:
    server_candidates = []
    auth_evidence = []
    header_names = []
    seen_urls = set()
    scanned = 0

    for file_path in source_root.rglob("*"):
        if scanned >= 500:
            break

        if not file_path.is_file():
            continue

        relative = file_path.relative_to(source_root)

        if any(
            part in SKIP_DIRECTORIES
            for part in relative.parts
        ):
            continue

        if file_path.suffix.lower() not in STRUCTURED_SUFFIXES:
            continue

        try:
            if file_path.stat().st_size > 2 * 1024 * 1024:
                continue

            content = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )

            document = (
                json.loads(content)
                if file_path.suffix.lower() == ".json"
                else yaml.safe_load(content)
            )
        except Exception:
            continue

        scanned += 1

        if not isinstance(document, dict):
            continue

        source = str(relative)

        if (
            "openapi" in document
            or "swagger" in document
            or "paths" in document
        ):
            servers = document.get("servers", [])

            if isinstance(servers, list):
                for server in servers:
                    if isinstance(server, dict):
                        add_url_candidate(
                            server_candidates,
                            seen_urls,
                            server.get("url"),
                            f"OpenAPI servers: {source}",
                            98,
                        )

            host = document.get("host")
            base_path = str(
                document.get("basePath", "")
            )

            if host:
                schemes = document.get(
                    "schemes",
                    ["https"],
                )

                if "https" in schemes:
                    add_url_candidate(
                        server_candidates,
                        seen_urls,
                        f"https://{host}{base_path}",
                        f"Swagger host/basePath: {source}",
                        96,
                    )

            components = document.get(
                "components",
                {},
            )

            schemes = {}

            if isinstance(components, dict):
                schemes = components.get(
                    "securitySchemes",
                    {},
                )

            if not schemes:
                schemes = document.get(
                    "securityDefinitions",
                    {},
                )

            if isinstance(schemes, dict):
                for name, scheme in schemes.items():
                    if not isinstance(scheme, dict):
                        continue

                    scheme_type = str(
                        scheme.get("type", "")
                    ).lower()

                    http_scheme = str(
                        scheme.get("scheme", "")
                    ).lower()

                    location = str(
                        scheme.get("in", "")
                    ).lower()

                    header_name = str(
                        scheme.get("name", "")
                    ).strip()

                    detected = "none"

                    if (
                        scheme_type == "http"
                        and http_scheme == "bearer"
                    ):
                        detected = "bearer"
                    elif (
                        scheme_type == "http"
                        and http_scheme == "basic"
                    ):
                        detected = "basic"
                    elif (
                        scheme_type == "apikey"
                        and location == "header"
                    ):
                        detected = "api_key"

                        if header_name:
                            header_names.append(
                                header_name
                            )

                    if detected != "none":
                        auth_evidence.append(
                            {
                                "type": detected,
                                "source": (
                                    f"OpenAPI security scheme "
                                    f"'{name}' in {source}"
                                ),
                                "confidence": 98,
                                "header_name": header_name,
                            }
                        )

        info = document.get("info", {})

        if (
            isinstance(info, dict)
            and str(info.get("_postman_id", "")).strip()
        ):
            variables = document.get(
                "variable",
                [],
            )

            if isinstance(variables, list):
                for variable in variables:
                    if not isinstance(variable, dict):
                        continue

                    key = str(
                        variable.get("key", "")
                    ).lower()

                    if key in {
                        "baseurl",
                        "base_url",
                        "apiurl",
                        "api_url",
                        "host",
                    }:
                        add_url_candidate(
                            server_candidates,
                            seen_urls,
                            variable.get(
                                "value",
                                variable.get("initial"),
                            ),
                            f"Postman variable in {source}",
                            94,
                        )

    return (
        server_candidates,
        auth_evidence,
        sorted(set(header_names)),
    )


def detect_auth(
    inventory_auth: list[str],
    structured_evidence: list[dict],
) -> dict:
    if structured_evidence:
        best = max(
            structured_evidence,
            key=lambda item: item["confidence"],
        )

        return {
            "type": best["type"],
            "confidence": best["confidence"],
            "source": best["source"],
            "header_name": best.get(
                "header_name",
                "",
            ),
        }

    combined = " ".join(
        inventory_auth
    ).lower()

    if any(
        token in combined
        for token in {
            "bearer",
            "oauth2",
            "jwt",
        }
    ):
        return {
            "type": "bearer",
            "confidence": 82,
            "source": "Discovered endpoint authentication metadata",
            "header_name": "",
        }

    if "basic" in combined:
        return {
            "type": "basic",
            "confidence": 82,
            "source": "Discovered endpoint authentication metadata",
            "header_name": "",
        }

    if any(
        token in combined
        for token in {
            "api_key",
            "apikey",
            "api key",
        }
    ):
        return {
            "type": "api_key",
            "confidence": 80,
            "source": "Discovered endpoint authentication metadata",
            "header_name": "X-API-Key",
        }

    return {
        "type": "none",
        "confidence": 45,
        "source": (
            "Authentication was not explicitly documented; "
            "review before saving."
        ),
        "header_name": "",
    }


def infer_configuration(
    db: Session,
    project,
    owner_user_id: int,
) -> dict:
    run = (
        db.execute(
            text(
                """
                SELECT *
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
                "project_id": project["id"],
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )

    endpoints = []

    if run:
        endpoints = (
            db.execute(
                text(
                    """
                    SELECT
                        endpoint_path,
                        authentication,
                        source_file,
                        confidence_score
                    FROM api_inventory
                    WHERE discovery_run_id = :run_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                    ORDER BY endpoint_path
                    """
                ),
                {
                    "run_id": run["id"],
                    "project_id": project["id"],
                    "owner_user_id": owner_user_id,
                },
            )
            .mappings()
            .all()
        )

    paths = [
        row["endpoint_path"]
        for row in endpoints
    ]

    prefix, prefix_confidence, prefix_source = (
        infer_prefix(paths)
    )

    source_root = (
        Path(project["storage_directory"]).resolve()
        / "source"
    )

    expected_root = (
        PROJECT_ROOT / str(owner_user_id)
    ).resolve()

    server_candidates = []
    auth_evidence = []
    header_names = []

    try:
        source_root.relative_to(expected_root)

        if source_root.is_dir():
            (
                server_candidates,
                auth_evidence,
                header_names,
            ) = inspect_structured_documents(
                source_root
            )
    except ValueError:
        pass

    auth = detect_auth(
        [
            str(row["authentication"] or "")
            for row in endpoints
        ],
        auth_evidence,
    )

    if (
        auth.get("header_name")
        and auth["header_name"] not in header_names
    ):
        header_names.append(auth["header_name"])

    sample_paths = []

    for path in paths:
        if path not in sample_paths:
            sample_paths.append(path)

        if len(sample_paths) >= 5:
            break

    return {
        "project": {
            "name": project["name"],
            "environment": project["environment"],
        },
        "api_prefix": {
            "value": prefix,
            "confidence": prefix_confidence,
            "source": prefix_source,
        },
        "base_url_candidates": server_candidates[:10],
        "authentication": auth,
        "suggested_headers": header_names,
        "endpoint_count": len(endpoints),
        "sample_paths": sample_paths,
        "framework_summary": (
            run["framework_summary"]
            if run
            else "API discovery has not been run."
        ),
    }


@router.get(
    "/projects/{public_id}/test-config/suggestions"
)
def smart_suggestions(
    request: Request,
    public_id: str,
):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"error": "Authentication required."},
            status_code=401,
        )

    try:
        uuid.UUID(public_id)
    except ValueError:
        return JSONResponse(
            {"error": "Invalid project."},
            status_code=404,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return JSONResponse(
                {"error": "Project not found."},
                status_code=404,
            )

        result = infer_configuration(
            db,
            project,
            user.id,
        )

    return JSONResponse(result)


class NoRedirectHandler:
    pass


def pinned_https_probe(
    url: str,
    timeout: int = 10,
) -> dict:
    normalized = normalize_public_https_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname
    port = parsed.port or 443
    addresses = public_addresses(
        hostname,
        port,
    )

    address = addresses[0]
    raw_socket = socket.create_connection(
        (address, port),
        timeout=timeout,
    )

    context = ssl.create_default_context()
    tls_socket = context.wrap_socket(
        raw_socket,
        server_hostname=hostname,
    )

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    request_data = (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "User-Agent: QAFox-Safe-Probe/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    tls_socket.sendall(request_data)

    response = http.client.HTTPResponse(
        tls_socket
    )
    response.begin()

    result = {
        "ok": response.status < 500,
        "status_code": response.status,
        "reason": response.reason,
        "url": normalized,
        "resolved_address": address,
        "tls": True,
    }

    response.close()
    tls_socket.close()

    return result


@router.post(
    "/projects/{public_id}/test-config/test-connection"
)
async def test_connection(
    request: Request,
    public_id: str,
):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"error": "Authentication required."},
            status_code=401,
        )

    try:
        uuid.UUID(public_id)
    except ValueError:
        return JSONResponse(
            {"error": "Invalid project."},
            status_code=404,
        )

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid request."},
            status_code=400,
        )

    if not csrf_valid(
        request,
        str(payload.get("csrf", "")),
    ):
        return JSONResponse(
            {"error": "Security token validation failed."},
            status_code=403,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if not project:
            return JSONResponse(
                {"error": "Project not found."},
                status_code=404,
            )

    try:
        result = pinned_https_probe(
            str(payload.get("url", "")),
        )
    except (
        ValueError,
        OSError,
        ssl.SSLError,
        http.client.HTTPException,
    ) as exc:
        return JSONResponse(
            {
                "ok": False,
                "error": str(exc),
            },
            status_code=400,
        )

    return JSONResponse(result)
