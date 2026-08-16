import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)

from app.test_configuration import decrypt_json
from app.smart_data.placeholders import approval_blockers

router = APIRouter()

MAX_RESPONSE_BYTES = 256 * 1024
MIN_REQUEST_INTERVAL_SECONDS = 0.50
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
EXECUTABLE_DECISIONS = {"included-safe", "approved"}

PROHIBITED_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "proxy-authorization",
    "proxy-authenticate",
    "upgrade",
    "cookie",
    "set-cookie",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
}

SENSITIVE_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "password",
    "token",
    "secret",
    "cookie",
    "set-cookie",
}


def utc_now():
    return datetime.now(timezone.utc)


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def resolve_public_addresses(
    hostname: str,
    port: int,
):
    hostname = hostname.lower().rstrip(".")

    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise ValueError(
            "Local or internal targets are blocked."
        )

    results = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
    )

    addresses = sorted({
        item[4][0]
        for item in results
        if item and item[4]
    })

    if not addresses:
        raise ValueError(
            "Target did not resolve to an address."
        )

    if any(
        not is_public_ip(address)
        for address in addresses
    ):
        raise ValueError(
            "Private, loopback or reserved targets are blocked."
        )

    return addresses


def validate_target_url(value: str):
    parsed = urlsplit(
        str(value or "").strip()
    )

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError(
            "Only public HTTPS targets are allowed."
        )

    port = parsed.port or 443
    addresses = resolve_public_addresses(
        parsed.hostname,
        port,
    )

    return parsed, addresses


def safe_json(raw, fallback):
    try:
        return json.loads(raw or "")
    except Exception:
        return fallback


def canonical_hash(value) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def expected_codes(raw: str):
    exact = set()
    ranges = []

    for token in re.split(
        r"[\s,]+",
        str(raw or ""),
    ):
        token = token.strip().lower()

        if re.fullmatch(r"[1-5][0-9]{2}", token):
            exact.add(int(token))
        elif re.fullmatch(r"[1-5]xx", token):
            ranges.append(int(token[0]))

    return exact, ranges


def status_matches(
    actual: int,
    expected: str,
):
    exact, ranges = expected_codes(
        expected
    )

    if not exact and not ranges:
        return 200 <= actual < 300

    return (
        actual in exact
        or actual // 100 in ranges
    )


def mask_text(
    value: str,
    secret_values: list[str],
):
    masked = str(value or "")

    for secret in sorted(
        {
            item
            for item in secret_values
            if item and len(item) >= 3
        },
        key=len,
        reverse=True,
    ):
        masked = masked.replace(
            secret,
            "[REDACTED]",
        )

    return masked


def mask_headers(
    headers: dict,
    secret_values: list[str],
):
    result = {}

    for name, value in headers.items():
        if name.lower() in SENSITIVE_NAMES:
            result[name] = "[REDACTED]"
        else:
            result[name] = mask_text(
                str(value),
                secret_values,
            )

    return result


def sanitize_headers(headers):
    result = {}

    if not isinstance(headers, dict):
        return result

    for name, value in headers.items():
        name = str(name).strip()
        lower = name.lower()
        value = str(value)

        if (
            not name
            or lower in PROHIBITED_HEADERS
            or "\r" in name
            or "\n" in name
            or ":" in name
            or "\r" in value
            or "\n" in value
        ):
            continue

        if len(name) <= 100 and len(value) <= 4096:
            result[name] = value

    return result


def build_runtime_headers(
    configuration,
    case_headers,
):
    custom_headers = decrypt_json(
        configuration[
            "encrypted_custom_headers"
        ]
    )

    auth = decrypt_json(
        configuration[
            "encrypted_auth_config"
        ]
    )

    headers = sanitize_headers(
        custom_headers
    )

    headers.update(
        sanitize_headers(case_headers)
    )

    auth_type = str(
        configuration["auth_type"] or "none"
    )

    if auth_type == "bearer":
        token = str(
            auth.get(
                "token",
                auth.get("access_token", ""),
            )
        )

        if token:
            headers["Authorization"] = (
                f"Bearer {token}"
            )

    elif auth_type == "api_key":
        header_name = str(
            auth.get(
                "header_name",
                auth.get("name", "X-API-Key"),
            )
        )

        api_key = str(
            auth.get(
                "value",
                auth.get("api_key", ""),
            )
        )

        if api_key:
            headers[header_name] = api_key

    elif auth_type == "basic":
        username = str(
            auth.get("username", "")
        )
        password = str(
            auth.get("password", "")
        )

        if username or password:
            encoded = base64.b64encode(
                f"{username}:{password}".encode(
                    "utf-8"
                )
            ).decode("ascii")

            headers["Authorization"] = (
                f"Basic {encoded}"
            )

    secret_values = []

    for value in auth.values():
        if isinstance(value, str):
            secret_values.append(value)

    for value in custom_headers.values():
        if isinstance(value, str):
            secret_values.append(value)

    return headers, secret_values



def unresolved_test_data_marker(
    value,
) -> str | None:
    blockers = approval_blockers(value)
    return blockers[0] if blockers else None

def resolve_path(
    path: str,
    method: str,
):
    path = str(path or "")

    required_marker = unresolved_test_data_marker(
        path
    )

    if required_marker:
        return (
            path,
            "Required editable test data is unresolved: "
            + required_marker,
        )

    path = re.sub(
        r"\{\{INVALID_[A-Z0-9_]+\}\}",
        "qafox-invalid",
        path,
    )

    unresolved = re.findall(
        r"\{([^{}]+)\}",
        path,
    )

    if not unresolved:
        return path, None

    if method not in SAFE_METHODS:
        return (
            path,
            "State-changing request contains unresolved path parameters.",
        )

    for expression in unresolved:
        name, _, type_name = (
            expression.partition(":")
        )

        replacement = (
            "1"
            if type_name.lower() in {
                "int",
                "integer",
                "number",
            }
            else "qafox-test"
        )

        path = path.replace(
            "{" + expression + "}",
            replacement,
        )

    return path, None


class PinnedHTTPSConnection(
    http.client.HTTPSConnection
):
    def __init__(
        self,
        hostname,
        address,
        port,
        timeout,
        context,
    ):
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=context,
        )

        self.pinned_address = address

    def connect(self):
        raw_socket = socket.create_connection(
            (
                self.pinned_address,
                self.port,
            ),
            timeout=self.timeout,
            source_address=self.source_address,
        )

        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


def execute_https_request(
    url,
    method,
    headers,
    body,
    timeout,
):
    parsed, addresses = validate_target_url(
        url
    )

    context = ssl.create_default_context()

    connection = PinnedHTTPSConnection(
        parsed.hostname,
        addresses[0],
        parsed.port or 443,
        timeout,
        context,
    )

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    connection.request(
        method,
        path,
        body=body,
        headers=headers,
    )

    response = connection.getresponse()

    raw_body = response.read(
        MAX_RESPONSE_BYTES + 1
    )

    if len(raw_body) > MAX_RESPONSE_BYTES:
        raise ValueError(
            "Response exceeded the 256 KB capture limit."
        )

    response_headers = {
        name: value
        for name, value in response.getheaders()
    }

    result = {
        "status_code": response.status,
        "reason": response.reason,
        "headers": response_headers,
        "body": raw_body,
        "size": len(raw_body),
    }

    connection.close()

    return result


def final_url(
    base_url: str,
    endpoint_path: str,
    query: dict,
):
    base = base_url.rstrip("/")
    path = "/" + endpoint_path.lstrip("/")
    url = base + path

    if query:
        url += "?" + urlencode(
            query,
            doseq=True,
        )

    validate_target_url(url)

    return url


def run_stopped(
    db: Session,
    run_id: int,
    owner_user_id: int,
):
    return bool(
        db.execute(
            text(
                """
                SELECT stop_requested
                FROM api_test_runs
                WHERE id = :run_id
                  AND owner_user_id = :owner_user_id
                """
            ),
            {
                "run_id": run_id,
                "owner_user_id": owner_user_id,
            },
        ).scalar()
    )


def recalculate_run(
    db: Session,
    run_id: int,
    owner_user_id: int,
):
    totals = (
        db.execute(
            text(
                """
                SELECT
                    COUNT(*) AS completed,
                    COUNT(*) FILTER (
                        WHERE status = 'passed'
                    ) AS passed,
                    COUNT(*) FILTER (
                        WHERE status = 'failed'
                    ) AS failed,
                    COUNT(*) FILTER (
                        WHERE status = 'error'
                    ) AS errors,
                    COUNT(*) FILTER (
                        WHERE status = 'skipped'
                    ) AS skipped
                FROM api_test_results
                WHERE test_run_id = :run_id
                  AND owner_user_id = :owner_user_id
                """
            ),
            {
                "run_id": run_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .one()
    )

    db.execute(
        text(
            """
            UPDATE api_test_runs
            SET
                completed_count = :completed,
                passed_count = :passed,
                failed_count = :failed,
                error_count = :errors,
                skipped_count = :skipped
            WHERE id = :run_id
              AND owner_user_id = :owner_user_id
            """
        ),
        {
            **totals,
            "run_id": run_id,
            "owner_user_id": owner_user_id,
        },
    )


def store_result(
    db,
    run,
    plan_case,
    sequence,
    snapshot,
    status,
    url,
    started_at,
    actual_status=None,
    duration_ms=None,
    response_headers=None,
    response_body="",
    response_size=None,
    error_message="",
    assertion_summary="",
):
    db.execute(
        text(
            """
            INSERT INTO api_test_results (
                public_id,
                test_run_id,
                execution_plan_case_id,
                project_id,
                owner_user_id,
                sequence_number,
                status,
                http_method,
                endpoint_path,
                final_url_masked,
                expected_status_codes,
                actual_status_code,
                duration_ms,
                response_headers,
                response_body_sample,
                response_size_bytes,
                error_message,
                assertion_summary,
                started_at,
                completed_at,
                created_at
            )
            VALUES (
                :public_id,
                :test_run_id,
                :execution_plan_case_id,
                :project_id,
                :owner_user_id,
                :sequence_number,
                :status,
                :http_method,
                :endpoint_path,
                :final_url_masked,
                :expected_status_codes,
                :actual_status_code,
                :duration_ms,
                :response_headers,
                :response_body_sample,
                :response_size_bytes,
                :error_message,
                :assertion_summary,
                :started_at,
                :completed_at,
                :created_at
            )
            """
        ),
        {
            "public_id": str(uuid.uuid4()),
            "test_run_id": run["id"],
            "execution_plan_case_id":
                plan_case["id"],
            "project_id": run["project_id"],
            "owner_user_id":
                run["owner_user_id"],
            "sequence_number": sequence,
            "status": status,
            "http_method":
                snapshot.get("http_method", ""),
            "endpoint_path":
                snapshot.get("endpoint_path", ""),
            "final_url_masked": url,
            "expected_status_codes":
                snapshot.get(
                    "expected_status_codes",
                    "",
                ),
            "actual_status_code": actual_status,
            "duration_ms": duration_ms,
            "response_headers": json.dumps(
                response_headers or {},
                ensure_ascii=False,
            ),
            "response_body_sample":
                response_body,
            "response_size_bytes":
                response_size,
            "error_message": error_message,
            "assertion_summary":
                assertion_summary,
            "started_at": started_at,
            "completed_at": utc_now(),
            "created_at": utc_now(),
        },
    )

    recalculate_run(
        db,
        run["id"],
        run["owner_user_id"],
    )

    db.commit()


def execute_run(run_id: int):
    with Session(engine) as db:
        run = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_test_runs
                    WHERE id = :run_id
                    LIMIT 1
                    """
                ),
                {"run_id": run_id},
            )
            .mappings()
            .first()
        )

        if not run:
            return

        plan = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_execution_plans
                    WHERE id = :plan_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                    LIMIT 1
                    """
                ),
                {
                    "plan_id":
                        run["execution_plan_id"],
                    "project_id":
                        run["project_id"],
                    "owner_user_id":
                        run["owner_user_id"],
                },
            )
            .mappings()
            .first()
        )

        configuration = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_test_configurations
                    WHERE id = :configuration_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                      AND is_active = TRUE
                    LIMIT 1
                    """
                ),
                {
                    "configuration_id":
                        plan["configuration_id"],
                    "project_id":
                        run["project_id"],
                    "owner_user_id":
                        run["owner_user_id"],
                },
            )
            .mappings()
            .first()
        )

        if not plan or not configuration:
            db.execute(
                text(
                    """
                    UPDATE api_test_runs
                    SET status = 'error',
                        completed_at = :completed_at
                    WHERE id = :run_id
                    """
                ),
                {
                    "completed_at": utc_now(),
                    "run_id": run_id,
                },
            )
            db.commit()
            return

        stored_snapshot = safe_json(
            plan["snapshot_json"],
            {},
        )

        if (
            canonical_hash(stored_snapshot)
            != plan["snapshot_sha256"]
        ):
            db.execute(
                text(
                    """
                    UPDATE api_test_runs
                    SET status = 'integrity-failed',
                        completed_at = :completed_at
                    WHERE id = :run_id
                    """
                ),
                {
                    "completed_at": utc_now(),
                    "run_id": run_id,
                },
            )
            db.commit()
            return

        cases = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_execution_plan_cases
                    WHERE execution_plan_id = :plan_id
                      AND owner_user_id = :owner_user_id
                      AND decision IN (
                          'included-safe',
                          'approved'
                      )
                      AND destructive = FALSE
                    ORDER BY id
                    """
                ),
                {
                    "plan_id": plan["id"],
                    "owner_user_id":
                        run["owner_user_id"],
                },
            )
            .mappings()
            .all()
        )

        db.execute(
            text(
                """
                UPDATE api_test_runs
                SET status = 'running',
                    started_at = :started_at,
                    total_count = :total_count
                WHERE id = :run_id
                """
            ),
            {
                "started_at": utc_now(),
                "total_count": len(cases),
                "run_id": run_id,
            },
        )
        db.commit()

        timeout = max(
            3,
            min(
                30,
                int(
                    configuration[
                        "request_timeout_seconds"
                    ]
                ),
            ),
        )

        for sequence, plan_case in enumerate(
            cases,
            start=1,
        ):
            db.expire_all()

            if run_stopped(
                db,
                run["id"],
                run["owner_user_id"],
            ):
                break

            snapshot = safe_json(
                plan_case["case_snapshot"],
                {},
            )

            method = str(
                snapshot.get(
                    "http_method",
                    "GET",
                )
            ).upper()

            endpoint_path, skip_reason = (
                resolve_path(
                    snapshot.get(
                        "endpoint_path",
                        "/",
                    ),
                    method,
                )
            )

            request_body = snapshot.get(
                "request_body"
            )

            marker = unresolved_test_data_marker(
                {
                    "body": request_body,
                    "query": snapshot.get(
                        "request_query",
                        {},
                    ),
                    "headers": snapshot.get(
                        "request_headers",
                        {},
                    ),
                }
            )

            if marker:
                skip_reason = (
                    "Required editable test data is unresolved: "
                    + marker
                )

            if (
                method not in SAFE_METHODS
                and request_body is None
                and not skip_reason
            ):
                skip_reason = (
                    "State-changing request has no concrete "
                    "request body; Qubi refused to guess."
                )

            started_at = utc_now()

            if skip_reason:
                store_result(
                    db,
                    run,
                    plan_case,
                    sequence,
                    snapshot,
                    "skipped",
                    (
                        plan["base_url_snapshot"]
                        + endpoint_path
                    ),
                    started_at,
                    error_message=skip_reason,
                    assertion_summary=(
                        "Skipped by runtime safety gate."
                    ),
                )
                continue

            query = snapshot.get(
                "request_query",
                {},
            )

            if not isinstance(query, dict):
                query = {}

            try:
                url = final_url(
                    plan["base_url_snapshot"],
                    endpoint_path,
                    query,
                )

                headers, secret_values = (
                    build_runtime_headers(
                        configuration,
                        snapshot.get(
                            "request_headers",
                            {},
                        ),
                    )
                )

                body = None

                if request_body is not None:
                    content_type = ""

                    for name, value in headers.items():
                        if name.lower() == "content-type":
                            content_type = value.lower()
                            break

                    if (
                        "application/x-www-form-urlencoded"
                        in content_type
                    ):
                        body = urlencode(
                            request_body,
                            doseq=True,
                        ).encode("utf-8")

                    elif "text/plain" in content_type:
                        body = json.dumps(
                            request_body,
                            ensure_ascii=False,
                        ).encode("utf-8")

                    else:
                        headers.setdefault(
                            "Content-Type",
                            "application/json",
                        )

                        body = json.dumps(
                            request_body,
                            ensure_ascii=False,
                        ).encode("utf-8")

                headers.setdefault(
                    "Accept",
                    "application/json, text/plain, */*",
                )

                headers["User-Agent"] = (
                    "QAFox-Hardened-Runner/1.0"
                )

                request_started = time.monotonic()

                response = execute_https_request(
                    url,
                    method,
                    headers,
                    body,
                    timeout,
                )

                duration_ms = round(
                    (
                        time.monotonic()
                        - request_started
                    )
                    * 1000
                )

                raw_body = response["body"].decode(
                    "utf-8",
                    errors="replace",
                )

                masked_body = mask_text(
                    raw_body,
                    secret_values,
                )

                masked_response_headers = (
                    mask_headers(
                        response["headers"],
                        secret_values,
                    )
                )

                passed = status_matches(
                    response["status_code"],
                    snapshot.get(
                        "expected_status_codes",
                        "",
                    ),
                )

                status = (
                    "passed"
                    if passed
                    else "failed"
                )

                assertion = (
                    "Actual status matched expected status."
                    if passed
                    else (
                        f"Expected "
                        f"{snapshot.get('expected_status_codes', '')}; "
                        f"received {response['status_code']}."
                    )
                )

                if 300 <= response["status_code"] < 400:
                    status = "failed"
                    assertion = (
                        "Redirect response was blocked and "
                        "was not followed."
                    )

                store_result(
                    db,
                    run,
                    plan_case,
                    sequence,
                    snapshot,
                    status,
                    mask_text(
                        url,
                        secret_values,
                    ),
                    started_at,
                    actual_status=
                        response["status_code"],
                    duration_ms=duration_ms,
                    response_headers=
                        masked_response_headers,
                    response_body=
                        masked_body[:MAX_RESPONSE_BYTES],
                    response_size=
                        response["size"],
                    assertion_summary=assertion,
                )

            except Exception as exc:
                store_result(
                    db,
                    run,
                    plan_case,
                    sequence,
                    snapshot,
                    "error",
                    (
                        plan["base_url_snapshot"]
                        + endpoint_path
                    ),
                    started_at,
                    error_message=mask_text(
                        str(exc),
                        locals().get(
                            "secret_values",
                            [],
                        ),
                    ),
                    assertion_summary=(
                        "Request could not be safely completed."
                    ),
                )

            time.sleep(
                MIN_REQUEST_INTERVAL_SECONDS
            )

        db.expire_all()

        stopped = run_stopped(
            db,
            run["id"],
            run["owner_user_id"],
        )

        db.execute(
            text(
                """
                UPDATE api_test_runs
                SET status = :status,
                    completed_at = :completed_at
                WHERE id = :run_id
                """
            ),
            {
                "status": (
                    "stopped"
                    if stopped
                    else "completed"
                ),
                "completed_at": utc_now(),
                "run_id": run["id"],
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
                    'api-test-run-completed',
                    :summary,
                    :created_at
                )
                """
            ),
            {
                "project_id":
                    run["project_id"],
                "owner_user_id":
                    run["owner_user_id"],
                "summary": (
                    f"API test run "
                    f"{'stopped' if stopped else 'completed'}."
                ),
                "created_at": utc_now(),
            },
        )

        db.commit()


def owned_plan(
    db,
    owner_user_id,
    project_id,
    plan_public_id,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_execution_plans
                WHERE public_id = :public_id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                LIMIT 1
                """
            ),
            {
                "public_id": plan_public_id,
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def owned_project(
    db,
    owner_user_id,
    public_id,
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


@router.post(
    "/projects/{public_id}/execution-plans/{plan_public_id}/run"
)
async def start_run(
    request: Request,
    public_id: str,
    plan_public_id: str,
    background_tasks: BackgroundTasks,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    try:
        uuid.UUID(public_id)
        uuid.UUID(plan_public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    form = await request.form()
    submitted_csrf = str(
        form.get("csrf", "")
    )
    confirmation = str(
        form.get("confirmation", "")
    ).strip()

    if not csrf_valid(
        request,
        submitted_csrf,
    ):
        return RedirectResponse(
            f"/projects/{public_id}/execution-plans/"
            f"{plan_public_id}?error=Security+validation+failed.",
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

        plan = owned_plan(
            db,
            user.id,
            project["id"],
            plan_public_id,
        )

        if not plan:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases",
                status_code=303,
            )

        required_confirmation = (
            "RUN " + plan["snapshot_sha256"][:8]
        )

        if confirmation != required_confirmation:
            return RedirectResponse(
                f"/projects/{public_id}/execution-plans/"
                f"{plan_public_id}?error=Typed+confirmation+did+not+match.",
                status_code=303,
            )

        run_public_id = str(uuid.uuid4())

        claimed = db.execute(
            text(
                """
                UPDATE api_execution_plans
                SET
                    status = 'consumed',
                    consumed_at = :consumed_at
                WHERE id = :plan_id
                  AND owner_user_id = :owner_user_id
                  AND status = 'approved'
                  AND consumed_at IS NULL
                RETURNING id
                """
            ),
            {
                "consumed_at": utc_now(),
                "plan_id": plan["id"],
                "owner_user_id": user.id,
            },
        ).scalar_one_or_none()

        if not claimed:
            db.rollback()

            existing_run = (
                db.execute(
                    text(
                        """
                        SELECT public_id
                        FROM api_test_runs
                        WHERE execution_plan_id = :plan_id
                          AND owner_user_id = :owner_user_id
                        LIMIT 1
                        """
                    ),
                    {
                        "plan_id": plan["id"],
                        "owner_user_id": user.id,
                    },
                )
                .mappings()
                .first()
            )

            if existing_run:
                return RedirectResponse(
                    f"/projects/{public_id}/execution-runs/"
                    f"{existing_run['public_id']}",
                    status_code=303,
                )

            return RedirectResponse(
                f"/projects/{public_id}/execution-plans/"
                f"{plan_public_id}?error=Plan+was+already+consumed.",
                status_code=303,
            )

        run_id = db.execute(
            text(
                """
                INSERT INTO api_test_runs (
                    public_id,
                    execution_plan_id,
                    project_id,
                    owner_user_id,
                    status,
                    created_at
                )
                VALUES (
                    :public_id,
                    :execution_plan_id,
                    :project_id,
                    :owner_user_id,
                    'queued',
                    :created_at
                )
                RETURNING id
                """
            ),
            {
                "public_id": run_public_id,
                "execution_plan_id": plan["id"],
                "project_id": project["id"],
                "owner_user_id": user.id,
                "created_at": utc_now(),
            },
        ).scalar_one()

        db.commit()

    background_tasks.add_task(
        execute_run,
        run_id,
    )

    return RedirectResponse(
        f"/projects/{public_id}/execution-runs/"
        f"{run_public_id}",
        status_code=303,
    )


@router.get(
    "/projects/{public_id}/execution-runs/{run_public_id}",
    response_class=HTMLResponse,
)
def run_results_page(
    request: Request,
    public_id: str,
    run_public_id: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
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

        run = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_test_runs
                    WHERE public_id = :public_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                    LIMIT 1
                    """
                ),
                {
                    "public_id": run_public_id,
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                },
            )
            .mappings()
            .first()
        )

        if not run:
            return RedirectResponse(
                f"/projects/{public_id}/test-cases",
                status_code=303,
            )

        results = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_test_results
                    WHERE test_run_id = :run_id
                      AND owner_user_id = :owner_user_id
                    ORDER BY sequence_number
                    """
                ),
                {
                    "run_id": run["id"],
                    "owner_user_id": user.id,
                },
            )
            .mappings()
            .all()
        )

    csrf = csrf_token(request)
    active = run["status"] in {
        "queued",
        "running",
    }

    rows = ""

    for result in results:
        rows += f"""
        <tr>
            <td>{esc(str(result["sequence_number"]))}</td>
            <td>
                <strong>{esc(result["http_method"])}</strong>
                <code>{esc(result["endpoint_path"])}</code>
            </td>
            <td>
                <span class="run-result-status {esc(result["status"])}">
                    {esc(result["status"].title())}
                </span>
            </td>
            <td>
                {
                    esc(str(result["actual_status_code"]))
                    if result["actual_status_code"] is not None
                    else "—"
                }
            </td>
            <td>
                {
                    esc(str(result["duration_ms"])) + " ms"
                    if result["duration_ms"] is not None
                    else "—"
                }
            </td>
            <td>
                <details>
                    <summary>Details</summary>
                    <p>{esc(result["assertion_summary"] or "")}</p>
                    <p>{esc(result["error_message"] or "")}</p>
                    <pre>{esc(result["response_body_sample"] or "")}</pre>
                </details>
            </td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="6" class="case-empty-row">
                Qubi is preparing the first result…
            </td>
        </tr>
        """

    refresh = (
        '<meta http-equiv="refresh" content="3">'
        if active
        else ""
    )

    stop_form = (
        f"""
        <form method="post"
              action="/projects/{esc(public_id)}/execution-runs/{esc(run_public_id)}/stop">
            <input type="hidden"
                   name="csrf"
                   value="{esc(csrf)}">
            <button class="runner-stop-button"
                    type="submit">
                Stop after current request
            </button>
        </form>
        """
        if active
        else ""
    )

    content = f"""
{refresh}
<section class="runner-shell">
    <div class="runner-heading">
        <div>
            <a href="/projects/{esc(public_id)}/test-cases">
                ← Test cases
            </a>
            <span>HARDENED AUTOMATED RUNNER</span>
            <h1>Execution {esc(run["status"])}</h1>
            <p>
                Sequential execution with TLS verification,
                SSRF protection and secret masking.
            </p>
        </div>
        {stop_form}
    </div>

    <div class="runner-progress">
        <div>
            <strong>
                {esc(str(run["completed_count"]))}
                / {esc(str(run["total_count"]))}
            </strong>
            <span>Completed</span>
        </div>
        <progress value="{esc(str(run["completed_count"]))}"
                  max="{esc(str(max(run["total_count"], 1)))}">
        </progress>
    </div>

    <div class="runner-stats">
        <article class="passed">
            <strong>{esc(str(run["passed_count"]))}</strong>
            <span>Passed</span>
        </article>
        <article class="failed">
            <strong>{esc(str(run["failed_count"]))}</strong>
            <span>Failed</span>
        </article>
        <article class="error">
            <strong>{esc(str(run["error_count"]))}</strong>
            <span>Errors</span>
        </article>
        <article class="skipped">
            <strong>{esc(str(run["skipped_count"]))}</strong>
            <span>Skipped</span>
        </article>
    </div>

    <div class="runner-table-wrap">
        <table class="runner-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Request</th>
                    <th>Result</th>
                    <th>HTTP</th>
                    <th>Duration</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
</section>
"""

    return layout(
        "API test execution",
        content,
        request,
        public=False,
    )


@router.post(
    "/projects/{public_id}/execution-runs/{run_public_id}/stop"
)
async def stop_run(
    request: Request,
    public_id: str,
    run_public_id: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    form = await request.form()

    if not csrf_valid(
        request,
        str(form.get("csrf", "")),
    ):
        return RedirectResponse(
            f"/projects/{public_id}/execution-runs/{run_public_id}",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            public_id,
        )

        if project:
            db.execute(
                text(
                    """
                    UPDATE api_test_runs
                    SET stop_requested = TRUE
                    WHERE public_id = :public_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                      AND status IN ('queued', 'running')
                    """
                ),
                {
                    "public_id": run_public_id,
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                },
            )
            db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/execution-runs/{run_public_id}",
        status_code=303,
    )


@router.get(
    "/projects/{public_id}/execution-runs/{run_public_id}/status"
)
def run_status(
    request: Request,
    public_id: str,
    run_public_id: str,
):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"error": "Authentication required."},
            status_code=401,
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

        run = (
            db.execute(
                text(
                    """
                    SELECT
                        status,
                        total_count,
                        completed_count,
                        passed_count,
                        failed_count,
                        error_count,
                        skipped_count,
                        stop_requested
                    FROM api_test_runs
                    WHERE public_id = :public_id
                      AND project_id = :project_id
                      AND owner_user_id = :owner_user_id
                    LIMIT 1
                    """
                ),
                {
                    "public_id": run_public_id,
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                },
            )
            .mappings()
            .first()
        )

    if not run:
        return JSONResponse(
            {"error": "Run not found."},
            status_code=404,
        )

    return JSONResponse(dict(run))
