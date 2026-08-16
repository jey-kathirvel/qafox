import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.smart_data.orchestration import (
    apply_orchestration_to_snapshot,
    build_orchestration,
    plan_blockers,
)
from app.smart_data.placeholders import approval_blockers, request_payload

from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)

router = APIRouter()

DESTRUCTIVE_PATH_PATTERN = re.compile(
    r"(^|/)(delete|remove|destroy|drop|truncate|purge|erase)"
    r"($|/|[-_])",
    re.IGNORECASE,
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


def active_configurations(
    db: Session,
    owner_user_id: int,
    project_id: int,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_test_configurations
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND is_active = TRUE
                ORDER BY updated_at DESC
                """
            ),
            {
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .all()
    )


def owned_configuration(
    db: Session,
    owner_user_id: int,
    project_id: int,
    public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_test_configurations
                WHERE public_id = :public_id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND is_active = TRUE
                LIMIT 1
                """
            ),
            {
                "public_id": public_id,
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def enabled_cases(
    db: Session,
    owner_user_id: int,
    project_id: int,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_test_cases
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND is_enabled = TRUE
                ORDER BY
                    safe_to_execute DESC,
                    endpoint_path,
                    http_method,
                    case_type
                """
            ),
            {
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .all()
    )


def owned_plan(
    db: Session,
    owner_user_id: int,
    project_id: int,
    public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT
                    ep.*,
                    u.full_name AS approver_name,
                    u.username AS approver_username
                FROM api_execution_plans ep
                JOIN users u
                  ON u.id = ep.approved_by_user_id
                WHERE ep.public_id = :public_id
                  AND ep.project_id = :project_id
                  AND ep.owner_user_id = :owner_user_id
                LIMIT 1
                """
            ),
            {
                "public_id": public_id,
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def is_destructive(case) -> bool:
    method = str(
        case["http_method"] or ""
    ).upper()

    path = str(
        case["endpoint_path"] or ""
    )

    return bool(
        method == "DELETE"
        or DESTRUCTIVE_PATH_PATTERN.search(path)
    )


def safe_json(raw, fallback):
    try:
        value = json.loads(raw or "")
        return value
    except Exception:
        return fallback


def case_request_payload(case):
    return request_payload(case)


def unresolved_test_data(case) -> tuple[str, ...]:
    return approval_blockers(request_payload(case))


def case_snapshot(case, decision: str):
    payload = case_request_payload(case)
    return {
        "test_case_public_id": case["public_id"],
        "title": case["title"],
        "description": case["description"],
        "case_type": case["case_type"],
        "http_method": case["http_method"],
        "endpoint_path": case["endpoint_path"],
        "request_headers": payload["headers"],
        "request_query": payload["query"],
        "request_body": payload["body"],
        "expected_status_codes":
            case["expected_status_codes"],
        "expected_behavior":
            case["expected_behavior"],
        "confidence": case["confidence"],
        "safe_to_execute":
            bool(case["safe_to_execute"]),
        "requires_approval":
            bool(case["requires_approval"]),
        "destructive": is_destructive(case),
        "decision": decision,
    }


def configuration_options(
    configurations,
    selected_id: str,
):
    return "".join(
        f"""
        <option value="{esc(item["public_id"])}"
            {
                "selected"
                if item["public_id"] == selected_id
                else ""
            }>
            {esc(item["name"])}
            · {esc(item["environment"].title())}
            · {esc(item["base_url"])}
        </option>
        """
        for item in configurations
    )


def approval_page(
    request: Request,
    project,
    configurations,
    cases,
    selected_configuration_id: str = "",
    error: str = "",
):
    csrf = csrf_token(request)

    selected_configuration_id = (
        selected_configuration_id
        or (
            configurations[0]["public_id"]
            if configurations
            else ""
        )
    )

    safe_rows = ""
    approval_rows = ""
    data_rows = ""
    destructive_count = 0

    for case in cases:
        destructive = is_destructive(case)
        blockers = unresolved_test_data(case)

        if destructive:
            destructive_count += 1

        method_class = (
            str(case["http_method"]).lower()
        )

        if blockers:
            blocker_text = ", ".join(blockers[:4])
            data_rows += f"""
            <label class="approval-case approval-required-case">
                <input type="checkbox"
                       name="dependent_case"
                       value="{esc(case["public_id"])}">
                <div>
                    <span class="method-badge method-{esc(method_class)}">
                        {esc(case["http_method"])}
                    </span>
                </div>
                <div>
                    <strong>{esc(case["title"])}</strong>
                    <code>{esc(case["endpoint_path"])}</code>
                    <small>
                        Include as a dependent step if this plan also creates
                        the required resource. Otherwise edit the placeholder:
                        {esc(blocker_text)}
                    </small>
                    <p>
                        <a href="/projects/{esc(project["public_id"])}/test-cases/{esc(case["public_id"])}/edit">
                            Edit test data
                        </a>
                    </p>
                </div>
                <span class="approval-warning-badge">
                    Needs test data
                </span>
            </label>
            """
        elif case["safe_to_execute"]:
            safe_rows += f"""
            <article class="approval-case safe-case">
                <input type="hidden"
                       name="safe_case"
                       value="{esc(case["public_id"])}">

                <div>
                    <span class="method-badge method-{esc(method_class)}">
                        {esc(case["http_method"])}
                    </span>
                </div>

                <div>
                    <strong>{esc(case["title"])}</strong>
                    <code>{esc(case["endpoint_path"])}</code>
                    <small>
                        Automatically included · read-only classification
                    </small>
                </div>

                <span class="approval-safe-badge">
                    Included
                </span>
            </article>
            """
        else:
            blocked = destructive

            approval_rows += f"""
            <label class="approval-case approval-required-case
                          {"destructive-case" if destructive else ""}">
                <input type="checkbox"
                       name="approved_case"
                       value="{esc(case["public_id"])}"
                       {"disabled" if blocked else ""}>

                <div>
                    <span class="method-badge method-{esc(method_class)}">
                        {esc(case["http_method"])}
                    </span>
                </div>

                <div>
                    <strong>{esc(case["title"])}</strong>
                    <code>{esc(case["endpoint_path"])}</code>
                    <small>
                        {
                            "Blocked by configuration: destructive methods disabled."
                            if blocked
                            else
                            "Select to approve for this execution plan only."
                        }
                    </small>
                </div>

                <span class="approval-warning-badge">
                    {
                        "Blocked"
                        if blocked
                        else "Approval required"
                    }
                </span>
            </label>
            """

    if not safe_rows:
        safe_rows = """
        <div class="approval-empty">
            No enabled safe/read-only test cases.
        </div>
        """

    if not approval_rows:
        approval_rows = """
        <div class="approval-empty">
            No state-changing cases require approval.
        </div>
        """

    notice = (
        f'<div class="case-notice error">{esc(error)}</div>'
        if error
        else ""
    )

    if not configurations:
        content = f"""
        <section class="execution-approval-shell">
            <a href="/projects/{esc(project["public_id"])}/test-cases">
                ← Generated test cases
            </a>

            <div class="approval-empty-state">
                <div>🦊</div>
                <h1>Configuration required</h1>
                <p>
                    Create an encrypted test configuration before
                    preparing an execution plan.
                </p>
                <a class="primary-button"
                   href="/projects/{esc(project["public_id"])}/test-config/new">
                    Create configuration
                </a>
            </div>
        </section>
        """

        return layout(
            "Prepare execution",
            content,
            request,
            public=False,
        )

    content = f"""
<section class="execution-approval-shell">
    <div class="execution-approval-heading">
        <div>
            <a href="/projects/{esc(project["public_id"])}/test-cases">
                ← Generated test cases
            </a>
            <span>SAFE EXECUTION PLANNING</span>
            <h1>Review and approve</h1>
            <p>
                Qubi will snapshot only the cases approved here.
                Approval applies to one execution plan and does not
                grant permanent permission.
            </p>
        </div>

        <div class="approval-fox">🦊</div>
    </div>

    {notice}

    <form class="execution-approval-form"
          method="post"
          action="/projects/{esc(project["public_id"])}/execution-plans/new">

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <section class="approval-section">
            <div class="approval-section-heading">
                <div>
                    <span>STEP 1</span>
                    <h2>Select configuration</h2>
                </div>
            </div>

            <label class="approval-config-label">
                Test environment
                <select name="configuration_public_id"
                        required>
                    {
                        configuration_options(
                            configurations,
                            selected_configuration_id,
                        )
                    }
                </select>
            </label>

            <div class="approval-policy-grid">
                <article>
                    <strong>Safe mode</strong>
                    <span>Enabled</span>
                </article>
                <article>
                    <strong>Destructive methods</strong>
                    <span>Blocked unless configuration enables them</span>
                </article>
                <article>
                    <strong>Secrets</strong>
                    <span>Not copied into the plan snapshot</span>
                </article>
            </div>
        </section>

        <section class="approval-section">
            <div class="approval-section-heading">
                <div>
                    <span>STEP 2</span>
                    <h2>Safe cases</h2>
                    <p>
                        Enabled read-only cases are automatically included.
                    </p>
                </div>
            </div>

            <div class="approval-case-list">
                {safe_rows}
            </div>
        </section>

        {
            f'''
        <section class="approval-section">
            <div class="approval-section-heading">
                <div>
                    <span>NEEDS DATA</span>
                    <h2>Unresolved placeholders</h2>
                    <p>
                        These cases stay out of the plan unless you include
                        them as dependents of a create step in this plan, or
                        replace placeholders with reviewed values.
                    </p>
                </div>
            </div>
            <div class="approval-case-list">
                {data_rows}
            </div>
        </section>
            '''
            if data_rows
            else ""
        }

        <section class="approval-section">
            <div class="approval-section-heading">
                <div>
                    <span>STEP 3</span>
                    <h2>State-changing cases</h2>
                    <p>
                        Select only the cases you explicitly approve.
                        Unselected cases are recorded as excluded.
                    </p>
                </div>
            </div>

            <div class="approval-case-list">
                {approval_rows}
            </div>
        </section>

        <section class="approval-confirmation">
            <label class="approval-confirm-check">
                <input type="checkbox"
                       name="approve_cleanup"
                       value="yes">
                <span>
                    <strong>
                        Approve same-run cleanup
                    </strong>
                    <small>
                        If checked, Qubi may DELETE only resources created by
                        this run after the other steps finish. Cleanup never
                        uses guessed or historical IDs.
                    </small>
                </span>
            </label>

            <label class="approval-confirm-check">
                <input type="checkbox"
                       name="understood"
                       value="yes"
                       required>
                <span>
                    <strong>
                        I reviewed this one-run execution plan.
                    </strong>
                    <small>
                        Creating this plan does not execute any request.
                    </small>
                </span>
            </label>

            <label>
                Approval statement
                <input name="approval_statement"
                       maxlength="300"
                       required
                       placeholder="Example: Approved for the isolated QA environment">
            </label>

            {
                f'''
                <div class="destructive-notice">
                    ⚠ {destructive_count} destructive-looking case(s)
                    detected and blocked by the current configuration.
                </div>
                '''
                if destructive_count
                else ""
            }

            <button class="primary-button"
                    type="submit">
                Approve and create immutable plan
            </button>

            <p>
                No target API request will run in PATCH-QAFOX-004C1.
            </p>
        </section>
    </form>
</section>
"""

    return layout(
        "Review execution plan",
        content,
        request,
        public=False,
    )


@router.get(
    "/projects/{public_id}/execution-plans/new",
    response_class=HTMLResponse,
)
def new_execution_plan_page(
    request: Request,
    public_id: str,
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

        configurations = active_configurations(
            db,
            user.id,
            project["id"],
        )

        cases = enabled_cases(
            db,
            user.id,
            project["id"],
        )

    return approval_page(
        request,
        project,
        configurations,
        cases,
    )


@router.post(
    "/projects/{public_id}/execution-plans/new",
    response_class=HTMLResponse,
)
async def create_execution_plan(
    request: Request,
    public_id: str,
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

    form = await request.form()

    submitted_csrf = str(
        form.get("csrf", "")
    )

    configuration_public_id = str(
        form.get("configuration_public_id", "")
    )

    approval_statement = str(
        form.get("approval_statement", "")
    ).strip()

    understood = str(
        form.get("understood", "")
    )

    approved_public_ids = {
        str(value)
        for value in form.getlist("approved_case")
    }
    dependent_public_ids = {
        str(value)
        for value in form.getlist("dependent_case")
    }
    cleanup_approved = (
        str(form.get("approve_cleanup", "")) == "yes"
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

        configurations = active_configurations(
            db,
            user.id,
            project["id"],
        )

        cases = enabled_cases(
            db,
            user.id,
            project["id"],
        )

        def reject(message):
            return approval_page(
                request,
                project,
                configurations,
                cases,
                configuration_public_id,
                message,
            )

        if not csrf_valid(
            request,
            submitted_csrf,
        ):
            return reject(
                "Security validation failed."
            )

        if understood != "yes":
            return reject(
                "Confirm that you reviewed the plan."
            )

        if not approval_statement:
            return reject(
                "Enter a short approval statement."
            )

        configuration = owned_configuration(
            db,
            user.id,
            project["id"],
            configuration_public_id,
        )

        if not configuration:
            return reject(
                "Select a valid active configuration."
            )

        snapshots = []
        plan_rows = []

        safe_count = 0
        approved_count = 0
        excluded_count = 0
        destructive_count = 0

        valid_public_ids = {
            case["public_id"]
            for case in cases
        }

        if not approved_public_ids.issubset(
            valid_public_ids
        ) or not dependent_public_ids.issubset(
            valid_public_ids
        ):
            return reject(
                "One or more selected cases are invalid."
            )

        staged = []
        for case in cases:
            destructive = is_destructive(case)

            if destructive:
                destructive_count += 1

            blockers = unresolved_test_data(case)

            if blockers:
                if case["public_id"] in approved_public_ids:
                    return reject(
                        "Resolve mandatory test data before approval: "
                        + blockers[0]
                    )
                if (
                    case["public_id"] in dependent_public_ids
                    and not destructive
                ):
                    decision = "pending-dependent"
                else:
                    decision = "excluded"
                    excluded_count += 1
            elif case["safe_to_execute"]:
                decision = "included-safe"
                safe_count += 1
            elif (
                case["public_id"] in approved_public_ids
                and not destructive
            ):
                decision = "approved"
                approved_count += 1
            else:
                decision = (
                    "blocked-destructive"
                    if destructive
                    else "excluded"
                )
                excluded_count += 1

            staged.append(
                {
                    "case": case,
                    "decision": decision,
                    "destructive": destructive,
                }
            )

        bindable = [
            item["case"]
            for item in staged
            if item["decision"]
            in {"included-safe", "approved", "pending-dependent"}
        ]
        orchestration = build_orchestration(
            bindable,
            cleanup_approved=cleanup_approved,
        )

        for item in staged:
            case = item["case"]
            decision = item["decision"]
            if decision == "pending-dependent":
                if orchestration.producers_for_consumer(
                    case["public_id"]
                ):
                    decision = "approved"
                    approved_count += 1
                    item["decision"] = decision
                else:
                    return reject(
                        "No create step in this plan can supply runtime data for "
                        + str(case["title"])
                    )

            snapshot = case_snapshot(
                case,
                decision,
            )
            if decision in {"included-safe", "approved"}:
                snapshot = apply_orchestration_to_snapshot(
                    snapshot,
                    orchestration,
                    case["public_id"],
                )
                leftover = plan_blockers(
                    {
                        "path": snapshot["endpoint_path"],
                        "headers": snapshot["request_headers"],
                        "query": snapshot["request_query"],
                        "body": snapshot["request_body"],
                    },
                    orchestration,
                    case["public_id"],
                )
                if leftover:
                    return reject(
                        "Resolve mandatory test data before approval: "
                        + leftover[0]
                    )

            snapshots.append(snapshot)
            plan_rows.append(
                {
                    "case": case,
                    "decision": decision,
                    "snapshot": snapshot,
                    "destructive": item["destructive"],
                }
            )

        executable_count = (
            safe_count + approved_count
        )

        if executable_count == 0:
            return reject(
                "The plan must contain at least one executable case."
            )

        plan_public_id = str(uuid.uuid4())
        approved_at = utc_now()

        plan_snapshot = {
            "version": "qafox-execution-plan-v2",
            "project": {
                "public_id": project["public_id"],
                "name": project["name"],
            },
            "configuration": {
                "public_id":
                    configuration["public_id"],
                "name": configuration["name"],
                "environment":
                    configuration["environment"],
                "base_url":
                    configuration["base_url"],
                "request_timeout_seconds":
                    configuration[
                        "request_timeout_seconds"
                    ],
                "retry_count":
                    configuration["retry_count"],
                "verify_tls":
                    bool(configuration["verify_tls"]),
                "safe_mode":
                    bool(configuration["safe_mode"]),
                "allow_destructive_methods":
                    bool(
                        configuration[
                            "allow_destructive_methods"
                        ]
                    ),
                "auth_type":
                    configuration["auth_type"],
                "secrets_included": False,
            },
            "approval": {
                "approved_by_user_id": user.id,
                "approval_statement":
                    approval_statement,
                "approved_at":
                    approved_at.isoformat(),
                "one_run_only": True,
            },
            "cases": snapshots,
            "orchestration": orchestration.to_json(),
        }

        canonical_snapshot = json.dumps(
            plan_snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        fingerprint = hashlib.sha256(
            canonical_snapshot.encode("utf-8")
        ).hexdigest()

        plan_id = db.execute(
            text(
                """
                INSERT INTO api_execution_plans (
                    public_id,
                    project_id,
                    owner_user_id,
                    configuration_id,
                    status,
                    configuration_name,
                    environment,
                    base_url_snapshot,
                    total_case_count,
                    safe_case_count,
                    approved_case_count,
                    excluded_case_count,
                    destructive_case_count,
                    snapshot_json,
                    snapshot_sha256,
                    approval_statement,
                    approved_by_user_id,
                    approved_at,
                    created_at
                )
                VALUES (
                    :public_id,
                    :project_id,
                    :owner_user_id,
                    :configuration_id,
                    'approved',
                    :configuration_name,
                    :environment,
                    :base_url,
                    :total_count,
                    :safe_count,
                    :approved_count,
                    :excluded_count,
                    :destructive_count,
                    :snapshot_json,
                    :snapshot_sha256,
                    :approval_statement,
                    :approved_by_user_id,
                    :approved_at,
                    :created_at
                )
                RETURNING id
                """
            ),
            {
                "public_id": plan_public_id,
                "project_id": project["id"],
                "owner_user_id": user.id,
                "configuration_id":
                    configuration["id"],
                "configuration_name":
                    configuration["name"],
                "environment":
                    configuration["environment"],
                "base_url":
                    configuration["base_url"],
                "total_count": len(cases),
                "safe_count": safe_count,
                "approved_count": approved_count,
                "excluded_count": excluded_count,
                "destructive_count":
                    destructive_count,
                "snapshot_json":
                    canonical_snapshot,
                "snapshot_sha256":
                    fingerprint,
                "approval_statement":
                    approval_statement,
                "approved_by_user_id": user.id,
                "approved_at": approved_at,
                "created_at": approved_at,
            },
        ).scalar_one()

        for item in plan_rows:
            case = item["case"]

            db.execute(
                text(
                    """
                    INSERT INTO api_execution_plan_cases (
                        execution_plan_id,
                        test_case_id,
                        owner_user_id,
                        test_case_public_id,
                        decision,
                        approval_required,
                        safe_to_execute,
                        destructive,
                        case_snapshot,
                        created_at
                    )
                    VALUES (
                        :execution_plan_id,
                        :test_case_id,
                        :owner_user_id,
                        :test_case_public_id,
                        :decision,
                        :approval_required,
                        :safe_to_execute,
                        :destructive,
                        :case_snapshot,
                        :created_at
                    )
                    """
                ),
                {
                    "execution_plan_id": plan_id,
                    "test_case_id": case["id"],
                    "owner_user_id": user.id,
                    "test_case_public_id":
                        case["public_id"],
                    "decision": item["decision"],
                    "approval_required":
                        bool(case["requires_approval"]),
                    "safe_to_execute":
                        bool(case["safe_to_execute"]),
                    "destructive":
                        item["destructive"],
                    "case_snapshot": json.dumps(
                        item["snapshot"],
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "created_at": approved_at,
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
                    'execution-plan-approved',
                    :summary,
                    :created_at
                )
                """
            ),
            {
                "project_id": project["id"],
                "owner_user_id": user.id,
                "summary": (
                    f"Execution plan approved: "
                    f"{executable_count} executable, "
                    f"{excluded_count} excluded. "
                    f"Fingerprint {fingerprint[:12]}."
                ),
                "created_at": approved_at,
            },
        )

        db.commit()

    return RedirectResponse(
        f"/projects/{public_id}/execution-plans/"
        f"{plan_public_id}",
        status_code=303,
    )


@router.get(
    "/projects/{public_id}/execution-plans/{plan_public_id}",
    response_class=HTMLResponse,
)
def execution_plan_detail(
    request: Request,
    public_id: str,
    plan_public_id: str,
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

        rows = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_execution_plan_cases
                    WHERE execution_plan_id = :plan_id
                      AND owner_user_id = :owner_user_id
                    ORDER BY id
                    """
                ),
                {
                    "plan_id": plan["id"],
                    "owner_user_id": user.id,
                },
            )
            .mappings()
            .all()
        )

    case_html = ""

    for row in rows:
        snapshot = safe_json(
            row["case_snapshot"],
            {},
        )

        decision_class = (
            "included"
            if row["decision"] in {
                "included-safe",
                "approved",
            }
            else "excluded"
        )

        case_html += f"""
        <tr>
            <td>{esc(snapshot.get("http_method", ""))}</td>
            <td>
                <strong>{esc(snapshot.get("title", ""))}</strong>
                <code>{esc(snapshot.get("endpoint_path", ""))}</code>
            </td>
            <td>
                <span class="plan-decision {decision_class}">
                    {esc(row["decision"].replace("-", " ").title())}
                </span>
            </td>
            <td>
                {
                    "Yes"
                    if row["approval_required"]
                    else "No"
                }
            </td>
        </tr>
        """

    csrf = csrf_token(request)
    stored_plan = safe_json(plan["snapshot_json"], {})
    orchestration = stored_plan.get("orchestration") or {}
    binding_count = len(orchestration.get("bindings") or [])
    cleanup_note = (
        "Same-run cleanup approved."
        if orchestration.get("cleanup_approved")
        else "Same-run cleanup not approved."
    )
    orchestration_html = (
        f"""
        <p>
            Runtime orchestration: {esc(str(binding_count))} bound dependent
            step(s). {esc(cleanup_note)} Dynamic values are extracted only
            from this run and never guessed.
        </p>
        """
        if binding_count or orchestration.get("cleanup_approved")
        else ""
    )

    content = f"""
<section class="execution-plan-detail">
    <a href="/projects/{esc(public_id)}/test-cases">
        ← Generated test cases
    </a>

    <div class="plan-success-card">
        <div class="plan-success-fox">🦊</div>
        <span>EXECUTION PLAN APPROVED</span>
        <h1>Ready for the hardened runner</h1>
        <p>
            The plan is immutable and approved for one execution only.
            No API request has been executed yet.
        </p>
        {orchestration_html}
    </div>

    <div class="plan-summary-grid">
        <article>
            <strong>{esc(str(plan["safe_case_count"]))}</strong>
            <span>Safe cases</span>
        </article>
        <article>
            <strong>{esc(str(plan["approved_case_count"]))}</strong>
            <span>Explicitly approved</span>
        </article>
        <article>
            <strong>{esc(str(plan["excluded_case_count"]))}</strong>
            <span>Excluded/blocked</span>
        </article>
        <article>
            <strong>{esc(plan["environment"].title())}</strong>
            <span>Environment</span>
        </article>
    </div>

    <section class="plan-information">
        <div>
            <span>Configuration</span>
            <strong>{esc(plan["configuration_name"])}</strong>
        </div>
        <div>
            <span>Target</span>
            <code>{esc(plan["base_url_snapshot"])}</code>
        </div>
        <div>
            <span>Approved by</span>
            <strong>
                {esc(plan["approver_name"])}
                · @{esc(plan["approver_username"])}
            </strong>
        </div>
        <div>
            <span>Approval statement</span>
            <strong>{esc(plan["approval_statement"])}</strong>
        </div>
    </section>

    <section class="plan-fingerprint">
        <span>Immutable plan fingerprint</span>
        <code id="execution-plan-fingerprint">
            {esc(plan["snapshot_sha256"])}
        </code>
        <button type="button"
                class="copy-button"
                data-copy-target="#execution-plan-fingerprint">
            Copy
        </button>
    </section>

    <div class="plan-run-confirmation">
        <strong>Final one-time confirmation</strong>
        <p>
            Enter
            <code>RUN {esc(plan["snapshot_sha256"][:8])}</code>
            to consume this approved plan and begin execution.
        </p>

        <form method="post"
              action="/projects/{esc(public_id)}/execution-plans/{esc(plan_public_id)}/run">

            <input type="hidden"
                   name="csrf"
                   value="{esc(csrf)}">

            <input name="confirmation"
                   required
                   autocomplete="off"
                   placeholder="RUN {esc(plan["snapshot_sha256"][:8])}">

            <button class="primary-button"
                    type="submit">
                Confirm and run once
            </button>
        </form>

        <small>
            Destructive and unresolved state-changing requests remain blocked.
        </small>
    </div>

    <div class="plan-case-table-wrap">
        <table class="plan-case-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Test case</th>
                    <th>Decision</th>
                    <th>Approval required</th>
                </tr>
            </thead>
            <tbody>{case_html}</tbody>
        </table>
    </div>
</section>
"""

    return layout(
        "Approved execution plan",
        content,
        request,
        public=False,
    )
