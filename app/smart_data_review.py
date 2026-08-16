"""Owner-scoped field-level review of persisted adapter contracts."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api_discovery import latest_run, owned_project
from app.main import current_user, engine, esc, layout
from app.smart_data.persistence import load_snapshot

router = APIRouter()


@router.get("/projects/{public_id}/smart-data")
def smart_data_review(
    request: Request,
    public_id: str,
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with Session(engine) as db:
        project = owned_project(db, user.id, public_id)
        if not project:
            return RedirectResponse("/projects", status_code=303)
        run = latest_run(db, user.id, project["id"])
        snapshot = None
        if run:
            snapshot = load_snapshot(
                db,
                owner_user_id=user.id,
                project_id=project["id"],
                discovery_run_id=int(run["id"]),
            )

    if not run:
        return RedirectResponse(f"/projects/{public_id}", status_code=303)

    rows = ""
    if snapshot:
        for route in snapshot.routes:
            request_schema = route.request_schemas[0] if route.request_schemas else None
            field_count = len(request_schema.fields) if request_schema else 0
            auth = ", ".join(
                mode.value
                for flow in route.authentication
                for mode in flow.modes
            ) or "unknown"
            rows += f"""
            <tr>
                <td><span class="http-method {esc(route.method.lower())}">{esc(route.method)}</span></td>
                <td><code>{esc(route.path)}</code></td>
                <td>{esc(route.framework)}</td>
                <td>{esc(auth)}</td>
                <td>{field_count} field(s)</td>
                <td>
                    <a class="case-edit-button"
                       href="/projects/{esc(public_id)}/smart-data/route?method={esc(quote(route.method))}&path={esc(quote(route.path))}">
                        Review fields
                    </a>
                </td>
            </tr>
            """
    if not rows:
        rows = """
        <tr>
            <td colspan="6" class="inventory-empty">
                No adapter contracts were persisted for this discovery run.
                Legacy scanner results remain in the API inventory.
            </td>
        </tr>
        """

    content = f"""
<section class="inventory-shell">
    <div class="inventory-heading">
        <div>
            <a href="/projects/{esc(public_id)}/api-inventory">← API inventory</a>
            <span>SMART DATA REVIEW</span>
            <h1>Adapter contracts</h1>
            <p>
                Field-level evidence from OpenAPI, Postman, FastAPI and Flask
                adapters. Values stay editable in generated test cases.
                Unresolved mandatory placeholders still block execution approval.
            </p>
        </div>
    </div>
    <div class="inventory-table-wrap">
        <table class="inventory-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Adapter</th>
                    <th>Authentication</th>
                    <th>Fields</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
</section>
"""
    return layout("Smart data review", content, request, public=False)


@router.get("/projects/{public_id}/smart-data/route")
def smart_data_route_review(
    request: Request,
    public_id: str,
    method: str = "",
    path: str = "",
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    wanted_path = path if path.startswith("/") else "/" + path

    with Session(engine) as db:
        project = owned_project(db, user.id, public_id)
        if not project:
            return RedirectResponse("/projects", status_code=303)
        run = latest_run(db, user.id, project["id"])
        snapshot = None
        if run:
            snapshot = load_snapshot(
                db,
                owner_user_id=user.id,
                project_id=project["id"],
                discovery_run_id=int(run["id"]),
            )

    if snapshot is None:
        return RedirectResponse(f"/projects/{public_id}/smart-data", status_code=303)

    route = next(
        (
            item
            for item in snapshot.routes
            if item.method.lower() == method.lower()
            and item.path.rstrip("/") == wanted_path.rstrip("/")
        ),
        None,
    )
    if route is None:
        return RedirectResponse(f"/projects/{public_id}/smart-data", status_code=303)

    schema = route.request_schemas[0] if route.request_schemas else None
    field_rows = ""
    if schema:
        for item in schema.fields:
            constraints = ", ".join(
                f"{constraint.name}={constraint.value}"
                for constraint in item.constraints
            ) or "None"
            dependency = (
                f"{item.dependency.resource}.{item.dependency.field}"
                if item.dependency
                else ""
            )
            evidence = item.source_file or (
                item.evidence[0].source_file if item.evidence else ""
            )
            field_rows += f"""
            <tr>
                <td><code>{esc(item.name)}</code></td>
                <td>{esc(item.semantic_type.value)}</td>
                <td>{esc(item.data_type)}</td>
                <td>{"required" if item.required else "optional"}</td>
                <td>{esc(constraints)}</td>
                <td>{esc(str(item.generated_value or ""))}</td>
                <td>{esc(item.generation_strategy or "")}</td>
                <td>{esc(str(item.confidence_score))}</td>
                <td>{esc(evidence)}</td>
                <td>{esc(dependency)}</td>
            </tr>
            """
    if not field_rows:
        field_rows = '<tr><td colspan="10">No request fields were extracted.</td></tr>'

    auth_html = "".join(
        f"<li>{esc(flow.name)} — {esc(', '.join(mode.value for mode in flow.modes))}"
        f"{' (required)' if flow.required else ''}</li>"
        for flow in route.authentication
    ) or "<li>Not declared</li>"
    prereq_html = "".join(
        f"<li>{esc(item.resource)}.{esc(item.field)} "
        f"{esc(item.placeholder or '')} — {esc(item.reason)}</li>"
        for item in route.prerequisites
    ) or "<li>None</li>"
    setup_html = "".join(
        f"<li>{esc(item.kind.value)} {esc(item.name)} → {esc(item.route_reference)}"
        f"{' (approval required)' if item.requires_approval else ''}</li>"
        for item in (*route.setup_actions, *route.cleanup_actions)
    ) or "<li>None</li>"

    content = f"""
<section class="case-editor-shell">
    <a href="/projects/{esc(public_id)}/smart-data">← Adapter contracts</a>
    <span>FIELD-LEVEL REVIEW</span>
    <h1>{esc(route.method)} {esc(route.path)}</h1>
    <p>
        Adapter <strong>{esc(route.framework)}</strong>.
        Content type:
        <strong>{esc(schema.content_type if schema else "") or "not declared"}</strong>.
        Generated request bodies remain editable on each test case.
    </p>
    <div class="smart-evidence-panel">
        <strong>Authentication</strong>
        <ul>{auth_html}</ul>
        <strong>Prerequisites</strong>
        <ul>{prereq_html}</ul>
        <strong>Setup / cleanup</strong>
        <ul>{setup_html}</ul>
    </div>
    <div class="inventory-table-wrap">
        <table class="inventory-table">
            <thead>
                <tr>
                    <th>Field</th>
                    <th>Semantic</th>
                    <th>Type</th>
                    <th>Required</th>
                    <th>Constraints</th>
                    <th>Value</th>
                    <th>Reason</th>
                    <th>Confidence</th>
                    <th>Source</th>
                    <th>Depends on</th>
                </tr>
            </thead>
            <tbody>{field_rows}</tbody>
        </table>
    </div>
    <p>
        <a class="primary-button" href="/projects/{esc(public_id)}/test-cases">
            Edit generated request values
        </a>
    </p>
</section>
"""
    return layout(f"Review {route.method} {route.path}", content, request, public=False)
