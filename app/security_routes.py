"""Owner-scoped security findings UI."""

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.jobs import enqueue_security_run
from app.main import csrf_token, csrf_valid, current_user, engine, esc, layout
from app.security_scanning import scanner_availability

router = APIRouter()


@router.get("/projects/{public_id}/security")
def security_findings_page(request: Request, public_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with Session(engine) as db:
        project = db.execute(
            text(
                """
                SELECT id, name FROM projects
                WHERE public_id = :public_id
                  AND owner_user_id = :owner_user_id
                  AND deleted_at IS NULL
                """
            ),
            {"public_id": public_id, "owner_user_id": user.id},
        ).mappings().first()
        if not project:
            return RedirectResponse("/projects", status_code=303)
        findings = db.execute(
            text(
                """
                SELECT scanner, rule_id, title, severity, category, component,
                       source_file, source_line, evidence, recommendation,
                       confidence, created_at
                FROM security_findings
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                ORDER BY
                  CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                  END,
                  created_at DESC
                LIMIT 1000
                """
            ),
            {"project_id": project["id"], "owner_user_id": user.id},
        ).mappings().all()
        runs = db.execute(
            text(
                """
                SELECT scanner, status, tool_version, error_message, completed_at
                FROM security_scan_runs
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                ORDER BY created_at DESC
                LIMIT 20
                """
            ),
            {"project_id": project["id"], "owner_user_id": user.id},
        ).mappings().all()

    availability = scanner_availability()
    tools = "".join(
        f"<li><strong>{esc(name.title())}</strong>: "
        f"{'available' if available else 'not installed on worker'}</li>"
        for name, available in availability.items()
    )
    rows = "".join(
        f"""
        <tr>
          <td><strong>{esc(item['severity'])}</strong></td>
          <td>{esc(item['scanner'])}</td>
          <td>{esc(item['title'])}<br><small>{esc(item['rule_id'])}</small></td>
          <td>{esc(item['component'])}</td>
          <td>{esc(item['source_file'])}:{esc(str(item['source_line'] or ''))}</td>
          <td>{esc(item['recommendation'])}</td>
        </tr>
        """
        for item in findings
    ) or '<tr><td colspan="6">No persisted security findings yet.</td></tr>'
    run_rows = "".join(
        f"<li><strong>{esc(item['scanner'])}</strong> — {esc(item['status'])} "
        f"<small>{esc(item['tool_version'])} {esc(item['error_message'])}</small></li>"
        for item in runs
    ) or "<li>No security scans have run.</li>"
    content = f"""
    <section class="dashboard-shell">
      <a href="/projects/{esc(public_id)}">← Project overview</a>
      <h1>Security findings · {esc(project['name'])}</h1>
      <p>Normalized SAST, dependency, configuration, and secret findings.</p>
      <form method="post" action="/projects/{esc(public_id)}/security/run">
        <input type="hidden" name="csrf" value="{esc(csrf_token(request))}">
        <button class="primary-button" type="submit">Queue static security scan</button>
      </form>
      <h2>Scanner availability</h2><ul>{tools}</ul>
      <h2>Recent scans</h2><ul>{run_rows}</ul>
      <div class="table-wrap"><table>
        <thead><tr><th>Severity</th><th>Scanner</th><th>Finding</th><th>Component</th><th>Location</th><th>Recommendation</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
    </section>
    """
    return layout("Security findings", content, request, public=False)


@router.post("/projects/{public_id}/security/run")
def queue_security_scan(request: Request, public_id: str, csrf: str = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not csrf_valid(request, csrf):
        return RedirectResponse(
            f"/projects/{public_id}/security", status_code=303
        )
    with Session(engine) as db:
        project_id = db.execute(
            text(
                """
                SELECT id FROM projects
                WHERE public_id = :public_id
                  AND owner_user_id = :owner_user_id
                  AND deleted_at IS NULL
                """
            ),
            {"public_id": public_id, "owner_user_id": user.id},
        ).scalar()
        if not project_id:
            return RedirectResponse("/projects", status_code=303)
        enqueue_security_run(
            db, project_id=int(project_id), owner_user_id=user.id
        )
    return RedirectResponse(
        f"/projects/{public_id}/security", status_code=303
    )
