import hashlib
import json
import os
import shutil
import stat
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml
from fastapi import (
    APIRouter,
    File,
    Form,
    Request,
    UploadFile,
)
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    RedirectResponse,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)
from app.project_ingestion import IngestionRejected, ingest_git_repository
from app.technology_detection import detect_technologies, persist_technology_report

router = APIRouter()

settings = get_settings()
PROJECT_ROOT = settings.project_root
STAGING_ROOT = settings.staging_root

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_SINGLE_ENTRY_BYTES = 150 * 1024 * 1024
MAX_COMPRESSION_RATIO = 150

ALLOWED_ENVIRONMENTS = {
    "development",
    "testing",
    "staging",
    "production",
}

TEXT_API_SUFFIXES = {
    ".json",
    ".yaml",
    ".yml",
}

ARCHIVE_SUFFIXES = {
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
}

IGNORED_ARCHIVE_NAMES = {
    ".DS_Store",
    "Thumbs.db",
}


class UploadRejected(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def human_size(value: int | None) -> str:
    size = float(value or 0)

    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024

    return f"{size:.1f} GB"


def safe_filename(filename: str | None) -> str:
    cleaned = Path(filename or "project-upload").name
    cleaned = "".join(
        character
        if (
            character.isalnum()
            or character in "._- ()"
        )
        else "_"
        for character in cleaned
    ).strip(" .")

    if not cleaned:
        cleaned = "project-upload"

    return cleaned[:220]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_file_type(filename: str) -> str:
    lower = filename.lower()

    if lower.endswith(".tar.gz"):
        return "tar.gz"

    if lower.endswith(".tgz"):
        return "tgz"

    if lower.endswith(".zip"):
        return "zip"

    if lower.endswith(".tar"):
        return "tar"

    if lower.endswith(".json"):
        return "json"

    if lower.endswith(".yaml"):
        return "yaml"

    if lower.endswith(".yml"):
        return "yml"

    raise UploadRejected(
        "Unsupported file type. Upload ZIP, TAR, TAR.GZ, "
        "TGZ, JSON, YAML or YML."
    )


def safe_relative_path(member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")

    if "\x00" in normalized:
        raise UploadRejected(
            "Archive contains an invalid null-byte path."
        )

    pure = PurePosixPath(normalized)

    if pure.is_absolute():
        raise UploadRejected(
            "Archive contains an absolute path."
        )

    parts = [
        part
        for part in pure.parts
        if part not in ("", ".")
    ]

    if (
        not parts
        or any(part == ".." for part in parts)
        or any(":" in part for part in parts)
    ):
        raise UploadRejected(
            "Archive contains an unsafe traversal path."
        )

    return Path(*parts)


def ensure_inside(
    destination_root: Path,
    candidate: Path,
) -> None:
    root = destination_root.resolve()
    resolved = candidate.resolve()

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise UploadRejected(
            "Archive attempted to write outside its workspace."
        ) from exc


async def save_upload(
    upload: UploadFile,
    destination: Path,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination.open("wb") as output:
        while True:
            chunk = await upload.read(1024 * 1024)

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_UPLOAD_BYTES:
                raise UploadRejected(
                    "Upload exceeds the 100 MB limit."
                )

            digest.update(chunk)
            output.write(chunk)

    if total == 0:
        raise UploadRejected(
            "The uploaded file is empty."
        )

    return total, digest.hexdigest()


def validate_json_or_yaml(
    source: Path,
    file_type: str,
    extracted_root: Path,
) -> tuple[int, int, str]:
    if source.stat().st_size > 25 * 1024 * 1024:
        raise UploadRejected(
            "API-definition documents must be 25 MB or smaller."
        )

    try:
        with source.open(
            "r",
            encoding="utf-8",
            errors="strict",
        ) as handle:
            if file_type == "json":
                document = json.load(handle)
            else:
                document = yaml.safe_load(handle)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        raise UploadRejected(
            "The API definition is not valid JSON or YAML."
        ) from exc

    if not isinstance(document, dict):
        raise UploadRejected(
            "The API definition must contain an object document."
        )

    detected = "API definition"

    if (
        "openapi" in document
        or "swagger" in document
    ):
        detected = "OpenAPI/Swagger document"
    elif "info" in document and "item" in document:
        detected = "Postman collection"
    elif "paths" in document:
        detected = "API paths document"

    extracted_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = (
        extracted_root
        / safe_filename(source.name)
    )

    shutil.copy2(source, destination)

    return (
        1,
        source.stat().st_size,
        detected,
    )


def inspect_and_extract_zip(
    source: Path,
    destination_root: Path,
) -> tuple[int, int, str]:
    total_uncompressed = 0
    entry_count = 0

    try:
        archive = zipfile.ZipFile(source)
    except zipfile.BadZipFile as exc:
        raise UploadRejected(
            "The ZIP archive is invalid or corrupted."
        ) from exc

    with archive:
        members = archive.infolist()

        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise UploadRejected(
                "Archive contains too many entries."
            )

        for member in members:
            member_path = safe_relative_path(
                member.filename
            )

            if member_path.name in IGNORED_ARCHIVE_NAMES:
                continue

            unix_mode = member.external_attr >> 16

            if stat.S_ISLNK(unix_mode):
                # Never follow or extract archive symlinks.
                # Skipping preserves upload safety while allowing
                # legitimate source archives containing links.
                continue

            if member.is_dir():
                continue

            entry_count += 1
            total_uncompressed += member.file_size

            if member.file_size > MAX_SINGLE_ENTRY_BYTES:
                raise UploadRejected(
                    "Archive contains an oversized file."
                )

            if total_uncompressed > MAX_EXTRACTED_BYTES:
                raise UploadRejected(
                    "Archive expands beyond the 500 MB limit."
                )

            if member.compress_size == 0:
                if member.file_size > 1024 * 1024:
                    raise UploadRejected(
                        "Archive has a suspicious compression ratio."
                    )
            else:
                ratio = (
                    member.file_size
                    / member.compress_size
                )

                if ratio > MAX_COMPRESSION_RATIO:
                    raise UploadRejected(
                        "Archive has a suspicious compression ratio."
                    )

            destination = (
                destination_root / member_path
            )

            ensure_inside(
                destination_root,
                destination,
            )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(member, "r") as source_file:
                with destination.open("wb") as output:
                    shutil.copyfileobj(
                        source_file,
                        output,
                        length=1024 * 1024,
                    )

            os.chmod(destination, 0o600)

    if entry_count == 0:
        raise UploadRejected(
            "Archive does not contain any files."
        )

    return (
        entry_count,
        total_uncompressed,
        "ZIP project archive",
    )


def inspect_and_extract_tar(
    source: Path,
    destination_root: Path,
) -> tuple[int, int, str]:
    total_uncompressed = 0
    entry_count = 0

    try:
        archive = tarfile.open(source, mode="r:*")
    except tarfile.TarError as exc:
        raise UploadRejected(
            "The TAR archive is invalid or corrupted."
        ) from exc

    with archive:
        members = archive.getmembers()

        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise UploadRejected(
                "Archive contains too many entries."
            )

        for member in members:
            member_path = safe_relative_path(
                member.name
            )

            if member_path.name in IGNORED_ARCHIVE_NAMES:
                continue

            if member.issym() or member.islnk():
                # TAR symbolic and hard links are never followed
                # or extracted into the private workspace.
                continue

            if member.isdev() or member.isfifo():
                raise UploadRejected(
                    "Archive device and FIFO entries are not allowed."
                )

            if member.isdir():
                continue

            if not member.isfile():
                raise UploadRejected(
                    "Archive contains an unsupported entry type."
                )

            entry_count += 1
            total_uncompressed += member.size

            if member.size > MAX_SINGLE_ENTRY_BYTES:
                raise UploadRejected(
                    "Archive contains an oversized file."
                )

            if total_uncompressed > MAX_EXTRACTED_BYTES:
                raise UploadRejected(
                    "Archive expands beyond the 500 MB limit."
                )

            destination = (
                destination_root / member_path
            )

            ensure_inside(
                destination_root,
                destination,
            )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            source_file = archive.extractfile(member)

            if source_file is None:
                raise UploadRejected(
                    "Archive member could not be read."
                )

            with source_file:
                with destination.open("wb") as output:
                    shutil.copyfileobj(
                        source_file,
                        output,
                        length=1024 * 1024,
                    )

            os.chmod(destination, 0o600)

    if entry_count == 0:
        raise UploadRejected(
            "Archive does not contain any files."
        )

    return (
        entry_count,
        total_uncompressed,
        "TAR project archive",
    )


def inspect_project_upload(
    source: Path,
    file_type: str,
    extracted_root: Path,
) -> tuple[int, int, str]:
    extracted_root.mkdir(
        parents=True,
        exist_ok=True,
    )
    os.chmod(extracted_root, 0o700)

    if file_type == "zip":
        return inspect_and_extract_zip(
            source,
            extracted_root,
        )

    if file_type in {"tar", "tar.gz", "tgz"}:
        return inspect_and_extract_tar(
            source,
            extracted_root,
        )

    return validate_json_or_yaml(
        source,
        file_type,
        extracted_root,
    )


def project_for_owner(
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


def owned_storage_directory(
    owner_user_id: int,
    public_id: str,
    storage_directory: str | None,
) -> Path | None:
    expected = (
        PROJECT_ROOT / str(owner_user_id) / public_id
    ).resolve()

    try:
        expected.relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return None

    if storage_directory:
        actual = Path(storage_directory).resolve()
        if actual != expected:
            return None

    return expected


def remove_owned_project_files(
    owner_user_id: int,
    public_id: str,
    storage_directory: str | None,
) -> None:
    project_directory = owned_storage_directory(
        owner_user_id,
        public_id,
        storage_directory,
    )

    if project_directory and project_directory.is_dir():
        shutil.rmtree(project_directory, ignore_errors=True)

    staging_directory = (
        STAGING_ROOT / str(owner_user_id) / public_id
    ).resolve()

    try:
        staging_directory.relative_to(STAGING_ROOT.resolve())
    except ValueError:
        return

    if staging_directory.is_dir():
        shutil.rmtree(staging_directory, ignore_errors=True)


def status_badge(status: str) -> str:
    css_class = (
        "ready"
        if status == "ready"
        else "failed"
    )

    return (
        f'<span class="project-status {css_class}">'
        f'{esc(status.title())}'
        "</span>"
    )


@router.get("/projects")
def project_list(
    request: Request,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with Session(engine) as db:
        projects = (
            db.execute(
                text(
                    """
                    SELECT
                        public_id,
                        name,
                        environment,
                        original_filename,
                        file_type,
                        file_size_bytes,
                        archive_entry_count,
                        status,
                        created_at
                    FROM projects
                    WHERE owner_user_id = :owner_user_id
                      AND deleted_at IS NULL
                    ORDER BY created_at DESC
                    """
                ),
                {"owner_user_id": user.id},
            )
            .mappings()
            .all()
        )

    if projects:
        cards = "".join(
            f"""
            <article class="project-card">
                <div class="project-card-top">
                    <div class="project-file-icon">📦</div>
                    {status_badge(project["status"])}
                </div>

                <h3>{esc(project["name"])}</h3>

                <p>{esc(project["original_filename"])}</p>

                <div class="project-meta">
                    <span>
                        {esc(project["file_type"].upper())}
                    </span>
                    <span>
                        {esc(human_size(project["file_size_bytes"]))}
                    </span>
                    <span>
                        {esc(project["environment"].title())}
                    </span>
                </div>

                <div class="project-card-actions">
                    <a href="/projects/{esc(project["public_id"])}">
                        Open private project →
                    </a>
                    <a class="project-delete-link"
                       href="/projects/{esc(project["public_id"])}/delete">
                        Delete
                    </a>
                </div>
            </article>
            """
            for project in projects
        )
    else:
        cards = """
        <div class="project-empty">
            <div>🦊</div>
            <h2>No private projects yet</h2>
            <p>
                Upload your first project archive, OpenAPI document
                or Postman collection.
            </p>
            <a class="primary-button" href="/projects/new">
                Upload first project
            </a>
        </div>
        """

    notice = (
        f'<div class="message">{esc(message)}</div>'
        if message
        else ""
    )

    content = f"""
<section class="projects-shell">
    <div class="projects-heading">
        <div>
            <span>PRIVATE PROJECT WORKSPACE</span>
            <h1>Your projects</h1>
            <p>
                Only your authenticated account can access these
                project records and files.
            </p>
        </div>

        <a class="primary-button"
           href="/projects/new">
            + New private project
        </a>
    </div>

    {notice}

    <div class="project-grid">
        {cards}
    </div>
</section>
"""

    return layout(
        "Private projects",
        content,
        request,
        public=False,
    )



@router.get("/api-testing/support")
def api_testing_support_page(
    request: Request,
):
    """
    Same-origin, read-only information panel used by the
    API project-upload screen.

    This page contains no project data and performs no
    state-changing operation.
    """
    return HTMLResponse(
        """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>QAFox API Testing Support</title>

<style>
:root {
    color-scheme: light;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 24px;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    background:
        linear-gradient(
            180deg,
            #fbfbff 0%,
            #ffffff 100%
        );
    color: #252735;
    line-height: 1.55;
}

.support-wrap {
    max-width: 1100px;
    margin: 0 auto;
}

.hero {
    border: 1px solid #e6e2f5;
    border-radius: 20px;
    padding: 22px;
    background: #ffffff;
    margin-bottom: 18px;
}

.kicker {
    display: inline-block;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: .08em;
    color: #5b3db5;
    margin-bottom: 8px;
}

h1 {
    margin: 0 0 8px;
    font-size: clamp(22px, 4vw, 30px);
    line-height: 1.2;
}

h2 {
    margin: 0 0 10px;
    font-size: 18px;
}

p {
    margin: 6px 0 12px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.card {
    border: 1px solid #e8e8ef;
    border-radius: 18px;
    padding: 18px;
    background: #ffffff;
}

.card.full {
    grid-column: 1 / -1;
}

.items {
    display: grid;
    gap: 7px;
}

.item {
    display: flex;
    gap: 8px;
    align-items: flex-start;
}

.ok {
    color: #176c43;
    font-weight: 800;
}

.partial {
    color: #896500;
    font-weight: 800;
}

.planned {
    color: #6e7280;
    font-weight: 800;
}

.warn {
    color: #a23a2a;
    font-weight: 800;
}

.flow {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 7px;
    margin-top: 12px;
}

.flow span {
    border: 1px solid #dfd9f1;
    border-radius: 999px;
    padding: 8px 11px;
    background: #f8f6ff;
    font-size: 13px;
    font-weight: 700;
}

.flow b {
    color: #6a50b5;
}

.notice {
    border-left: 4px solid #6850ad;
    background: #f8f6ff;
    padding: 14px 16px;
    border-radius: 10px;
}

.limitations {
    border-color: #f0d8cf;
    background: #fffdfc;
}

.frameworks {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 8px;
}

.framework {
    border: 1px solid #eceaf2;
    border-radius: 12px;
    padding: 10px 12px;
    background: #fafafe;
}

code {
    overflow-wrap: anywhere;
}

@media (max-width: 720px) {
    body {
        padding: 14px;
    }

    .grid,
    .frameworks {
        grid-template-columns: 1fr;
    }

    .hero,
    .card {
        padding: 15px;
        border-radius: 15px;
    }
}
</style>
</head>

<body>

<main class="support-wrap">

<section class="hero">
    <span class="kicker">
        QAFox · UNIVERSAL API TESTING
    </span>

    <h1>
        Before you upload your project
    </h1>

    <p>
        QAFox inspects your uploaded project or API definition,
        discovers APIs, creates smart test scenarios and data,
        executes approved API requests, validates responses and
        produces QA test results.
    </p>

    <div class="notice">
        <strong>Important:</strong>
        uploaded application source code is inspected as evidence
        only. QAFox does not execute your uploaded source code.
    </div>
</section>


<div class="grid">

<section class="card">
    <h2>📦 Supported uploads</h2>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            ZIP project archive
        </div>

        <div class="item">
            <span class="ok">✓</span>
            TAR / TAR.GZ / TGZ
        </div>

        <div class="item">
            <span class="ok">✓</span>
            OpenAPI / Swagger JSON
        </div>

        <div class="item">
            <span class="ok">✓</span>
            OpenAPI / Swagger YAML
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Postman Collection
        </div>
    </div>

    <p>
        Current project upload limit:
        <strong>100 MB</strong>.
    </p>
</section>


<section class="card">
    <h2>🧩 Supported REST sources</h2>

    <div class="frameworks">
        <div class="framework">✓ OpenAPI / Swagger</div>
        <div class="framework">✓ Postman</div>
        <div class="framework">✓ FastAPI</div>
        <div class="framework">✓ Flask</div>
        <div class="framework">✓ Django / DRF</div>
        <div class="framework">✓ Express.js</div>
        <div class="framework">✓ NestJS</div>
        <div class="framework">✓ Spring Boot</div>
        <div class="framework">✓ Laravel</div>
        <div class="framework">✓ ASP.NET Core</div>
    </div>

    <p>
        Discovery depth can vary because frameworks and projects
        may define routes, validation and middleware differently.
    </p>
</section>


<section class="card full">
    <h2>🧪 What QAFox currently tests</h2>

    <div class="frameworks">

        <div class="item">
            <span class="ok">✓</span>
            API endpoint and HTTP method discovery
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Path and query parameters
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Request headers and bodies
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Request schemas and validation constraints
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Positive API scenarios
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Negative API scenarios
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Required-field scenarios
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Boundary-value scenarios
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Invalid types and enum values
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Authentication-related scenarios
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Response status assertions
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Response schema assertions
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Stack-trace and secret-leak checks
        </div>

        <div class="item">
            <span class="ok">✓</span>
            API duration checks
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Dependency-aware workflows
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Runtime value capture
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Root-cause classification
        </div>

        <div class="item">
            <span class="ok">✓</span>
            HTML and JSON QA reports
        </div>

    </div>
</section>


<section class="card">
    <h2>🧠 Smart Test Data</h2>

    <p>
        QAFox does not use one fixed data set for every project.
        Test data is created from discovered schemas, constraints
        and field meaning.
    </p>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            email → generated email
        </div>

        <div class="item">
            <span class="ok">✓</span>
            UUID → generated UUID
        </div>

        <div class="item">
            <span class="ok">✓</span>
            enum → documented valid value
        </div>

        <div class="item">
            <span class="ok">✓</span>
            numeric fields → constraint-aware values
        </div>

        <div class="item">
            <span class="ok">✓</span>
            required fields → populated
        </div>

        <div class="item">
            <span class="ok">✓</span>
            nested objects and arrays
        </div>
    </div>

    <p>
        Credentials and production tokens are not invented.
        Authentication values must come from secure test
        configuration.
    </p>
</section>


<section class="card">
    <h2>🔗 API workflow intelligence</h2>

    <p>
        QAFox can connect APIs when one API needs data returned
        from another.
    </p>

    <div class="flow">
        <span>Create Customer</span>
        <b>→</b>
        <span>Customer ID</span>
        <b>→</b>
        <span>Create Order</span>
        <b>→</b>
        <span>Order ID</span>
        <b>→</b>
        <span>Get Order</span>
    </div>

    <p>
        If a required dependency cannot be determined safely,
        QAFox should report it instead of inventing a production
        identifier.
    </p>
</section>


<section class="card">
    <h2>🛡️ Safe execution</h2>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            Read-only APIs can be classified as safe
        </div>

        <div class="item">
            <span class="ok">✓</span>
            State-changing APIs require approval
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Destructive APIs are blocked by default
        </div>

        <div class="item">
            <span class="ok">✓</span>
            TLS verification remains enabled
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Private, loopback and unsafe targets are blocked
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Secrets are masked
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Approved execution plans are snapshotted
        </div>
    </div>
</section>


<section class="card">
    <h2>📊 Test results</h2>

    <p>
        After execution, QAFox can report information such as:
    </p>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            APIs discovered
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Test scenarios generated
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Passed / Failed / Skipped / Error
        </div>

        <div class="item">
            <span class="ok">✓</span>
            HTTP response status
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Execution duration
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Assertion results
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Dependency failures
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Root-cause information
        </div>

        <div class="item">
            <span class="ok">✓</span>
            HTML report
        </div>

        <div class="item">
            <span class="ok">✓</span>
            JSON report
        </div>
    </div>
</section>


<section class="card full limitations">
    <h2>⚠️ Important limitations</h2>

    <div class="items">

        <div class="item">
            <span class="warn">!</span>
            QAFox cannot guarantee that static source inspection
            will discover 100% of APIs in every possible project.
        </div>

        <div class="item">
            <span class="warn">!</span>
            APIs created dynamically only while an application is
            running may not be visible from source files.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Custom or proprietary frameworks may have limited
            source-code discovery.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Route discovery can be available even when complete
            validation or response-schema evidence is unavailable.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Interactive browser authentication, external identity
            providers and MFA may require manual configuration.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Destructive API operations are not automatically run.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Current security assertions are not a replacement for
            full penetration testing or vulnerability scanning.
        </div>

        <div class="item">
            <span class="warn">!</span>
            Current performance checks measure request duration;
            full load, stress and endurance testing belong to the
            future QAFox Performance Testing module.
        </div>

    </div>
</section>


<section class="card">
    <h2>🌐 Protocol support</h2>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            REST APIs — Supported
        </div>

        <div class="item">
            <span class="planned">○</span>
            GraphQL — Planned
        </div>

        <div class="item">
            <span class="planned">○</span>
            gRPC — Planned
        </div>

        <div class="item">
            <span class="planned">○</span>
            SOAP / WSDL — Planned
        </div>

        <div class="item">
            <span class="planned">○</span>
            WebSocket — Planned
        </div>

        <div class="item">
            <span class="planned">○</span>
            AsyncAPI — Planned
        </div>
    </div>
</section>


<section class="card">
    <h2>📁 For best results</h2>

    <p>
        Upload the complete backend API project whenever possible.
    </p>

    <div class="items">
        <div class="item">
            <span class="ok">✓</span>
            Route/controller files
        </div>

        <div class="item">
            <span class="ok">✓</span>
            DTOs / request-response models
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Validation definitions
        </div>

        <div class="item">
            <span class="ok">✓</span>
            OpenAPI / Swagger when available
        </div>

        <div class="item">
            <span class="ok">✓</span>
            Postman Collection when available
        </div>

        <div class="item">
            <span class="warn">!</span>
            Do not upload production secrets, private keys,
            passwords or credential files.
        </div>
    </div>
</section>


<section class="card full">
    <h2>🚀 What happens after upload?</h2>

    <div class="flow">
        <span>1. Upload</span>
        <b>→</b>
        <span>2. Discover APIs</span>
        <b>→</b>
        <span>3. Configure</span>
        <b>→</b>
        <span>4. Generate Tests</span>
        <b>→</b>
        <span>5. Smart Data</span>
        <b>→</b>
        <span>6. Dependencies</span>
        <b>→</b>
        <span>7. Approve</span>
        <b>→</b>
        <span>8. Execute</span>
        <b>→</b>
        <span>9. QA Report</span>
    </div>

    <p>
        QAFox may mark inferred information as high confidence,
        medium confidence or review required. QAFox should show
        uncertainty instead of pretending an uncertain inference
        is definitely correct.
    </p>
</section>

</div>

</main>

</body>
</html>
"""
    )



@router.get("/projects/new")
def new_project_page(
    request: Request,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    csrf = csrf_token(request)

    notice = (
        f'<div class="message error">{esc(message)}</div>'
        if message
        else ""
    )

    content = f"""

<section class="api-upload-guidance"
         aria-labelledby="api-upload-guidance-title">

    <div class="api-upload-guidance-head">

        <div>
            <span class="pill">
                UNIVERSAL API TESTING
            </span>

            <h1 id="api-upload-guidance-title">
                Before you upload — Supported Features &amp; Limitations
            </h1>

            <p>
                Understand what QAFox can discover, test and report
                before adding your source project.
            </p>
        </div>

        <button type="button"
                class="secondary-button api-guidance-toggle"
                data-api-guidance-toggle
                aria-expanded="true"
                aria-controls="api-testing-support-frame-wrap">
            Hide details
        </button>

    </div>

    <div id="api-testing-support-frame-wrap"
         class="api-support-frame-wrap">

        <iframe
            src="/api-testing/support"
            title="QAFox API Testing supported features and limitations"
            class="api-support-frame"
            loading="eager">
        </iframe>

    </div>

    <div class="api-guidance-action">

        <button type="button"
                class="primary-button"
                data-api-upload-continue>
            I understand — Continue to Project Upload
        </button>

    </div>

</section>

<section class="upload-shell">
    <div class="upload-info">
        <span class="pill">PRIVATE UPLOAD</span>
        <div class="upload-fox">🦊</div>
        <h1>Bring your project to Qubi.</h1>
        <p>
            QAFox validates the file, checks archive safety and
            stores it inside your private account workspace.
        </p>

        <div class="upload-security-list">
            <span>✓ 100 MB upload limit</span>
            <span>✓ Path traversal blocked</span>
            <span>✓ Archive bombs blocked</span>
            <span>✓ Symlinks safely skipped</span>
            <span>✓ Device and FIFO entries blocked</span>
            <span>✓ Uploaded code is not executed</span>
            <span>✓ Strict account ownership checks</span>
        </div>
    </div>

    <form class="upload-form"
          method="post"
          action="/projects/new"
          enctype="multipart/form-data">

        <span class="auth-kicker">
            PHASE 1 · API TESTING
        </span>
        <h2>Create private project</h2>
        <p>
            Upload an archive/API definition or fetch a public HTTPS Git repository.
        </p>

        {notice}

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <label>
            Project name
            <input name="project_name"
                   required
                   minlength="2"
                   maxlength="160"
                   placeholder="Example: Customer API">
        </label>

        <label>
            Description <small>Optional</small>
            <textarea name="description"
                      maxlength="1500"
                      rows="3"
                      placeholder="What does this project contain?"></textarea>
        </label>

        <label>
            Target environment
            <select name="environment">
                <option value="development">
                    Development
                </option>
                <option value="testing" selected>
                    Testing
                </option>
                <option value="staging">
                    Staging
                </option>
                <option value="production">
                    Production
                </option>
            </select>
        </label>

        <label>
            Project source
            <select name="source_type">
                <option value="upload" selected>File upload</option>
                <option value="git">Git repository</option>
            </select>
        </label>

        <label>
            HTTPS Git repository <small>Required for Git source</small>
            <input name="repository_url"
                   maxlength="1000"
                   placeholder="https://github.com/organization/repository.git">
        </label>

        <label>
            Git branch
            <input name="default_branch"
                   maxlength="200"
                   value="main">
        </label>

        <label class="file-drop">
            <input type="file"
                   name="project_file"
                   accept=".zip,.tar,.gz,.tgz,.json,.yaml,.yml">

            <span class="file-drop-icon">⇧</span>
            <strong>Choose project file</strong>
            <small>
                ZIP, TAR, TAR.GZ, TGZ, JSON, YAML or YML
            </small>
            <small>Maximum 100 MB</small>
        </label>

        <label class="checkbox upload-consent">
            <input type="checkbox"
                   name="upload_confirmation"
                   value="yes"
                   required>
            <span>
                I am authorized to upload and test this project.
            </span>
        </label>

        <button class="primary-button full"
                type="submit">
            Upload to private workspace
        </button>

        <a class="cancel-link"
           href="/projects">
            Cancel
        </a>
    </form>
</section>
"""

    return layout(
        "New private project",
        content,
        request,
        public=False,
    )


@router.post("/projects/new")
async def create_project(
    request: Request,
    project_name: str = Form(...),
    description: str = Form(""),
    environment: str = Form("testing"),
    source_type: str = Form("upload"),
    repository_url: str = Form(""),
    default_branch: str = Form("main"),
    upload_confirmation: str = Form(""),
    csrf: str = Form(...),
    project_file: UploadFile | None = File(None),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/projects/new?"
            "message=Your+session+expired.+Please+try+again.",
            status_code=303,
        )

    project_name = project_name.strip()
    description = description.strip()
    environment = environment.strip().lower()
    source_type = source_type.strip().lower()

    if len(project_name) < 2:
        return RedirectResponse(
            "/projects/new?"
            "message=Enter+a+valid+project+name.",
            status_code=303,
        )

    if environment not in ALLOWED_ENVIRONMENTS:
        return RedirectResponse(
            "/projects/new?"
            "message=Choose+a+valid+environment.",
            status_code=303,
        )

    if source_type not in {"upload", "git"}:
        return RedirectResponse(
            "/projects/new?message=Choose+a+valid+project+source.",
            status_code=303,
        )

    if source_type == "upload" and (
        project_file is None or not project_file.filename
    ):
        return RedirectResponse(
            "/projects/new?message=Choose+a+project+file.",
            status_code=303,
        )

    if upload_confirmation != "yes":
        return RedirectResponse(
            "/projects/new?"
            "message=Confirm+that+you+are+authorized+to+upload+the+project.",
            status_code=303,
        )

    original_filename = (
        safe_filename(project_file.filename)
        if source_type == "upload" and project_file is not None
        else "repository-source.tar"
    )
    public_id = str(uuid.uuid4())
    staging_directory = (
        STAGING_ROOT
        / str(user.id)
        / public_id
    )
    project_directory = (
        PROJECT_ROOT
        / str(user.id)
        / public_id
    )

    staging_file = (
        staging_directory
        / original_filename
    )

    try:
        commit_sha = None
        normalized_repository_url = None
        normalized_branch = None
        if source_type == "git":
            git_result = ingest_git_repository(
                repository_url,
                default_branch,
                staging_directory,
                timeout_seconds=settings.git_timeout_seconds,
            )
            normalized_repository_url = git_result.repository_url
            normalized_branch = git_result.branch
            commit_sha = git_result.commit_sha
            staging_file = git_result.archive_path
            original_filename = "repository-source.tar"
            file_type = "tar"
            file_size = staging_file.stat().st_size
            sha256 = sha256_file(staging_file)
        else:
            file_type = detect_file_type(original_filename)
            staging_directory.mkdir(parents=True, exist_ok=False)
            os.chmod(staging_directory, 0o700)
            file_size, sha256 = await save_upload(project_file, staging_file)

        original_directory = (
            project_directory / "original"
        )
        extracted_directory = (
            project_directory / "source"
        )

        original_directory.mkdir(
            parents=True,
            exist_ok=False,
        )
        os.chmod(project_directory, 0o700)
        os.chmod(original_directory, 0o700)

        stored_file = (
            original_directory
            / original_filename
        )

        shutil.move(
            str(staging_file),
            str(stored_file),
        )
        os.chmod(stored_file, 0o600)

        (
            entry_count,
            extracted_size,
            detected_description,
        ) = inspect_project_upload(
            stored_file,
            file_type,
            extracted_directory,
        )

        shutil.rmtree(
            staging_directory,
            ignore_errors=True,
        )

        now = utc_now()

        with Session(engine) as db:
            result = db.execute(
                text(
                    """
                    INSERT INTO projects (
                        public_id,
                        owner_user_id,
                        name,
                        description,
                        environment,
                        original_filename,
                        stored_filename,
                        storage_directory,
                        file_type,
                        content_type,
                        file_size_bytes,
                        sha256,
                        archive_entry_count,
                        extracted_size_bytes,
                        status,
                        status_message,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        :public_id,
                        :owner_user_id,
                        :name,
                        :description,
                        :environment,
                        :original_filename,
                        :stored_filename,
                        :storage_directory,
                        :file_type,
                        :content_type,
                        :file_size_bytes,
                        :sha256,
                        :archive_entry_count,
                        :extracted_size_bytes,
                        'ready',
                        :status_message,
                        :created_at,
                        :updated_at
                    )
                    RETURNING id
                    """
                ),
                {
                    "public_id": public_id,
                    "owner_user_id": user.id,
                    "name": project_name,
                    "description": description or None,
                    "environment": environment,
                    "original_filename": original_filename,
                    "stored_filename": original_filename,
                    "storage_directory": str(
                        project_directory
                    ),
                    "file_type": file_type,
                    "content_type": (
                        (project_file.content_type or "application/octet-stream")
                        if project_file is not None and source_type == "upload"
                        else "application/x-tar"
                    )[:150],
                    "file_size_bytes": file_size,
                    "sha256": sha256,
                    "archive_entry_count": entry_count,
                    "extracted_size_bytes": extracted_size,
                    "status_message": (
                        f"{detected_description} validated. "
                        "Uploaded code has not been executed."
                    ),
                    "created_at": now,
                    "updated_at": now,
                },
            )

            project_id = result.scalar_one()

            db.execute(
                text(
                    """
                    INSERT INTO project_sources (
                        project_id, owner_user_id, source_type,
                        repository_url, default_branch, commit_sha,
                        authorization_confirmed_at,
                        authorization_confirmed_by, created_at
                    ) VALUES (
                        :project_id, :owner_user_id, :source_type,
                        :repository_url, :default_branch, :commit_sha,
                        :confirmed_at, :confirmed_by, :created_at
                    )
                    """
                ),
                {
                    "project_id": project_id,
                    "owner_user_id": user.id,
                    "source_type": source_type,
                    "repository_url": normalized_repository_url,
                    "default_branch": normalized_branch,
                    "commit_sha": commit_sha,
                    "confirmed_at": now,
                    "confirmed_by": user.id,
                    "created_at": now,
                },
            )

            technology_report = detect_technologies(extracted_directory)
            persist_technology_report(
                db,
                project_id=project_id,
                owner_user_id=user.id,
                source_sha256=sha256,
                report=technology_report,
                commit=False,
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
                        :event_type,
                        :event_summary,
                        :created_at
                    )
                    """
                ),
                {
                    "project_id": project_id,
                    "owner_user_id": user.id,
                    "event_type": (
                        "project-repository-ingested"
                        if source_type == "git"
                        else "project-uploaded"
                    ),
                    "event_summary": (
                        "Project source passed static ingestion and archive safety validation."
                    ),
                    "created_at": now,
                },
            )

            db.commit()

    except (UploadRejected, IngestionRejected) as exc:
        shutil.rmtree(
            staging_directory,
            ignore_errors=True,
        )
        shutil.rmtree(
            project_directory,
            ignore_errors=True,
        )

        return RedirectResponse(
            "/projects/new?message="
            + str(exc).replace(" ", "+"),
            status_code=303,
        )

    except Exception:
        shutil.rmtree(
            staging_directory,
            ignore_errors=True,
        )
        shutil.rmtree(
            project_directory,
            ignore_errors=True,
        )

        return RedirectResponse(
            "/projects/new?"
            "message=Upload+could+not+be+completed.+"
            "The+temporary+files+were+removed.",
            status_code=303,
        )

    finally:
        if project_file is not None:
            await project_file.close()

    return RedirectResponse(
        f"/projects/{public_id}",
        status_code=303,
    )


@router.get("/projects/{public_id}")
def project_detail(
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

    def safe_count(
        db,
        sql: str,
        parameters: dict,
    ) -> int:
        try:
            value = db.execute(
                text(sql),
                parameters,
            ).scalar()

            return int(value or 0)

        except Exception:
            return 0

    with Session(engine) as db:

        project = project_for_owner(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects?"
                "message=Project+was+not+found+in+your+workspace.",
                status_code=303,
            )

        parameters = {
            "project_id": project["id"],
            "owner_user_id": user.id,
        }

        events = (
            db.execute(
                text(
                    """
                    SELECT
                        event_type,
                        event_summary,
                        created_at
                    FROM project_audit_events
                    WHERE project_id = :project_id
                      AND owner_user_id = :owner_user_id
                    ORDER BY created_at DESC
                    LIMIT 12
                    """
                ),
                parameters,
            )
            .mappings()
            .all()
        )

        inventory_count = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_inventory_items
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
            """,
            parameters,
        )

        if inventory_count == 0:
            inventory_count = safe_count(
                db,
                """
                SELECT COUNT(*)
                FROM api_inventory
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                """,
                parameters,
            )

        test_case_count = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_test_cases
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
            """,
            parameters,
        )

        enabled_test_count = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_test_cases
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
              AND is_enabled = TRUE
            """,
            parameters,
        )

        config_count = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_test_configurations
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
            """,
            parameters,
        )

        if config_count == 0:
            config_count = safe_count(
                db,
                """
                SELECT COUNT(*)
                FROM test_configurations
                WHERE project_id = :project_id
                  AND owner_user_id = :owner_user_id
                """,
                parameters,
            )

        plan_count = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_execution_plans
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
            """,
            parameters,
        )

        discovery_runs = safe_count(
            db,
            """
            SELECT COUNT(*)
            FROM api_discovery_runs
            WHERE project_id = :project_id
              AND owner_user_id = :owner_user_id
            """,
            parameters,
        )

    event_items = "".join(
        f"""
        <li>
            <span class="qa-activity-dot"></span>

            <div>
                <strong>
                    {esc(event["event_summary"])}
                </strong>

                <small>
                    {esc(str(event["created_at"]))}
                </small>
            </div>
        </li>
        """
        for event in events
    )

    if not event_items:
        event_items = """
        <li class="qa-empty-activity">
            No project activity yet.
        </li>
        """

    sha_id = f"project-sha-{public_id}"
    discovery_csrf = csrf_token(request)

    discovery_done = (
        inventory_count > 0
        or discovery_runs > 0
    )

    tests_done = test_case_count > 0
    config_done = config_count > 0
    plan_done = plan_count > 0

    completed_steps = sum(
        (
            discovery_done,
            tests_done,
            config_done,
            plan_done,
        )
    )

    workflow_percent = int(
        completed_steps * 100 / 4
    )

    project_status = str(
        project["status"] or "ready"
    ).lower()

    environment = str(
        project["environment"] or "testing"
    ).title()

    content = f"""
<section class="qa-api-workspace">

    <div class="qa-project-workspace-header">

        <div>

            <a class="qa-project-breadcrumb"
               href="/projects">
                ← Projects
            </a>

            <div class="qa-project-title-row">

                <div>
                    <span class="qa-eyebrow">
                        API TESTING WORKSPACE
                    </span>

                    <h1>
                        {esc(project["name"])}
                    </h1>

                    <p>
                        {
                            esc(project["description"])
                            if project["description"]
                            else
                            "Universal API discovery, Smart Data, test generation and execution."
                        }
                    </p>
                </div>

            </div>

        </div>


        <div class="qa-project-header-actions">

            <span class="qa-project-environment">
                {esc(environment)}
            </span>

            {status_badge(project["status"])}

            <form method="post"
                  action="/projects/{esc(public_id)}/api-discovery">

                <input type="hidden"
                       name="csrf"
                       value="{esc(discovery_csrf)}">

                <button class="primary-button"
                        type="submit">
                    ↻ Discover APIs
                </button>

            </form>

        </div>

    </div>


    <nav class="qa-project-tabs"
         aria-label="API testing workspace">

        <a class="qa-project-tab is-active"
           href="/projects/{esc(public_id)}">
            <span>⌂</span>
            Overview
        </a>

        <a class="qa-project-tab"
           href="/projects/{esc(public_id)}/api-inventory">
            <span>▦</span>
            API Inventory

            <small>
                {inventory_count}
            </small>
        </a>

        <a class="qa-project-tab"
           href="/projects/{esc(public_id)}/smart-data">
            <span>✦</span>
            Smart Data
        </a>

        <a class="qa-project-tab"
           href="/projects/{esc(public_id)}/test-cases">
            <span>▤</span>
            Test Cases

            <small>
                {test_case_count}
            </small>
        </a>

        <a class="qa-project-tab"
           href="/projects/{esc(public_id)}/test-config">
            <span>⚙</span>
            Configuration

            <small>
                {config_count}
            </small>
        </a>

        <a class="qa-project-tab"
           href="/projects/{esc(public_id)}/execution-plans/new">
            <span>▶</span>
            Execution Plan

            <small>
                {plan_count}
            </small>
        </a>

    </nav>


    <div class="qa-project-kpis">

        <article>
            <span class="qa-project-kpi-icon purple">
                ▦
            </span>

            <div>
                <small>API Endpoints</small>
                <strong>
                    {inventory_count:,}
                </strong>
                <span>
                    Latest discovered inventory
                </span>
            </div>
        </article>


        <article>
            <span class="qa-project-kpi-icon blue">
                ▤
            </span>

            <div>
                <small>Test Cases</small>
                <strong>
                    {test_case_count:,}
                </strong>
                <span>
                    {enabled_test_count:,} enabled
                </span>
            </div>
        </article>


        <article>
            <span class="qa-project-kpi-icon saffron">
                ⚙
            </span>

            <div>
                <small>Configurations</small>
                <strong>
                    {config_count:,}
                </strong>
                <span>
                    Secure target environments
                </span>
            </div>
        </article>


        <article>
            <span class="qa-project-kpi-icon green">
                ▶
            </span>

            <div>
                <small>Execution Plans</small>
                <strong>
                    {plan_count:,}
                </strong>
                <span>
                    Immutable approved plans
                </span>
            </div>
        </article>

    </div>


    <div class="qa-project-content-grid">

        <div class="qa-project-main-column">


            <article class="qa-workflow-card">

                <div class="qa-card-heading">

                    <div>
                        <span>
                            API TESTING FLOW
                        </span>

                        <h2>
                            Project readiness
                        </h2>

                        <p>
                            Follow the workflow from discovery
                            through approved execution.
                        </p>
                    </div>

                    <div class="qa-workflow-percent">
                        {workflow_percent}%
                    </div>

                </div>


                <div class="qa-workflow-progress">

                    <span style="width:{workflow_percent}%">
                    </span>

                </div>


                <div class="qa-workflow-steps">


                    <a href="/projects/{esc(public_id)}/api-inventory"
                       class="qa-workflow-step {'complete' if discovery_done else 'current'}">

                        <div class="qa-step-number">
                            {'✓' if discovery_done else '1'}
                        </div>

                        <div>
                            <strong>
                                Discover APIs
                            </strong>

                            <small>
                                {
                                    f"{inventory_count} endpoints discovered"
                                    if discovery_done
                                    else
                                    "Inspect uploaded source and contracts"
                                }
                            </small>
                        </div>

                    </a>


                    <a href="/projects/{esc(public_id)}/smart-data"
                       class="qa-workflow-step {'complete' if discovery_done else 'locked'}">

                        <div class="qa-step-number">
                            {'✓' if discovery_done else '2'}
                        </div>

                        <div>
                            <strong>
                                Review Smart Data
                            </strong>

                            <small>
                                Schemas, constraints and prerequisites
                            </small>
                        </div>

                    </a>


                    <a href="/projects/{esc(public_id)}/test-cases"
                       class="qa-workflow-step {'complete' if tests_done else ('current' if discovery_done else 'locked')}">

                        <div class="qa-step-number">
                            {'✓' if tests_done else '3'}
                        </div>

                        <div>
                            <strong>
                                Generate Test Cases
                            </strong>

                            <small>
                                {
                                    f"{test_case_count} cases available"
                                    if tests_done
                                    else
                                    "Positive, negative and boundary scenarios"
                                }
                            </small>
                        </div>

                    </a>


                    <a href="/projects/{esc(public_id)}/test-config"
                       class="qa-workflow-step {'complete' if config_done else ('current' if tests_done else 'locked')}">

                        <div class="qa-step-number">
                            {'✓' if config_done else '4'}
                        </div>

                        <div>
                            <strong>
                                Configure Target
                            </strong>

                            <small>
                                Base URL, authentication and safety
                            </small>
                        </div>

                    </a>


                    <a href="/projects/{esc(public_id)}/execution-plans/new"
                       class="qa-workflow-step {'complete' if plan_done else ('current' if config_done and tests_done else 'locked')}">

                        <div class="qa-step-number">
                            {'✓' if plan_done else '5'}
                        </div>

                        <div>
                            <strong>
                                Review & Approve
                            </strong>

                            <small>
                                Immutable one-run execution plan
                            </small>
                        </div>

                    </a>

                </div>

            </article>


            <article class="qa-project-security-card">

                <div class="qa-card-heading">

                    <div>
                        <span>
                            EXECUTION SAFETY
                        </span>

                        <h2>
                            Protected testing workflow
                        </h2>
                    </div>

                    <span class="qa-security-state">
                        ● Protected
                    </span>

                </div>


                <div class="qa-security-grid">

                    <div>
                        <strong>
                            Uploaded source
                        </strong>

                        <span>
                            Static inspection only
                        </span>

                        <small>
                            Source code is never executed by QAFox.
                        </small>
                    </div>


                    <div>
                        <strong>
                            Ownership
                        </strong>

                        <span>
                            Owner isolated
                        </span>

                        <small>
                            Project data is scoped to your authenticated account.
                        </small>
                    </div>


                    <div>
                        <strong>
                            State changes
                        </strong>

                        <span>
                            Approval required
                        </span>

                        <small>
                            State-changing requests require explicit review.
                        </small>
                    </div>


                    <div>
                        <strong>
                            Destructive APIs
                        </strong>

                        <span>
                            Blocked by default
                        </span>

                        <small>
                            Destructive operations remain protected.
                        </small>
                    </div>

                </div>

            </article>


            <article class="qa-project-file-card">

                <div class="qa-card-heading">

                    <div>
                        <span>
                            SOURCE PROJECT
                        </span>

                        <h2>
                            Uploaded project
                        </h2>
                    </div>

                    <a class="outline-dark-button"
                       href="/projects/{esc(public_id)}/download">
                        Download original
                    </a>

                </div>


                <div class="qa-file-meta-grid">

                    <div>
                        <small>File</small>
                        <strong>
                            {esc(project["original_filename"])}
                        </strong>
                    </div>

                    <div>
                        <small>Type</small>
                        <strong>
                            {esc(project["file_type"].upper())}
                        </strong>
                    </div>

                    <div>
                        <small>Upload size</small>
                        <strong>
                            {esc(human_size(project["file_size_bytes"]))}
                        </strong>
                    </div>

                    <div>
                        <small>Extracted</small>
                        <strong>
                            {esc(human_size(project["extracted_size_bytes"]))}
                        </strong>
                    </div>

                    <div>
                        <small>Files</small>
                        <strong>
                            {esc(str(project["archive_entry_count"]))}
                        </strong>
                    </div>

                    <div>
                        <small>Environment</small>
                        <strong>
                            {esc(environment)}
                        </strong>
                    </div>

                </div>


                <div class="qa-project-hash">

                    <div>
                        <small>
                            SHA-256 fingerprint
                        </small>

                        <code id="{esc(sha_id)}">
                            {esc(project["sha256"])}
                        </code>
                    </div>

                    <button type="button"
                            class="copy-button"
                            data-copy-target="#{esc(sha_id)}">
                        ⧉ Copy
                    </button>

                </div>

            </article>

        </div>


        <aside class="qa-project-side-column">


            <article class="qa-project-action-card">

                <div class="qa-card-heading">

                    <div>
                        <span>
                            QUICK ACTIONS
                        </span>

                        <h2>
                            Continue testing
                        </h2>
                    </div>

                </div>


                <div class="qa-project-actions-list">

                    <form method="post"
                          action="/projects/{esc(public_id)}/api-discovery">

                        <input type="hidden"
                               name="csrf"
                               value="{esc(discovery_csrf)}">

                        <button type="submit"
                                class="qa-project-action is-primary">

                            <span>↻</span>

                            <div>
                                <strong>
                                    Discover APIs
                                </strong>

                                <small>
                                    Scan source and API definitions
                                </small>
                            </div>

                            <b>›</b>

                        </button>

                    </form>


                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/api-inventory">

                        <span>▦</span>

                        <div>
                            <strong>
                                API Inventory
                            </strong>

                            <small>
                                Review {inventory_count} discovered endpoints
                            </small>
                        </div>

                        <b>›</b>

                    </a>

                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/security">
                        <span>◇</span>
                        <div>
                            <strong>Security Findings</strong>
                            <small>Semgrep, Trivy and Gitleaks results</small>
                        </div>
                        <b>›</b>
                    </a>

                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/performance">
                        <span>◷</span>
                        <div>
                            <strong>Performance Tests</strong>
                            <small>Generate k6 scenarios and inspect exact metrics</small>
                        </div>
                        <b>›</b>
                    </a>


                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/smart-data">

                        <span>✦</span>

                        <div>
                            <strong>
                                Smart Data
                            </strong>

                            <small>
                                Review schemas and generated values
                            </small>
                        </div>

                        <b>›</b>

                    </a>


                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/test-cases">

                        <span>▤</span>

                        <div>
                            <strong>
                                Test Cases
                            </strong>

                            <small>
                                Generate or review test scenarios
                            </small>
                        </div>

                        <b>›</b>

                    </a>


                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/test-config">

                        <span>⚙</span>

                        <div>
                            <strong>
                                Test Configuration
                            </strong>

                            <small>
                                Target URL, auth and environment
                            </small>
                        </div>

                        <b>›</b>

                    </a>


                    <a class="qa-project-action"
                       href="/projects/{esc(public_id)}/execution-plans/new">

                        <span>▶</span>

                        <div>
                            <strong>
                                Execution Plan
                            </strong>

                            <small>
                                Review and approve test execution
                            </small>
                        </div>

                        <b>›</b>

                    </a>

                </div>

            </article>


            <article class="qa-project-activity-card">

                <div class="qa-card-heading">

                    <div>
                        <span>
                            ACTIVITY
                        </span>

                        <h2>
                            Recent project activity
                        </h2>
                    </div>

                </div>

                <ul class="qa-project-activity-list">
                    {event_items}
                </ul>

            </article>


            <article class="qa-project-danger-card">

                <strong>
                    Project management
                </strong>

                <p>
                    Delete removes this private project
                    and its uploaded project files.
                </p>

                <a href="/projects/{esc(public_id)}/delete">
                    Delete project
                </a>

            </article>

        </aside>

    </div>

</section>
"""

    return layout(
        project["name"],
        content,
        request,
        public=False,
    )

@router.get("/projects/{public_id}/delete")
def delete_project_page(
    request: Request,
    public_id: str,
    message: str = "",
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
        project = project_for_owner(
            db,
            user.id,
            public_id,
        )

    if not project:
        return RedirectResponse(
            "/projects?"
            "message=Project+was+not+found+in+your+workspace.",
            status_code=303,
        )

    csrf = csrf_token(request)
    notice = (
        f'<div class="message error">{esc(message)}</div>'
        if message
        else ""
    )

    content = f"""
<section class="simple-card project-delete-shell">
    <a href="/projects/{esc(public_id)}">← Cancel</a>
    <span>DELETE PRIVATE PROJECT</span>
    <h1>Delete {esc(project["name"])}?</h1>
    {notice}
    <p>
        This removes the project from your workspace and deletes
        the uploaded files for this project only. Other accounts
        are not affected. This cannot be undone from the app.
    </p>
    <p>
        File: {esc(project["original_filename"])}
    </p>
    <form method="post"
          action="/projects/{esc(public_id)}/delete">
        <input type="hidden" name="csrf" value="{esc(csrf)}">
        <button class="project-delete-button" type="submit">
            Delete project
        </button>
        <a class="outline-dark-button" href="/projects/{esc(public_id)}">
            Keep project
        </a>
    </form>
</section>
"""

    return layout(
        "Delete project",
        content,
        request,
        public=False,
    )


@router.post("/projects/{public_id}/delete")
def delete_project(
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
            f"/projects/{public_id}/delete"
            "?message=Your+session+expired.+Please+try+again.",
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
        project = project_for_owner(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects?"
                "message=Project+was+not+found+in+your+workspace.",
                status_code=303,
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
                    'project-deleted',
                    :summary,
                    :created_at
                )
                """
            ),
            {
                "project_id": project["id"],
                "owner_user_id": user.id,
                "summary": (
                    f"Deleted private project {project['name']}."
                ),
                "created_at": utc_now(),
            },
        )

        deleted = db.execute(
            text(
                """
                UPDATE projects
                SET deleted_at = :deleted_at,
                    updated_at = :updated_at
                WHERE id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND deleted_at IS NULL
                """
            ),
            {
                "deleted_at": utc_now(),
                "updated_at": utc_now(),
                "project_id": project["id"],
                "owner_user_id": user.id,
            },
        )

        if deleted.rowcount != 1:
            db.rollback()
            return RedirectResponse(
                "/projects?"
                "message=Project+was+not+found+in+your+workspace.",
                status_code=303,
            )

        db.commit()

    remove_owned_project_files(
        user.id,
        public_id,
        project["storage_directory"],
    )

    return RedirectResponse(
        "/projects?message=Private+project+deleted.",
        status_code=303,
    )


@router.get("/projects/{public_id}/download")
def download_original_project(
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
        project = project_for_owner(
            db,
            user.id,
            public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects?"
                "message=Project+was+not+found+in+your+workspace.",
                status_code=303,
            )

        project_directory = Path(
            project["storage_directory"]
        )

        expected_owner_root = (
            PROJECT_ROOT
            / str(user.id)
        ).resolve()

        original_file = (
            project_directory
            / "original"
            / project["stored_filename"]
        ).resolve()

        try:
            original_file.relative_to(
                expected_owner_root
            )
        except ValueError:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        if not original_file.is_file():
            return RedirectResponse(
                f"/projects/{public_id}",
                status_code=303,
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
                    'original-downloaded',
                    'Original project file downloaded.',
                    :created_at
                )
                """
            ),
            {
                "project_id": project["id"],
                "owner_user_id": user.id,
                "created_at": utc_now(),
            },
        )
        db.commit()

    return FileResponse(
        path=str(original_file),
        filename=project["original_filename"],
        media_type="application/octet-stream",
        headers={
            "Cache-Control": (
                "private, no-store, max-age=0"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )
