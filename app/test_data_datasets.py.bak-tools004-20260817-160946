from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text


MAX_DATASET_ROWS = 500
MAX_DATASET_BYTES = 2_000_000


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def normalize_rows(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError("Dataset rows must be an array.")

    if len(rows) > MAX_DATASET_ROWS:
        raise ValueError(
            f"Maximum {MAX_DATASET_ROWS} rows per saved dataset."
        )

    normalized = []

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(
                f"Dataset row {index + 1} must be an object."
            )

        normalized.append(row)

    encoded = canonical_json(normalized)

    if len(encoded.encode("utf-8")) > MAX_DATASET_BYTES:
        raise ValueError(
            "Dataset exceeds the 2 MB persistence limit."
        )

    return normalized


def project_for_owner(
    db,
    owner_user_id: int,
    project_public_id: str | None,
):
    if not project_public_id:
        return None

    return db.execute(
        text(
            """
            SELECT id,
                   public_id,
                   name
            FROM projects
            WHERE public_id = :public_id
              AND owner_user_id = :owner_user_id
              AND deleted_at IS NULL
            LIMIT 1
            """
        ),
        {
            "public_id": project_public_id,
            "owner_user_id": owner_user_id,
        },
    ).mappings().first()


def list_projects(db, owner_user_id: int):
    return db.execute(
        text(
            """
            SELECT public_id,
                   name,
                   environment
            FROM projects
            WHERE owner_user_id = :owner_user_id
              AND deleted_at IS NULL
            ORDER BY updated_at DESC,
                     id DESC
            """
        ),
        {
            "owner_user_id": owner_user_id,
        },
    ).mappings().all()


def list_datasets(db, owner_user_id: int):
    return db.execute(
        text(
            """
            SELECT
                d.public_id,
                d.name,
                d.description,
                d.domain,
                d.objective,
                d.locale,
                d.version,
                d.row_count,
                d.dataset_sha256,
                d.updated_at,
                p.public_id AS project_public_id,
                p.name AS project_name
            FROM qa_test_datasets d
            LEFT JOIN projects p
              ON p.id = d.project_id
             AND p.owner_user_id = d.owner_user_id
            WHERE d.owner_user_id = :owner_user_id
              AND d.status = 'active'
            ORDER BY d.updated_at DESC,
                     d.id DESC
            LIMIT 100
            """
        ),
        {
            "owner_user_id": owner_user_id,
        },
    ).mappings().all()


def get_dataset(
    db,
    owner_user_id: int,
    public_id: str,
):
    return db.execute(
        text(
            """
            SELECT
                d.*,
                p.public_id AS project_public_id,
                p.name AS project_name
            FROM qa_test_datasets d
            LEFT JOIN projects p
              ON p.id = d.project_id
             AND p.owner_user_id = d.owner_user_id
            WHERE d.public_id = :public_id
              AND d.owner_user_id = :owner_user_id
              AND d.status = 'active'
            LIMIT 1
            """
        ),
        {
            "public_id": public_id,
            "owner_user_id": owner_user_id,
        },
    ).mappings().first()


def save_dataset(
    db,
    *,
    owner_user_id: int,
    public_id: str | None,
    name: str,
    description: str,
    domain: str,
    objective: str,
    locale: str,
    project_public_id: str | None,
    schema: Any,
    semantic: Any,
    rows: Any,
):
    name = str(name or "").strip()

    if not name:
        raise ValueError("Dataset name is required.")

    if len(name) > 180:
        raise ValueError(
            "Dataset name must be 180 characters or fewer."
        )

    rows = normalize_rows(rows)

    schema = (
        schema
        if isinstance(schema, (dict, list))
        else {}
    )

    semantic = (
        semantic
        if isinstance(semantic, dict)
        else {}
    )

    project = project_for_owner(
        db,
        owner_user_id,
        project_public_id,
    )

    if (
        project_public_id
        and not project
    ):
        raise ValueError(
            "Selected project was not found in your workspace."
        )

    row_count = len(rows)

    dataset_hash = sha256_json(
        {
            "rows": rows,
            "schema": schema,
            "semantic": semantic,
        }
    )

    now = datetime.utcnow()

    existing = None

    if public_id:
        existing = get_dataset(
            db,
            owner_user_id,
            public_id,
        )

        if not existing:
            raise ValueError(
                "Dataset was not found in your workspace."
            )

    if existing:
        version = int(
            existing["version"] or 1
        ) + 1

        db.execute(
            text(
                """
                INSERT INTO qa_test_dataset_versions (
                    public_id,
                    dataset_id,
                    owner_user_id,
                    version,
                    row_count,
                    schema_json,
                    semantic_json,
                    dataset_json,
                    dataset_sha256,
                    created_at
                )
                VALUES (
                    :public_id,
                    :dataset_id,
                    :owner_user_id,
                    :version,
                    :row_count,
                    :schema_json,
                    :semantic_json,
                    :dataset_json,
                    :dataset_sha256,
                    :created_at
                )
                ON CONFLICT (
                    dataset_id,
                    version
                )
                DO NOTHING
                """
            ),
            {
                "public_id": str(uuid.uuid4()),
                "dataset_id": existing["id"],
                "owner_user_id": owner_user_id,
                "version": existing["version"],
                "row_count": existing["row_count"],
                "schema_json": existing["schema_json"],
                "semantic_json": existing["semantic_json"],
                "dataset_json": existing["dataset_json"],
                "dataset_sha256": existing["dataset_sha256"],
                "created_at": now,
            },
        )

        db.execute(
            text(
                """
                UPDATE qa_test_datasets
                SET
                    project_id = :project_id,
                    name = :name,
                    description = :description,
                    domain = :domain,
                    objective = :objective,
                    locale = :locale,
                    version = :version,
                    row_count = :row_count,
                    schema_json = :schema_json,
                    semantic_json = :semantic_json,
                    dataset_json = :dataset_json,
                    dataset_sha256 = :dataset_sha256,
                    updated_at = :updated_at
                WHERE id = :dataset_id
                  AND owner_user_id = :owner_user_id
                """
            ),
            {
                "project_id":
                    project["id"]
                    if project else None,
                "name": name,
                "description":
                    str(description or "")[:4000],
                "domain":
                    str(domain or "general")[:60],
                "objective":
                    str(objective or "functional")[:60],
                "locale":
                    str(locale or "india")[:40],
                "version": version,
                "row_count": row_count,
                "schema_json":
                    canonical_json(schema),
                "semantic_json":
                    canonical_json(semantic),
                "dataset_json":
                    canonical_json(rows),
                "dataset_sha256":
                    dataset_hash,
                "updated_at": now,
                "dataset_id": existing["id"],
                "owner_user_id": owner_user_id,
            },
        )

        dataset_public_id = existing["public_id"]

    else:
        version = 1
        dataset_public_id = str(
            uuid.uuid4()
        )

        result = db.execute(
            text(
                """
                INSERT INTO qa_test_datasets (
                    public_id,
                    owner_user_id,
                    project_id,
                    name,
                    description,
                    domain,
                    objective,
                    locale,
                    version,
                    status,
                    row_count,
                    schema_json,
                    semantic_json,
                    dataset_json,
                    dataset_sha256,
                    created_at,
                    updated_at
                )
                VALUES (
                    :public_id,
                    :owner_user_id,
                    :project_id,
                    :name,
                    :description,
                    :domain,
                    :objective,
                    :locale,
                    :version,
                    'active',
                    :row_count,
                    :schema_json,
                    :semantic_json,
                    :dataset_json,
                    :dataset_sha256,
                    :created_at,
                    :updated_at
                )
                RETURNING id
                """
            ),
            {
                "public_id":
                    dataset_public_id,
                "owner_user_id":
                    owner_user_id,
                "project_id":
                    project["id"]
                    if project else None,
                "name": name,
                "description":
                    str(description or "")[:4000],
                "domain":
                    str(domain or "general")[:60],
                "objective":
                    str(objective or "functional")[:60],
                "locale":
                    str(locale or "india")[:40],
                "version": 1,
                "row_count": row_count,
                "schema_json":
                    canonical_json(schema),
                "semantic_json":
                    canonical_json(semantic),
                "dataset_json":
                    canonical_json(rows),
                "dataset_sha256":
                    dataset_hash,
                "created_at": now,
                "updated_at": now,
            },
        )

        dataset_id = result.scalar_one()

        db.execute(
            text(
                """
                INSERT INTO qa_test_dataset_versions (
                    public_id,
                    dataset_id,
                    owner_user_id,
                    version,
                    row_count,
                    schema_json,
                    semantic_json,
                    dataset_json,
                    dataset_sha256,
                    created_at
                )
                VALUES (
                    :public_id,
                    :dataset_id,
                    :owner_user_id,
                    1,
                    :row_count,
                    :schema_json,
                    :semantic_json,
                    :dataset_json,
                    :dataset_sha256,
                    :created_at
                )
                """
            ),
            {
                "public_id":
                    str(uuid.uuid4()),
                "dataset_id":
                    dataset_id,
                "owner_user_id":
                    owner_user_id,
                "row_count":
                    row_count,
                "schema_json":
                    canonical_json(schema),
                "semantic_json":
                    canonical_json(semantic),
                "dataset_json":
                    canonical_json(rows),
                "dataset_sha256":
                    dataset_hash,
                "created_at":
                    now,
            },
        )

    return get_dataset(
        db,
        owner_user_id,
        dataset_public_id,
    )


def archive_dataset(
    db,
    owner_user_id: int,
    public_id: str,
) -> bool:
    result = db.execute(
        text(
            """
            UPDATE qa_test_datasets
            SET
                status = 'archived',
                updated_at = CURRENT_TIMESTAMP
            WHERE public_id = :public_id
              AND owner_user_id = :owner_user_id
              AND status = 'active'
            """
        ),
        {
            "public_id": public_id,
            "owner_user_id": owner_user_id,
        },
    )

    return bool(result.rowcount)


# ==========================================================
# PATCH-QAFOX-TOOLS-003B
# Dataset → API Test Case binding
# ==========================================================

def _case_display_columns(db) -> set[str]:
    from sqlalchemy import inspect

    return {
        col["name"]
        for col in inspect(
            db.get_bind()
        ).get_columns(
            "api_test_cases"
        )
    }


def list_project_test_cases(
    db,
    *,
    owner_user_id: int,
    project_public_id: str,
):
    project = project_for_owner(
        db,
        owner_user_id,
        project_public_id,
    )

    if not project:
        raise ValueError(
            "Project was not found in your workspace."
        )

    columns = _case_display_columns(db)

    def pick(*names):
        for name in names:
            if name in columns:
                return name
        return None

    public_col = pick(
        "public_id",
        "case_public_id",
    )

    title_col = pick(
        "title",
        "name",
        "case_name",
        "scenario_name",
    )

    method_col = pick(
        "method",
        "http_method",
    )

    path_col = pick(
        "path",
        "endpoint_path",
        "endpoint",
        "url_path",
    )

    category_col = pick(
        "category",
        "case_type",
        "test_type",
        "scenario_type",
    )

    safe_col = pick(
        "is_safe",
        "safe",
        "safe_to_run",
    )

    enabled_col = pick(
        "enabled",
        "is_enabled",
    )

    select_parts = [
        "id",
    ]

    if public_col:
        select_parts.append(
            f"{public_col} AS public_id"
        )
    else:
        select_parts.append(
            "CAST(id AS VARCHAR) AS public_id"
        )

    if title_col:
        select_parts.append(
            f"{title_col} AS title"
        )
    else:
        select_parts.append(
            "'API Test Case' AS title"
        )

    if method_col:
        select_parts.append(
            f"{method_col} AS method"
        )
    else:
        select_parts.append(
            "'' AS method"
        )

    if path_col:
        select_parts.append(
            f"{path_col} AS path"
        )
    else:
        select_parts.append(
            "'' AS path"
        )

    if category_col:
        select_parts.append(
            f"{category_col} AS category"
        )
    else:
        select_parts.append(
            "'' AS category"
        )

    if safe_col:
        select_parts.append(
            f"{safe_col} AS is_safe"
        )
    else:
        select_parts.append(
            "NULL AS is_safe"
        )

    where_parts = [
        "owner_user_id = :owner_user_id",
        "project_id = :project_id",
    ]

    if enabled_col:
        where_parts.append(
            f"COALESCE({enabled_col}, TRUE) = TRUE"
        )

    sql = f"""
        SELECT
            {", ".join(select_parts)}
        FROM api_test_cases
        WHERE {" AND ".join(where_parts)}
        ORDER BY id
    """

    return db.execute(
        text(sql),
        {
            "owner_user_id":
                owner_user_id,
            "project_id":
                project["id"],
        },
    ).mappings().all()


def bind_dataset_to_cases(
    db,
    *,
    owner_user_id: int,
    dataset_public_id: str,
    project_public_id: str,
    test_case_public_ids: list[str],
):
    import uuid

    dataset = get_dataset(
        db,
        owner_user_id,
        dataset_public_id,
    )

    if not dataset:
        raise ValueError(
            "Dataset was not found in your workspace."
        )

    project = project_for_owner(
        db,
        owner_user_id,
        project_public_id,
    )

    if not project:
        raise ValueError(
            "Project was not found in your workspace."
        )

    if (
        dataset["project_id"]
        is not None
        and int(dataset["project_id"])
            != int(project["id"])
    ):
        raise ValueError(
            "Dataset is linked to a different project."
        )

    if not isinstance(
        test_case_public_ids,
        list,
    ):
        raise ValueError(
            "test_case_public_ids must be an array."
        )

    requested = {
        str(item)
        for item in test_case_public_ids
        if str(item).strip()
    }

    if not requested:
        raise ValueError(
            "Select at least one API test case."
        )

    available = list_project_test_cases(
        db,
        owner_user_id=owner_user_id,
        project_public_id=
            project_public_id,
    )

    available_by_public = {
        str(item["public_id"]):
            item
        for item in available
    }

    unknown = (
        requested
        - set(available_by_public)
    )

    if unknown:
        raise ValueError(
            "One or more selected test cases "
            "do not belong to this project."
        )

    bound = []

    for case_public_id in sorted(
        requested
    ):
        case = available_by_public[
            case_public_id
        ]

        db.execute(
            text(
                """
                INSERT INTO
                qa_test_dataset_bindings (
                    public_id,
                    owner_user_id,
                    project_id,
                    test_case_id,
                    dataset_id,
                    dataset_version,
                    dataset_sha256,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (
                    :public_id,
                    :owner_user_id,
                    :project_id,
                    :test_case_id,
                    :dataset_id,
                    :dataset_version,
                    :dataset_sha256,
                    'active',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                ON CONFLICT (
                    owner_user_id,
                    test_case_id
                )
                DO UPDATE SET
                    project_id =
                        EXCLUDED.project_id,
                    dataset_id =
                        EXCLUDED.dataset_id,
                    dataset_version =
                        EXCLUDED.dataset_version,
                    dataset_sha256 =
                        EXCLUDED.dataset_sha256,
                    status =
                        'active',
                    updated_at =
                        CURRENT_TIMESTAMP
                """
            ),
            {
                "public_id":
                    str(uuid.uuid4()),
                "owner_user_id":
                    owner_user_id,
                "project_id":
                    project["id"],
                "test_case_id":
                    case["id"],
                "dataset_id":
                    dataset["id"],
                "dataset_version":
                    dataset["version"],
                "dataset_sha256":
                    dataset[
                        "dataset_sha256"
                    ],
            },
        )

        bound.append(
            {
                "public_id":
                    case["public_id"],
                "title":
                    case["title"],
            }
        )

    return {
        "dataset_public_id":
            dataset["public_id"],

        "dataset_version":
            dataset["version"],

        "dataset_sha256":
            dataset["dataset_sha256"],

        "project_public_id":
            project["public_id"],

        "bound_cases":
            bound,
    }


def list_dataset_bindings(
    db,
    *,
    owner_user_id: int,
    dataset_public_id: str,
):
    dataset = get_dataset(
        db,
        owner_user_id,
        dataset_public_id,
    )

    if not dataset:
        raise ValueError(
            "Dataset was not found in your workspace."
        )

    columns = _case_display_columns(db)

    title_col = next(
        (
            name
            for name in (
                "title",
                "name",
                "case_name",
                "scenario_name",
            )
            if name in columns
        ),
        None,
    )

    public_col = next(
        (
            name
            for name in (
                "public_id",
                "case_public_id",
            )
            if name in columns
        ),
        None,
    )

    title_expr = (
        f"c.{title_col}"
        if title_col
        else "'API Test Case'"
    )

    public_expr = (
        f"c.{public_col}"
        if public_col
        else "CAST(c.id AS VARCHAR)"
    )

    return db.execute(
        text(
            f"""
            SELECT
                b.public_id AS binding_public_id,
                {public_expr}
                    AS case_public_id,
                {title_expr}
                    AS case_title,
                b.dataset_version,
                b.dataset_sha256,
                b.updated_at
            FROM qa_test_dataset_bindings b
            JOIN api_test_cases c
              ON c.id = b.test_case_id
             AND c.owner_user_id =
                 b.owner_user_id
            WHERE b.owner_user_id =
                    :owner_user_id
              AND b.dataset_id =
                    :dataset_id
              AND b.status = 'active'
            ORDER BY c.id
            """
        ),
        {
            "owner_user_id":
                owner_user_id,
            "dataset_id":
                dataset["id"],
        },
    ).mappings().all()


def execution_dataset_snapshot(
    db,
    *,
    owner_user_id: int,
    project_id: int,
    test_case_id: int,
):
    """
    Return immutable dataset material suitable for copying
    into a NEW execution-plan snapshot.

    This function never modifies a plan, test case or dataset.
    """

    row = db.execute(
        text(
            """
            SELECT
                d.public_id
                    AS dataset_public_id,
                d.name
                    AS dataset_name,
                b.dataset_version,
                b.dataset_sha256,
                d.domain,
                d.objective,
                d.locale,
                d.schema_json,
                d.semantic_json,
                d.dataset_json
            FROM qa_test_dataset_bindings b
            JOIN qa_test_datasets d
              ON d.id = b.dataset_id
             AND d.owner_user_id =
                 b.owner_user_id
            WHERE b.owner_user_id =
                    :owner_user_id
              AND b.project_id =
                    :project_id
              AND b.test_case_id =
                    :test_case_id
              AND b.status = 'active'
              AND d.status = 'active'
            LIMIT 1
            """
        ),
        {
            "owner_user_id":
                owner_user_id,
            "project_id":
                project_id,
            "test_case_id":
                test_case_id,
        },
    ).mappings().first()

    if not row:
        return None

    def parsed(value, fallback):
        try:
            return json.loads(value)
        except Exception:
            return fallback

    return {
        "dataset_public_id":
            row["dataset_public_id"],

        "dataset_name":
            row["dataset_name"],

        "dataset_version":
            row["dataset_version"],

        "dataset_sha256":
            row["dataset_sha256"],

        "domain":
            row["domain"],

        "objective":
            row["objective"],

        "locale":
            row["locale"],

        "schema":
            parsed(
                row["schema_json"],
                {},
            ),

        "semantic":
            parsed(
                row["semantic_json"],
                {},
            ),

        "rows":
            parsed(
                row["dataset_json"],
                [],
            ),
    }
