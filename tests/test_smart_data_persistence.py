from unittest import TestCase

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.smart_data.contracts import (
    ActionKind,
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DependencyRelationship,
    FieldContract,
    PrerequisiteContract,
    RouteContract,
    RuntimeVariableContract,
    SchemaContract,
    SemanticType,
    TestDataSource,
    WorkflowActionContract,
)
from app.smart_data.migrate import (
    HISTORICAL_API_TABLES,
    MIGRATIONS_DIR,
    SMART_DATA_TABLES,
    apply_forward,
    apply_rollback,
    historical_api_table_counts,
    rollback_targets,
    smart_data_table_names_present,
)
from app.smart_data.persistence import (
    PersistenceIsolationError,
    load_snapshot,
    persist_contracts,
)
from app.smart_data.placeholders import build_placeholder, PlaceholderKind
from app.smart_data.serialization import UnsafeSecretError, route_from_json, route_to_json


def memory_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
    return engine


def seed_historical_tables(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE api_execution_plans (
                id INTEGER PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL
            )
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TABLE api_test_cases (
                id INTEGER PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                title TEXT NOT NULL
            )
            """
        )
        connection.exec_driver_sql(
            """
            INSERT INTO api_execution_plans (id, owner_user_id, fingerprint)
            VALUES (1, 9, 'historical-plan-must-not-change')
            """
        )
        connection.exec_driver_sql(
            """
            INSERT INTO api_test_cases (id, owner_user_id, title)
            VALUES (1, 9, 'historical-case')
            """
        )


def sample_route() -> RouteContract:
    return RouteContract(
        "POST",
        "/records",
        "fixture",
        operation_id="create_record",
        summary="Create a record",
        request_schemas=(
            SchemaContract(
                "RecordInput",
                "object",
                fields=(
                    FieldContract(
                        "title",
                        SemanticType.ENTITY_NAME,
                        "string",
                        True,
                        min_length=2,
                        max_length=80,
                        constraints=(ConstraintContract("minLength", 2),),
                    ),
                    FieldContract(
                        "owner_id",
                        SemanticType.FOREIGN_KEY,
                        "integer",
                        True,
                        dependency=DependencyRelationship("owner", "id"),
                    ),
                    FieldContract(
                        "access_token",
                        SemanticType.SECRET,
                        "string",
                        True,
                        secret=True,
                        generated_value=build_placeholder(
                            PlaceholderKind.SECRET_REF,
                            "configuration.access_token",
                        ),
                    ),
                ),
            ),
        ),
        authentication=(
            AuthFlowContract(
                "bearer",
                (AuthenticationMode.BEARER,),
                required=True,
            ),
        ),
        prerequisites=(PrerequisiteContract("owner", "id", placeholder="{{REQUIRED:owner.id}}"),),
        runtime_variables=(
            RuntimeVariableContract("create_record.output.id", "create_record", "$.id", "integer"),
        ),
        setup_actions=(
            WorkflowActionContract(
                "prepare_owner",
                ActionKind.SETUP,
                "POST /owners",
                requires_approval=True,
            ),
        ),
        cleanup_actions=(
            WorkflowActionContract(
                "remove_record",
                ActionKind.CLEANUP,
                "DELETE /records/{id}",
                requires_approval=True,
                same_run_only=True,
            ),
        ),
        confidence_score=90,
    )


class MigrationSqlContractTests(TestCase):
    def test_forward_sql_declares_every_smart_data_table(self):
        sql = (MIGRATIONS_DIR / "forward.sql").read_text(encoding="utf-8")
        for name in SMART_DATA_TABLES:
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {name}", sql)
            self.assertIn("owner_user_id", sql)

    def test_rollback_drops_only_smart_data_tables(self):
        targets = rollback_targets()
        self.assertEqual(set(targets), set(SMART_DATA_TABLES))
        rollback_sql = (MIGRATIONS_DIR / "rollback.sql").read_text(encoding="utf-8").lower()
        for name in HISTORICAL_API_TABLES:
            self.assertNotIn(f"drop table if exists {name}", rollback_sql)

    def test_forward_sql_does_not_mutate_historical_api_tables(self):
        sql = (MIGRATIONS_DIR / "forward.sql").read_text(encoding="utf-8").lower()
        for name in HISTORICAL_API_TABLES:
            self.assertNotIn(f"alter table {name}", sql)
            self.assertNotIn(f"update {name}", sql)
            self.assertNotIn(f"insert into {name}", sql)


class MigrationIdempotencyTests(TestCase):
    def test_forward_can_run_twice_and_rollback_preserves_history(self):
        engine = memory_engine()
        seed_historical_tables(engine)
        before = historical_api_table_counts(engine)
        apply_forward(engine)
        apply_forward(engine)
        self.assertEqual(smart_data_table_names_present(engine), SMART_DATA_TABLES)
        after_forward = historical_api_table_counts(engine)
        self.assertEqual(before, after_forward)
        apply_rollback(engine)
        self.assertEqual(smart_data_table_names_present(engine), ())
        self.assertEqual(historical_api_table_counts(engine), before)
        with engine.connect() as connection:
            fingerprint = connection.execute(
                text("SELECT fingerprint FROM api_execution_plans WHERE id = 1")
            ).scalar_one()
        self.assertEqual(fingerprint, "historical-plan-must-not-change")


class PersistenceIsolationTests(TestCase):
    def setUp(self):
        self.engine = memory_engine()
        apply_forward(self.engine)
        self.session = Session(self.engine)
        self.route = sample_route()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_owner_cannot_load_another_owners_snapshot(self):
        saved = persist_contracts(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
            routes=[self.route],
            adapter_names=("openapi",),
        )
        self.session.commit()
        missing = load_snapshot(
            self.session,
            owner_user_id=12,
            project_id=21,
            public_id=saved.public_id,
        )
        self.assertIsNone(missing)
        visible = load_snapshot(
            self.session,
            owner_user_id=11,
            project_id=21,
            public_id=saved.public_id,
        )
        self.assertIsNotNone(visible)
        self.assertEqual(visible.routes[0].path, "/records")

    def test_same_discovery_run_cannot_be_claimed_by_another_owner(self):
        persist_contracts(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
            routes=[self.route],
        )
        self.session.commit()
        with self.assertRaises(PersistenceIsolationError):
            persist_contracts(
                self.session,
                owner_user_id=12,
                project_id=99,
                discovery_run_id=31,
                routes=[self.route],
            )

    def test_persist_is_idempotent_for_the_same_owner_run(self):
        first = persist_contracts(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
            routes=[self.route],
        )
        second = persist_contracts(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
            routes=[self.route],
            fixtures=(
                TestDataSource(
                    "collection",
                    "postman",
                    {
                        "baseUrl": "https://example.test",
                        "access_token": "{{SECRET_REF:configuration.access_token}}",
                    },
                    contains_secrets=True,
                ),
            ),
        )
        self.session.commit()
        self.assertEqual(first.public_id, second.public_id)
        self.assertEqual(first.id, second.id)
        count = self.session.execute(
            text(
                """
                SELECT COUNT(*) FROM smart_data_snapshots
                WHERE owner_user_id = 11 AND project_id = 21
                """
            )
        ).scalar_one()
        self.assertEqual(count, 1)
        self.assertEqual(second.fixtures[0].values["access_token"], "{{SECRET_REF:configuration.access_token}}")

    def test_secret_raw_values_are_rejected(self):
        unsafe = RouteContract(
            "POST",
            "/login",
            "fixture",
            request_schemas=(
                SchemaContract(
                    "Login",
                    "object",
                    fields=(
                        FieldContract(
                            "password",
                            SemanticType.SECRET,
                            "string",
                            True,
                            secret=True,
                            generated_value="literal-password-must-not-persist",
                        ),
                    ),
                ),
            ),
        )
        with self.assertRaises(UnsafeSecretError):
            persist_contracts(
                self.session,
                owner_user_id=11,
                project_id=21,
                discovery_run_id=44,
                routes=[unsafe],
            )

    def test_round_trip_preserves_contracts_and_does_not_write_plans(self):
        seed_historical_tables(self.engine)
        saved = persist_contracts(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
            routes=[self.route],
            adapter_names=("fastapi",),
        )
        self.session.commit()
        loaded = load_snapshot(
            self.session,
            owner_user_id=11,
            project_id=21,
            discovery_run_id=31,
        )
        self.assertEqual(route_to_json(loaded.routes[0]), route_to_json(self.route))
        self.assertEqual(loaded.schema_version, 1)
        self.assertIn("POST /records", loaded.graphs)
        plan_count = self.session.execute(text("SELECT COUNT(*) FROM api_execution_plans")).scalar_one()
        self.assertEqual(plan_count, 1)
        field_names = {
            row[0]
            for row in self.session.execute(
                text(
                    """
                    SELECT name FROM smart_data_fields
                    WHERE owner_user_id = 11 AND project_id = 21
                    """
                )
            )
        }
        self.assertEqual(field_names, {"title", "owner_id", "access_token"})
        secret_value = self.session.execute(
            text(
                """
                SELECT generated_value_json FROM smart_data_fields
                WHERE owner_user_id = 11 AND name = 'access_token'
                """
            )
        ).scalar_one()
        self.assertIn("SECRET_REF", secret_value)
        self.assertNotIn("literal", secret_value)
        self.assertEqual(saved.adapter_names, ("fastapi",))

    def test_route_json_rejects_unknown_schema_version(self):
        payload = route_to_json(self.route)
        payload["schema_version"] = 99
        with self.assertRaises(ValueError):
            route_from_json(payload)
