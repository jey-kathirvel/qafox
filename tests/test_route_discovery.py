from pathlib import Path
from unittest import TestCase

from sqlalchemy.orm import Session

from app.route_discovery import discover_normalized_routes, normalize_route
from app.smart_data.contracts import ProjectRef, RouteContract
from app.smart_data.migrate import apply_forward
from app.smart_data.persistence import load_snapshot, persist_contracts
from tests.test_smart_data_persistence import memory_engine


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class RouteFrameworkMatrixTests(TestCase):
    def test_every_mvp_adapter_emits_canonical_routes(self):
        matrix = {
            "openapi": ("GET", "/books/{book_id}"),
            "fastapi_app": ("GET", "/v1/books/{book_id}"),
            "flask_app": ("GET", "/v2/catalog/items/{item_id}"),
            "django_app": ("GET", "/api/products/{product_id}"),
            "express_app": ("GET", "/api/v1/items/{id}"),
            "nestjs_app": ("GET", "/orders/{id}"),
            "spring_app": ("GET", "/v1/catalog/items/{id}"),
            "aspnet_app": ("GET", "/api/widgets/{id}"),
            "laravel_app": ("GET", "/api/books/{id}"),
        }
        for fixture, expected in matrix.items():
            with self.subTest(fixture=fixture):
                report = discover_normalized_routes(ProjectRef(FIXTURES / fixture))
                self.assertIn(expected, {(route.method, route.path) for route in report.routes})
                self.assertTrue(all(route.path.startswith("/") for route in report.routes))
                self.assertTrue(all(0 <= route.confidence_score <= 100 for route in report.routes))

    def test_generic_adapter_is_only_used_as_fallback(self):
        generic = discover_normalized_routes(ProjectRef(FIXTURES / "generic_app"))
        self.assertEqual(
            {(route.method, route.path) for route in generic.routes},
            {("GET", "/widgets/{widget_id}"), ("POST", "/widgets")},
        )
        self.assertEqual({route.framework for route in generic.routes}, {"Generic"})

        express = discover_normalized_routes(ProjectRef(FIXTURES / "express_app"))
        self.assertNotIn("Generic", {route.framework for route in express.routes})

    def test_invalid_method_and_absolute_url_are_rejected(self):
        self.assertIsNone(normalize_route(RouteContract("EXEC", "/admin", "fixture")))
        self.assertIsNone(
            normalize_route(RouteContract("GET", "https://internal.example/admin", "fixture"))
        )


class RoutePersistenceTests(TestCase):
    def test_normalized_routes_round_trip_owner_scoped(self):
        engine = memory_engine()
        apply_forward(engine)
        report = discover_normalized_routes(ProjectRef(FIXTURES / "express_app"))
        with Session(engine) as db:
            snapshot = persist_contracts(
                db,
                owner_user_id=11,
                project_id=21,
                discovery_run_id=31,
                routes=report.routes,
                fixtures=report.fixtures,
                adapter_names=report.adapter_names,
            )
            db.commit()
            loaded = load_snapshot(
                db,
                owner_user_id=11,
                project_id=21,
                public_id=snapshot.public_id,
            )
            hidden = load_snapshot(
                db,
                owner_user_id=12,
                project_id=21,
                public_id=snapshot.public_id,
            )
        self.assertIsNotNone(loaded)
        self.assertIsNone(hidden)
        self.assertIn(
            ("GET", "/api/v1/items/{id}"),
            {(route.method, route.path) for route in loaded.routes},
        )
