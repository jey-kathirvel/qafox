from pathlib import Path
from unittest import TestCase

from app.smart_data.assertions import default_assertions, evaluate_assertions
from app.smart_data.compatibility import collect_adapter_contracts, inventory_item_from_route
from app.smart_data.contracts import ProjectRef


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class FixtureMatrixTests(TestCase):
    def test_fastapi_fixture_is_discovered_without_executing_source(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "fastapi_app"))
        paths = {(route.method, route.path) for route in collected.routes}
        self.assertIn(("POST", "/v1/books"), paths)
        self.assertIn(("GET", "/v1/books/{book_id}"), paths)
        self.assertFalse(any("leaf.ads-ai.in" in (route.summary or "") for route in collected.routes))

    def test_flask_blueprint_fixture_is_discovered(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "flask_app"))
        paths = {(route.method, route.path) for route in collected.routes}
        self.assertIn(("POST", "/v2/catalog/items"), paths)

    def test_openapi_and_swagger_fixtures_are_discovered(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "openapi"))
        paths = {(route.method, route.path) for route in collected.routes}
        self.assertTrue(paths)
        self.assertTrue(any(item.detected and item.framework == "openapi" for item in collected.detections))

    def test_postman_fixture_is_discovered(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "postman"))
        self.assertTrue(collected.routes)
        self.assertTrue(any(item.detected and item.framework == "postman" for item in collected.detections))

    def test_community_fixtures_are_discovered(self):
        express = collect_adapter_contracts(ProjectRef(FIXTURES / "express_app"))
        nest = collect_adapter_contracts(ProjectRef(FIXTURES / "nestjs_app"))
        django = collect_adapter_contracts(ProjectRef(FIXTURES / "django_app"))
        self.assertIn(("GET", "/api/v1/items/:id"), {(r.method, r.path) for r in express.routes})
        self.assertIn(("GET", "/orders/:id"), {(r.method, r.path) for r in nest.routes})
        self.assertIn("/api/products/<int:product_id>", {r.path for r in django.routes})

    def test_excluded_virtualenv_is_not_scanned(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "excluded_python"))
        self.assertEqual(collected.routes, [])
        self.assertFalse(any(item.detected for item in collected.detections))

    def test_converted_inventory_carries_response_contract_for_assertions(self):
        collected = collect_adapter_contracts(ProjectRef(FIXTURES / "openapi"))
        route = next(item for item in collected.routes if item.response_schemas)
        item = inventory_item_from_route(route)
        schema = __import__("json").loads(item["smart_data_schema"])
        self.assertIn("responses", schema)
        specs = default_assertions(
            case_type="positive",
            expected_status_codes="200",
            response_fields=next(iter(schema["responses"].values())).get("fields") or (),
        )
        body = "{}"
        # Evaluation must not require a live HTTP call or a production host.
        passed, _, _ = evaluate_assertions(
            [spec for spec in specs if spec["kind"] != "schema.fields"],
            status_code=200,
            body=body,
            duration_ms=5,
            timeout_ms=1000,
        )
        self.assertTrue(passed)
