from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import default_registry
from app.smart_data.compatibility import (
    canonical_path,
    collect_adapter_contracts,
    comparison_key,
    inventory_item_from_route,
    merge_legacy_and_adapter,
)
from app.smart_data.contracts import ProjectRef


FIXTURES = Path(__file__).parent / "fixtures"


class CanonicalPathTests(TestCase):
    def test_normalizes_framework_parameter_syntax(self):
        self.assertEqual(canonical_path("/books/{book_id:int}"), "/books/{book_id}")
        self.assertEqual(canonical_path("/items/<int:item_id>"), "/items/{item_id}")
        self.assertEqual(canonical_path("/books/:book_id"), "/books/{book_id}")
        self.assertEqual(
            comparison_key("post", "/v1/books/{id}"),
            comparison_key("POST", "/v1/books/:id"),
        )


class RegistryTests(TestCase):
    def test_default_registry_includes_supported_adapters(self):
        self.assertEqual(
            default_registry().names(),
            ("fastapi", "flask", "openapi", "postman"),
        )


class AdapterCollectionTests(TestCase):
    def test_openapi_fixture_is_collected_without_executing_source(self):
        project = ProjectRef(FIXTURES / "openapi")
        collected = collect_adapter_contracts(project)
        paths = {(route.method, route.path) for route in collected.routes}
        self.assertIn(("POST", "/books"), paths)
        self.assertTrue(any(item.detected and item.framework == "openapi" for item in collected.detections))


class InventoryConversionTests(TestCase):
    def test_converted_item_keeps_editable_generated_fields(self):
        project = ProjectRef(FIXTURES / "openapi")
        collected = collect_adapter_contracts(project)
        route = next(item for item in collected.routes if item.path == "/books")
        item = inventory_item_from_route(route)
        self.assertEqual(item["http_method"], "POST")
        self.assertEqual(item["endpoint_path"], "/books")
        self.assertEqual(item["discovery_source"], "adapter")
        schema = __import__("json").loads(item["smart_data_schema"])
        names = {field["name"] for field in schema["fields"]}
        self.assertIn("title", names)
        self.assertTrue(all(field.get("editable", True) for field in schema["fields"]))
        author = next(field for field in schema["fields"] if field["name"] == "author_id")
        self.assertIn("REQUIRED", str(author["generated_value"]))


class MergeTests(TestCase):
    def test_matching_route_prefers_adapter_and_keeps_legacy_only(self):
        legacy = [
            {
                "http_method": "POST",
                "endpoint_path": "/books",
                "framework": "OpenAPI",
                "warnings": [],
                "confidence": "high",
                "confidence_score": 98,
                "is_duplicate": False,
            },
            {
                "http_method": "GET",
                "endpoint_path": "/healthz",
                "framework": "Express.js",
                "warnings": [],
                "confidence": "high",
                "confidence_score": 91,
                "is_duplicate": False,
            },
        ]
        adapter = [
            {
                "http_method": "POST",
                "endpoint_path": "/books",
                "framework": "openapi",
                "warnings": [],
                "confidence": "high",
                "confidence_score": 99,
                "is_duplicate": False,
                "discovery_source": "adapter",
                "smart_data_schema": "{}",
            }
        ]
        selected, report = merge_legacy_and_adapter(legacy, adapter)
        paths = {(item["http_method"], item["endpoint_path"]) for item in selected}
        self.assertEqual(paths, {("POST", "/books"), ("GET", "/healthz")})
        post = next(item for item in selected if item["endpoint_path"] == "/books")
        self.assertEqual(post["discovery_source"], "adapter")
        self.assertTrue(
            any("Adapter output selected" in warning for warning in post["warnings"])
        )
        self.assertEqual(report.agreed, 1)
        self.assertEqual(report.legacy_only, 1)
        self.assertEqual(report.adapter_only, 0)

    def test_flask_and_openapi_parameter_shapes_are_comparable(self):
        legacy = [
            {
                "http_method": "GET",
                "endpoint_path": "/books/:book_id",
                "framework": "Postman",
                "warnings": [],
                "confidence": "high",
                "confidence_score": 96,
                "is_duplicate": False,
            }
        ]
        adapter = [
            {
                "http_method": "GET",
                "endpoint_path": "/books/{book_id}",
                "framework": "openapi",
                "warnings": [],
                "confidence": "high",
                "confidence_score": 99,
                "is_duplicate": False,
                "discovery_source": "adapter",
            }
        ]
        selected, report = merge_legacy_and_adapter(legacy, adapter)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["endpoint_path"], "/books/{book_id}")
        self.assertEqual(report.adapter_selected, 1)
