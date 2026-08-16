from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import OpenAPIAdapter, PostmanAdapter
from app.smart_data.contracts import AuthenticationMode, ProjectRef, SemanticType


FIXTURES = Path(__file__).parent / "fixtures"


class OpenAPIAdapterTests(TestCase):
    def setUp(self):
        self.adapter = OpenAPIAdapter()
        self.project = ProjectRef(FIXTURES / "openapi")

    def test_detects_and_discovers_library_fixture(self):
        self.assertTrue(self.adapter.detect(self.project).detected)
        routes = self.adapter.discover_routes(self.project)
        self.assertEqual(
            [(route.method, route.path) for route in routes],
            [("POST", "/books"), ("GET", "/books/{book_id}"), ("POST", "/authors")],
        )

    def test_resolves_schema_constraints_and_foreign_key(self):
        schema = next(item for item in self.adapter.extract_schemas(self.project) if item.name == "BookInput")
        fields = {field.name: field for field in schema.fields}
        self.assertEqual(fields["title"].min_length, 2)
        self.assertEqual(fields["title"].max_length, 120)
        self.assertEqual(fields["author_id"].semantic_type, SemanticType.FOREIGN_KEY)
        self.assertIsNotNone(fields["author_id"].dependency)
        self.assertEqual(fields["genre"].enum_values, ("fiction", "reference"))

    def test_extracts_public_and_bearer_auth(self):
        routes = self.adapter.discover_routes(self.project)
        by_path = {route.path: route for route in routes}
        self.assertEqual(by_path["/books"].authentication[0].modes, (AuthenticationMode.BEARER,))
        self.assertEqual(by_path["/books/{book_id}"].authentication[0].modes, (AuthenticationMode.PUBLIC,))
        self.assertEqual(by_path["/authors"].authentication[0].modes, (AuthenticationMode.API_KEY,))

    def test_supports_swagger_body_and_response_schemas(self):
        route = next(route for route in self.adapter.discover_routes(self.project) if route.path == "/authors")
        self.assertEqual(route.request_schemas[0].fields[0].name, "name")
        self.assertIn("201", route.response_schemas)


class PostmanAdapterTests(TestCase):
    def setUp(self):
        self.adapter = PostmanAdapter()
        self.project = ProjectRef(FIXTURES / "postman")

    def test_detects_nested_collection_routes(self):
        self.assertTrue(self.adapter.detect(self.project).detected)
        routes = self.adapter.discover_routes(self.project)
        self.assertEqual([(route.method, route.path) for route in routes], [("POST", "/books"), ("GET", "/books/:book_id")])
        self.assertEqual(routes[0].authentication[0].modes, (AuthenticationMode.BEARER,))
        self.assertEqual(routes[1].authentication[0].modes, (AuthenticationMode.PUBLIC,))

    def test_secret_variable_value_is_never_copied(self):
        fixture = self.adapter.extract_fixtures(self.project)[0]
        self.assertTrue(fixture.contains_secrets)
        self.assertEqual(fixture.values["access_token"], "{{SECRET_REF:configuration.access_token}}")
        self.assertNotIn("must-not-be-copied", repr(fixture))

    def test_request_example_becomes_editable_schema_evidence(self):
        schema = self.adapter.extract_schemas(self.project)[0]
        fields = {field.name: field for field in schema.fields}
        self.assertIn("title", fields)
        self.assertEqual(fields["author_id"].semantic_type, SemanticType.FOREIGN_KEY)


class ScannerSafetyTests(TestCase):
    def test_excluded_directory_is_not_scanned(self):
        adapter = OpenAPIAdapter()
        project = ProjectRef(FIXTURES.parent / "excluded_scan")
        self.assertFalse(adapter.detect(project).detected)
