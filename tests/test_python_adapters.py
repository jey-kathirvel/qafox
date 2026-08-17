from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import FastAPIAdapter, FlaskAdapter
from app.smart_data.contracts import AuthenticationMode, ProjectRef, SemanticType


FIXTURES = Path(__file__).parent / "fixtures"


class FastAPIAdapterTests(TestCase):
    def setUp(self):
        self.adapter = FastAPIAdapter()
        self.project = ProjectRef(FIXTURES / "fastapi_app")

    def test_composes_imported_router_prefixes(self):
        self.assertTrue(self.adapter.detect(self.project).detected)
        routes = self.adapter.discover_routes(self.project)
        self.assertEqual(
            [(route.method, route.path) for route in routes],
            [("POST", "/v1/books"), ("GET", "/v1/books/{book_id}")],
        )

    def test_extracts_pydantic_constraints_and_secret_classification(self):
        schema = next(item for item in self.adapter.extract_schemas(self.project) if item.name == "BookCreate")
        fields = {field.name: field for field in schema.fields}
        self.assertEqual(fields["title"].min_length, 2)
        self.assertEqual(fields["title"].max_length, 120)
        self.assertEqual(fields["author_id"].minimum, 1)
        self.assertEqual(fields["author_id"].semantic_type, SemanticType.FOREIGN_KEY)
        self.assertTrue(fields["access_token"].secret)

    def test_authentication_comes_from_dependency_evidence(self):
        routes = {route.operation_id: route for route in self.adapter.discover_routes(self.project)}
        self.assertEqual(routes["create_book"].authentication[0].modes, (AuthenticationMode.BEARER,))
        self.assertEqual(routes["read_book"].authentication[0].modes, (AuthenticationMode.PUBLIC,))


class FlaskAdapterTests(TestCase):
    def setUp(self):
        self.adapter = FlaskAdapter()
        self.project = ProjectRef(FIXTURES / "flask_app")

    def test_composes_registered_blueprint_prefixes(self):
        self.assertTrue(self.adapter.detect(self.project).detected)
        routes = self.adapter.discover_routes(self.project)
        self.assertEqual(
            [(route.method, route.path) for route in routes],
            [("POST", "/v2/catalog/items"), ("GET", "/v2/catalog/items/<int:item_id>")],
        )

    def test_extracts_form_fields_and_session_auth(self):
        route = self.adapter.discover_routes(self.project)[0]
        fields = {field.name: field for field in route.request_schemas[0].fields}
        self.assertEqual(route.request_schemas[0].content_type, "application/x-www-form-urlencoded")
        self.assertIn("title", fields)
        self.assertEqual(fields["publisher_id"].semantic_type, SemanticType.FOREIGN_KEY)
        self.assertEqual(route.authentication[0].modes, (AuthenticationMode.SESSION,))


class PythonScannerSafetyTests(TestCase):
    def test_virtual_environment_source_is_not_scanned(self):
        project = ProjectRef(FIXTURES / "excluded_python")
        self.assertFalse(FastAPIAdapter().detect(project).detected)
