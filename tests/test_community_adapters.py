from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import (
    AspNetAdapter,
    DjangoAdapter,
    ExpressAdapter,
    LaravelAdapter,
    NestJSAdapter,
    SpringAdapter,
)
from app.smart_data.adapters.source_text import iter_source_text
from app.smart_data.compatibility import collect_adapter_contracts
from app.smart_data.contracts import AuthenticationMode, ProjectRef


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class CommunityAdapterTests(TestCase):
    def test_express_composes_nested_use_prefixes(self):
        adapter = ExpressAdapter()
        project = ProjectRef(FIXTURES / "express_app")
        self.assertTrue(adapter.detect(project).detected)
        routes = {(route.method, route.path) for route in adapter.discover_routes(project)}
        self.assertIn(("GET", "/api/v1/items/:id"), routes)

    def test_nestjs_controller_and_guard(self):
        adapter = NestJSAdapter()
        project = ProjectRef(FIXTURES / "nestjs_app")
        routes = adapter.discover_routes(project)
        self.assertEqual(routes[0].method, "GET")
        self.assertEqual(routes[0].path, "/orders/:id")
        self.assertEqual(routes[0].authentication[0].modes, (AuthenticationMode.BEARER,))
        self.assertTrue(routes[0].authentication[0].required)

    def test_django_include_prefix_applies_to_child_urlpatterns(self):
        adapter = DjangoAdapter()
        project = ProjectRef(FIXTURES / "django_app")
        paths = {route.path for route in adapter.discover_routes(project)}
        self.assertIn("/api/products/<int:product_id>", paths)
        self.assertFalse(any(path == "/api/" or path.endswith("include") for path in paths))

    def test_spring_laravel_and_aspnet_routes(self):
        spring = {(r.method, r.path) for r in SpringAdapter().discover_routes(ProjectRef(FIXTURES / "spring_app"))}
        laravel = {(r.method, r.path) for r in LaravelAdapter().discover_routes(ProjectRef(FIXTURES / "laravel_app"))}
        aspnet = {(r.method, r.path) for r in AspNetAdapter().discover_routes(ProjectRef(FIXTURES / "aspnet_app"))}
        self.assertIn(("GET", "/v1/catalog/items/{id}"), spring)
        self.assertIn(("GET", "/api/books/{id}"), laravel)
        self.assertIn(("GET", "/api/widgets/{id}"), aspnet)

    def test_virtualenv_is_not_walked_for_source_text(self):
        project = ProjectRef(FIXTURES / "excluded_python")
        files = [item.relative_path for item in iter_source_text(project, frozenset({".py"}))]
        self.assertEqual(files, [])
        collected = collect_adapter_contracts(project)
        self.assertFalse(any(item.detected for item in collected.detections))
