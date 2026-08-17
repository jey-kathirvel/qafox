from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import default_registry
from app.smart_data.capabilities import capabilities_for
from app.smart_data.contracts import ProjectRef, SemanticType
from app.smart_data.uapi import AdapterCapability, ParameterLocation, UniversalContractNormalizer


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fields(contract):
    found = []
    for operation in contract.operations:
        if operation.request:
            found.extend(operation.request.fields)
        for parameter in operation.parameters:
            if parameter.field is not None:
                found.append(parameter.field)
            else:
                found.append(type("F", (), {"name": parameter.name, "semantic_type": SemanticType.UNKNOWN, "format": ""})())
        for response in operation.responses:
            found.extend(response.fields)
    for schema in contract.schemas:
        found.extend(schema.fields)
    return found


def _has_email(fields) -> bool:
    return any(
        getattr(field, "semantic_type", None) is SemanticType.EMAIL or getattr(field, "format", "") == "email"
        for field in fields
    )


class UniversalRestAdapterIntelligenceTests(TestCase):
    def _contract(self, name: str, folder: str):
        adapter = default_registry().get(name)
        project = ProjectRef(FIXTURES / folder)
        self.assertTrue(adapter.detect(project).detected, name)
        contract = adapter.normalize_contract(project)
        self.assertTrue(contract.operations, name)
        self.assertEqual(contract.contract_version, "qafox.uapi.contract/v2")
        for operation in contract.operations:
            self.assertTrue(operation.evidence, operation.operation_id)
            self.assertGreater(operation.confidence, 0)
        return adapter, project, contract

    def test_openapi_normalizes_email_format(self):
        adapter, project, contract = self._contract("openapi", "openapi")
        schema = next(item for item in adapter.extract_schemas(project) if item.name == "BookInput")
        email = next(field for field in schema.fields if field.name == "contact_email")
        self.assertEqual(email.semantic_type, SemanticType.EMAIL)
        self.assertEqual(email.format, "email")
        self.assertIn(AdapterCapability.VALIDATION, capabilities_for("openapi"))

    def test_fastapi_extracts_models_params_validation_auth_and_response(self):
        adapter, project, contract = self._contract("fastapi", "fastapi_app")
        routes = {(route.method, route.path) for route in adapter.discover_routes(project)}
        self.assertEqual(routes, {("POST", "/v1/books"), ("GET", "/v1/books/{book_id}")})
        schema = next(item for item in adapter.extract_schemas(project) if item.name == "BookCreate")
        fields = {field.name: field for field in schema.fields}
        self.assertEqual(fields["contact_email"].semantic_type, SemanticType.EMAIL)
        self.assertEqual(fields["contact_email"].format, "email")
        self.assertEqual(fields["author_id"].semantic_type, SemanticType.FOREIGN_KEY)
        self.assertTrue(fields["title"].min_length)
        self.assertTrue(fields["nested"].children)
        self.assertEqual(fields["genre"].semantic_type, SemanticType.ENUM)
        create = next(item for item in contract.operations if item.method == "POST")
        read = next(item for item in contract.operations if item.method == "GET")
        self.assertTrue(create.request and create.request.fields)
        self.assertTrue(create.responses)
        self.assertTrue(any(item.location is ParameterLocation.PATH for item in read.parameters))
        self.assertTrue(any(item.location is ParameterLocation.QUERY for item in read.parameters))
        self.assertTrue(any(item.location is ParameterLocation.HEADER for item in read.parameters))
        self.assertTrue(create.authentication[0].required)
        self.assertIn("pydantic", " ".join(ev.evidence_type for ev in schema.evidence))

    def test_flask_marshmallow_and_request_access(self):
        adapter, project, contract = self._contract("flask", "flask_app")
        create = next(item for item in contract.operations if item.method == "POST")
        names = {field.name for schema in adapter.discover_routes(project)[0].request_schemas for field in schema.fields}
        self.assertIn("title", names)
        self.assertIn("contact_email", names)
        self.assertTrue(_has_email(_fields(contract)) or "contact_email" in names)
        self.assertTrue(create.authentication)

    def test_express_zod_orm_and_request_fields(self):
        adapter, project, contract = self._contract("express", "express_app")
        paths = {(item.method, item.path) for item in contract.operations}
        self.assertIn(("GET", "/api/v1/items/:id"), paths)
        self.assertIn(("POST", "/api/v1/items"), paths)
        self.assertTrue(_has_email(_fields(contract)))
        post = next(item for item in contract.operations if item.method == "POST")
        self.assertTrue(post.request and post.request.fields)
        self.assertTrue(any(item.location is ParameterLocation.PATH for op in contract.operations for item in op.parameters))

    def test_nestjs_dto_class_validator_and_guards(self):
        adapter, project, contract = self._contract("nestjs", "nestjs_app")
        paths = {(item.method, item.path) for item in contract.operations}
        self.assertIn(("GET", "/orders/:id"), paths)
        self.assertIn(("POST", "/orders"), paths)
        self.assertTrue(_has_email(_fields(contract)))
        get = next(item for item in contract.operations if item.method == "GET")
        self.assertTrue(get.authentication[0].required)
        post = next(item for item in contract.operations if item.method == "POST")
        self.assertTrue(post.request and post.request.fields)

    def test_django_serializers_models_and_prefix(self):
        adapter, project, contract = self._contract("django", "django_app")
        paths = {item.path for item in contract.operations}
        self.assertIn("/api/products/<int:product_id>", paths)
        self.assertTrue(_has_email(_fields(contract)))
        self.assertTrue(any(item.method == "POST" for item in contract.operations))
        self.assertTrue(any(field.semantic_type is SemanticType.FOREIGN_KEY for field in _fields(contract)))

    def test_spring_bean_validation_and_parameters(self):
        adapter, project, contract = self._contract("spring", "spring_app")
        paths = {(item.method, item.path) for item in contract.operations}
        self.assertIn(("GET", "/v1/catalog/items/{id}"), paths)
        self.assertIn(("POST", "/v1/catalog/items"), paths)
        self.assertTrue(_has_email(_fields(contract)))
        post = next(item for item in contract.operations if item.method == "POST")
        self.assertTrue(post.request and post.request.fields)
        get = next(item for item in contract.operations if item.method == "GET")
        self.assertTrue(any(item.location is ParameterLocation.QUERY for item in get.parameters) or any(item.location is ParameterLocation.PATH for item in get.parameters))

    def test_laravel_validation_resource_and_eloquent(self):
        adapter, project, contract = self._contract("laravel", "laravel_app")
        paths = {(item.method, item.path) for item in contract.operations}
        self.assertIn(("GET", "/api/books/{id}"), paths)
        self.assertIn(("POST", "/api/books"), paths)
        self.assertTrue(any(path.endswith("/reviews") or "reviews" in path for _, path in paths))
        self.assertTrue(_has_email(_fields(contract)))

    def test_aspnet_dataannotations_and_authorize(self):
        adapter, project, contract = self._contract("aspnet", "aspnet_app")
        paths = {(item.method, item.path) for item in contract.operations}
        self.assertIn(("GET", "/api/widgets/{id}"), paths)
        self.assertIn(("POST", "/api/widgets"), paths)
        self.assertTrue(_has_email(_fields(contract)))
        post = next(item for item in contract.operations if item.method == "POST")
        self.assertTrue(post.authentication[0].required)
        self.assertTrue(post.request and post.request.fields)

    def test_email_semantics_are_equivalent_across_adapters(self):
        emails = []
        for name, folder in (
            ("openapi", "openapi"),
            ("fastapi", "fastapi_app"),
            ("flask", "flask_app"),
            ("express", "express_app"),
            ("nestjs", "nestjs_app"),
            ("django", "django_app"),
            ("spring", "spring_app"),
            ("laravel", "laravel_app"),
            ("aspnet", "aspnet_app"),
        ):
            contract = UniversalContractNormalizer().normalize_adapter(
                default_registry().get(name), ProjectRef(FIXTURES / folder)
            )
            self.assertTrue(_has_email(_fields(contract)), name)
            emails.append(name)
        self.assertEqual(len(emails), 9)

    def test_capability_matrix_does_not_claim_unimplemented_response_on_django(self):
        self.assertNotIn(AdapterCapability.RESPONSE_SCHEMA, capabilities_for("django"))
        self.assertIn(AdapterCapability.VALIDATION, capabilities_for("fastapi"))
        self.assertIn(AdapterCapability.REQUEST_SCHEMA, capabilities_for("spring"))
