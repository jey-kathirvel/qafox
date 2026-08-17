import json
from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import default_registry
from app.smart_data.capabilities import REGISTERED_ADAPTERS, capabilities_for, capability_matrix
from app.smart_data.compatibility import canonical_path
from app.smart_data.contracts import (
    AuthenticationMode,
    ConstraintContract,
    FieldContract,
    ProjectRef,
    RouteContract,
    SemanticType,
    SourceEvidence,
)
from app.smart_data.placeholders import PlaceholderKind, build_placeholder
from app.smart_data.serialization import UnsafeSecretError, field_from_json, field_to_json
from app.smart_data.uapi import (
    UAPI_CONTRACT_VERSION,
    AdapterCapability,
    ApiContract,
    AssertionContract,
    AuthenticationContract,
    DependencyContract,
    Evidence,
    OperationContract,
    ParameterContract,
    ParameterLocation,
    ProtocolKind,
    RequestContract,
    ResponseContract,
    RuntimeBindingContract,
    SecurityRequirement,
    UniversalContractNormalizer,
    canonical_operation_shape,
    operation_from_route,
    route_from_operation,
)


FIXTURES = Path(__file__).parent / "fixtures"


def sample_field(**overrides) -> FieldContract:
    values = dict(
        name="title",
        semantic_type=SemanticType.ENTITY_NAME,
        data_type="string",
        required=True,
        path="title",
        min_length=2,
        max_length=80,
        example_values=("Alpha",),
        confidence_score=90,
        evidence=(SourceEvidence("schema.yaml", 12, evidence_type="schema-field", excerpt="title:"),),
    )
    values.update(overrides)
    return FieldContract(**values)


def sample_operation() -> OperationContract:
    secret = FieldContract(
        "access_token",
        SemanticType.SECRET,
        "string",
        True,
        secret=True,
        sensitive=True,
        default_value="must-not-serialize",
        example_values=("must-not-serialize",),
        generated_value=build_placeholder(PlaceholderKind.SECRET_REF, "configuration.access_token"),
        confidence_score=99,
        evidence=(SourceEvidence("schema.yaml", 20, evidence_type="schema-field"),),
    )
    return OperationContract(
        operation_id="create_record",
        protocol=ProtocolKind.REST,
        method="POST",
        path="/records",
        summary="Create a record",
        description="Create a record",
        tags=("records",),
        parameters=(
            ParameterContract(
                "id",
                ParameterLocation.PATH,
                FieldContract("id", SemanticType.IDENTIFIER, "string", True, path="id"),
                True,
                confidence=80,
            ),
        ),
        request=RequestContract(
            content_type="application/json",
            required=True,
            fields=(sample_field(), secret),
            schema_name="RecordInput",
            confidence=90,
        ),
        responses=(
            ResponseContract(
                "201",
                "application/json",
                fields=(FieldContract("id", SemanticType.IDENTIFIER, "integer", True),),
                schema_name="Record",
                confidence=88,
            ),
        ),
        authentication=(
            AuthenticationContract(
                "bearer",
                (AuthenticationMode.BEARER,),
                True,
                "configuration.auth.bearer",
                confidence=95,
                evidence=(SourceEvidence("schema.yaml", evidence_type="security"),),
            ),
        ),
        security_requirements=(
            SecurityRequirement("bearer", required=True, scheme="bearer-token", confidence=95),
        ),
        dependencies=(DependencyContract("owner", "id", confidence=70),),
        runtime_bindings=(
            RuntimeBindingContract(
                "create_record.output.id", "create_record", "$.id", "integer", confidence=80
            ),
        ),
        assertions=(AssertionContract("status-201", "status", expected="201", confidence=70),),
        safe_read_only=False,
        state_changing=True,
        destructive=False,
        confidence=90,
        evidence=(SourceEvidence("schema.yaml", 3, evidence_type="operation", confidence_score=90),),
        source_location="schema.yaml:3",
    )


class ContractConstructionTests(TestCase):
    def test_api_contract_carries_versioned_canonical_concepts(self):
        operation = sample_operation()
        contract = ApiContract(
            source_type="definition",
            source_framework="openapi",
            source_protocol=ProtocolKind.REST,
            title="Records",
            base_paths=("/records",),
            operations=(operation,),
            authentication=operation.authentication,
            confidence=90,
            adapter_name="openapi",
            adapter_version="3.0.3",
        )
        self.assertEqual(contract.contract_version, UAPI_CONTRACT_VERSION)
        self.assertEqual(UAPI_CONTRACT_VERSION, "qafox.uapi.contract/v2")
        self.assertIs(Evidence, SourceEvidence)
        self.assertEqual(operation.protocol, ProtocolKind.REST)
        self.assertTrue(operation.state_changing)
        self.assertFalse(operation.destructive)
        self.assertEqual(operation.parameters[0].location, ParameterLocation.PATH)
        self.assertEqual(ConstraintContract("minLength", 2).to_dict()["name"], "minLength")

    def test_extensible_protocols_exist_and_rest_is_the_implemented_kind(self):
        self.assertEqual(
            {item.value for item in ProtocolKind},
            {"REST", "GRAPHQL", "GRPC", "SOAP", "WEBSOCKET", "ASYNCAPI", "UNKNOWN"},
        )
        self.assertEqual(
            {item.value for item in ParameterLocation},
            {
                "PATH",
                "QUERY",
                "HEADER",
                "COOKIE",
                "BODY",
                "FORM",
                "MULTIPART",
                "GRAPHQL_VARIABLE",
                "GRPC_METADATA",
                "SOAP_HEADER",
                "MESSAGE",
                "UNKNOWN",
            },
        )


class SerializationTests(TestCase):
    def test_round_trip_preserves_operations_evidence_and_confidence(self):
        contract = ApiContract(
            source_type="definition",
            source_framework="openapi",
            operations=(sample_operation(),),
            confidence=90,
            adapter_name="openapi",
            evidence=sample_operation().evidence,
        )
        payload = contract.to_dict()
        restored = ApiContract.from_dict(payload)
        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(restored.operations[0].confidence, 90)
        self.assertEqual(restored.operations[0].evidence[0].source_file, "schema.yaml")
        self.assertEqual(restored.operations[0].source_location, "schema.yaml:3")
        json.dumps(payload)

    def test_enum_values_are_stable_strings(self):
        payload = sample_operation().to_dict()
        self.assertEqual(payload["protocol"], "REST")
        self.assertEqual(payload["parameters"][0]["location"], "PATH")
        self.assertIsInstance(payload["protocol"], str)
        self.assertIsInstance(payload["parameters"][0]["location"], str)

    def test_unknown_contract_version_is_rejected(self):
        with self.assertRaises(ValueError):
            ApiContract.from_dict({"contract_version": "qafox.uapi.contract/v1"})

    def test_field_round_trip_keeps_expanded_constraints(self):
        field = FieldContract(
            "quantity",
            SemanticType.INTEGER,
            "integer",
            True,
            minimum=1,
            maximum=9,
            exclusive_minimum=0,
            exclusive_maximum=10,
            multiple_of=1,
            min_items=1,
            max_items=3,
            unique_items=True,
            items=FieldContract("item", SemanticType.INTEGER, "integer"),
            one_of=(FieldContract("alt", SemanticType.INTEGER, "integer"),),
            confidence_score=77,
            source_location="models.py:4",
        )
        restored = FieldContract.from_dict(field.to_dict())
        self.assertEqual(restored.exclusive_minimum, 0)
        self.assertEqual(restored.items.name, "item")
        self.assertEqual(restored.one_of[0].name, "alt")
        self.assertEqual(restored.confidence_score, 77)


class SecretProtectionTests(TestCase):
    def test_plaintext_secret_defaults_and_examples_are_excluded(self):
        payload = sample_operation().to_dict()
        encoded = json.dumps(payload)
        self.assertNotIn("must-not-serialize", encoded)
        secret = payload["request"]["fields"][1]
        self.assertTrue(secret["secret"])
        self.assertIsNone(secret["default_value"])
        self.assertEqual(secret["example_values"], [])
        self.assertIn("SECRET_REF", secret["generated_value"])

    def test_raw_secret_generated_value_is_rejected(self):
        field = FieldContract(
            "password",
            SemanticType.SECRET,
            "string",
            True,
            secret=True,
            generated_value="literal-password",
        )
        with self.assertRaises(UnsafeSecretError):
            field_to_json(field)
        with self.assertRaises(UnsafeSecretError):
            field_from_json(
                {
                    "name": "password",
                    "secret": True,
                    "generated_value": "literal-password",
                    "semantic_type": "secret",
                }
            )


class AdapterCapabilityTests(TestCase):
    def test_registered_adapters_have_explicit_capabilities(self):
        names = set(default_registry().names())
        self.assertEqual(names, set(REGISTERED_ADAPTERS))
        matrix = capability_matrix()
        self.assertEqual(set(matrix), names)
        self.assertIn(AdapterCapability.ROUTES.value, matrix["openapi"])
        self.assertIn(AdapterCapability.RESPONSE_SCHEMA.value, matrix["openapi"])
        self.assertIn(AdapterCapability.FIXTURES.value, matrix["postman"])
        self.assertIn(AdapterCapability.PREFIX_COMPOSITION.value, matrix["express"])
        self.assertIn(AdapterCapability.REQUEST_SCHEMA.value, matrix["express"])
        self.assertIn(AdapterCapability.VALIDATION.value, matrix["django"])
        self.assertIn(AdapterCapability.MODEL_RELATIONSHIPS.value, matrix["express"])
        self.assertNotIn(AdapterCapability.FIXTURES.value, matrix["openapi"])
        for adapter in default_registry().all():
            self.assertEqual(adapter.capabilities, capabilities_for(adapter.name))


class NormalizationBoundaryTests(TestCase):
    def test_adapters_normalize_to_versioned_rest_contracts(self):
        normalizer = UniversalContractNormalizer()
        project = ProjectRef(FIXTURES / "openapi")
        adapter = default_registry().get("openapi")
        contract = adapter.normalize_contract(project)
        self.assertEqual(contract.contract_version, UAPI_CONTRACT_VERSION)
        self.assertEqual(contract.adapter_name, "openapi")
        self.assertEqual(contract.source_protocol, ProtocolKind.REST)
        self.assertTrue(contract.operations)
        create = next(
            item for item in contract.operations if item.method == "POST" and item.path == "/books"
        )
        self.assertTrue(create.state_changing)
        self.assertFalse(create.safe_read_only)
        self.assertTrue(create.request and create.request.fields)
        self.assertTrue(create.authentication)
        self.assertTrue(create.evidence)
        self.assertGreater(create.confidence, 0)
        read = next(item for item in contract.operations if item.method == "GET")
        self.assertTrue(read.safe_read_only)
        self.assertFalse(read.state_changing)
        delete_like = operation_from_route(RouteContract("DELETE", "/books/{book_id}", "OpenAPI"))
        self.assertTrue(delete_like.destructive)
        self.assertTrue(delete_like.state_changing)
        mapped = route_from_operation(create, "OpenAPI")
        self.assertEqual(mapped.method, "POST")
        self.assertEqual(mapped.path, "/books")
        self.assertEqual(normalizer.normalize_route(mapped).method, "POST")

    def test_equivalent_canonical_shapes_across_adapters(self):
        normalizer = UniversalContractNormalizer()
        openapi = normalizer.normalize_adapter(
            default_registry().get("openapi"), ProjectRef(FIXTURES / "openapi")
        )
        postman = normalizer.normalize_adapter(
            default_registry().get("postman"), ProjectRef(FIXTURES / "postman")
        )
        fastapi = normalizer.normalize_adapter(
            default_registry().get("fastapi"), ProjectRef(FIXTURES / "fastapi_app")
        )
        flask = normalizer.normalize_adapter(
            default_registry().get("flask"), ProjectRef(FIXTURES / "flask_app")
        )
        openapi_create = next(
            item for item in openapi.operations if item.method == "POST" and item.path == "/books"
        )
        postman_create = next(item for item in postman.operations if item.method == "POST")
        fastapi_create = next(item for item in fastapi.operations if item.method == "POST")
        self.assertEqual(canonical_operation_shape(openapi_create)["protocol"], "REST")
        self.assertEqual(canonical_operation_shape(postman_create)["protocol"], "REST")
        self.assertEqual(canonical_operation_shape(fastapi_create)["protocol"], "REST")
        self.assertEqual(canonical_operation_shape(openapi_create)["method"], "POST")
        self.assertEqual(canonical_path(openapi_create.path), canonical_path(postman_create.path))
        self.assertTrue(canonical_operation_shape(openapi_create)["has_request_fields"])
        self.assertTrue(canonical_operation_shape(postman_create)["has_request_fields"])
        self.assertTrue(canonical_operation_shape(fastapi_create)["has_request_fields"])
        self.assertTrue(canonical_operation_shape(openapi_create)["state_changing"])
        flask_create = next(item for item in flask.operations if item.method == "POST")
        self.assertEqual(flask_create.protocol, ProtocolKind.REST)
        self.assertTrue(flask_create.request and flask_create.request.fields)


class BackwardCompatibilityTests(TestCase):
    def test_existing_field_construction_still_accepts_positional_arguments(self):
        field = FieldContract("quantity", SemanticType.INTEGER, "integer", True, None, 3, 9)
        self.assertEqual(field.minimum, 3)
        self.assertEqual(field.maximum, 9)
        self.assertEqual(field.path, "")
        self.assertFalse(field.read_only)
        payload = field_to_json(field)
        restored = field_from_json(
            {"name": "quantity", "semantic_type": "integer", "data_type": "integer"}
        )
        self.assertEqual(restored.name, "quantity")
        self.assertIn("path", payload)
        self.assertIn("confidence_score", payload)
