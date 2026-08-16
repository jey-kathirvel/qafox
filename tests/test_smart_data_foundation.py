from pathlib import Path
from unittest import TestCase

from app.smart_data.adapters import AdapterRegistry, FrameworkAdapter
from app.smart_data.contracts import DetectionResult, ProjectRef
from app.smart_data.placeholders import (
    PlaceholderKind,
    build_placeholder,
    invalid_placeholders,
    parse_placeholder,
    unresolved_mandatory,
)


class EmptyAdapter(FrameworkAdapter):
    name = "fixture"

    def detect(self, project):
        return DetectionResult(self.name, True, 100)

    def discover_routes(self, project):
        return []

    def extract_schemas(self, project):
        return []

    def extract_constraints(self, project):
        return []

    def extract_auth_flows(self, project):
        return []

    def extract_fixtures(self, project):
        return []


class PlaceholderTests(TestCase):
    def test_canonical_placeholder_round_trip(self):
        raw = build_placeholder(
            PlaceholderKind.REQUIRED,
            "resource.field",
        )
        parsed = parse_placeholder(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.reference, "resource.field")
        self.assertTrue(parsed.blocks_approval)

    def test_synthetic_placeholder_does_not_block_approval(self):
        value = {"email": "{{SYNTHETIC:email}}"}
        self.assertEqual(unresolved_mandatory(value), ())

    def test_mandatory_placeholders_are_found_recursively(self):
        value = {
            "body": [{"id": "{{REQUIRED:product.id}}"}],
            "headers": {"authorization": "{{SECRET_REF:configuration.token}}"},
            "path": "{{DYNAMIC:create.output.id}}",
        }
        self.assertEqual(len(unresolved_mandatory(value)), 3)

    def test_legacy_and_malformed_placeholders_are_rejected(self):
        value = ["{{REQUIRED_PRODUCT_ID}}", "{{SECRET_REF:}}"]
        self.assertEqual(invalid_placeholders(value), tuple(value))

    def test_invalid_reference_cannot_be_built(self):
        with self.assertRaises(ValueError):
            build_placeholder(PlaceholderKind.REQUIRED, "bad value")


class AdapterRegistryTests(TestCase):
    def test_registration_is_deterministic(self):
        adapter = EmptyAdapter()
        registry = AdapterRegistry([adapter])
        self.assertEqual(registry.names(), ("fixture",))
        self.assertIs(registry.get("FIXTURE"), adapter)

    def test_duplicate_adapter_name_is_rejected(self):
        registry = AdapterRegistry([EmptyAdapter()])
        with self.assertRaises(ValueError):
            registry.register(EmptyAdapter())

    def test_project_reference_does_not_load_source(self):
        project = ProjectRef(Path("/untrusted/project"), 42, "fixture-id")
        self.assertEqual(project.owner_user_id, 42)
