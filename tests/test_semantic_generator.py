from pathlib import Path
from unittest import TestCase

from app.smart_data.contracts import (
    DependencyRelationship,
    FieldContract,
    SemanticType,
)
from app.smart_data.generator import generate_field, valid_boundary_values
from app.smart_data.placeholders import approval_blockers


class SemanticGeneratorTests(TestCase):
    def test_email_and_url_use_safe_reserved_domain(self):
        email = generate_field(FieldContract("contact", format="email"))
        url = generate_field(FieldContract("callback", format="url"))
        self.assertTrue(email.value.endswith("@example.test"))
        self.assertTrue(url.value.startswith("https://example.test/"))

    def test_numeric_value_and_boundaries_respect_constraints(self):
        field = FieldContract(
            "quantity",
            SemanticType.INTEGER,
            "integer",
            True,
            minimum=3,
            maximum=9,
        )
        result = generate_field(field)
        self.assertGreaterEqual(result.value, 3)
        self.assertLessEqual(result.value, 9)
        self.assertEqual(valid_boundary_values(field), (3, 9))

    def test_foreign_key_becomes_editable_prerequisite(self):
        field = FieldContract(
            "publisher_id",
            SemanticType.FOREIGN_KEY,
            "integer",
            True,
            dependency=DependencyRelationship("publisher", "id"),
        )
        result = generate_field(field)
        self.assertEqual(result.value, "{{REQUIRED:publisher.id}}")
        self.assertEqual(result.status, "prerequisite-required")

    def test_secret_default_is_never_copied(self):
        field = FieldContract(
            "access_token",
            SemanticType.SECRET,
            "string",
            True,
            default_value="fixture-secret-must-not-copy",
            secret=True,
        )
        result = generate_field(field)
        self.assertEqual(result.value, "{{SECRET_REF:configuration.access_token}}")
        self.assertNotIn("fixture-secret-must-not-copy", repr(result))

    def test_nested_object_is_generated_recursively(self):
        field = FieldContract(
            "profile",
            SemanticType.OBJECT,
            "object",
            children=(
                FieldContract("email", SemanticType.EMAIL, "string", True),
                FieldContract("active", SemanticType.BOOLEAN, "boolean"),
            ),
        )
        value = generate_field(field).value
        self.assertTrue(value["email"].endswith("@example.test"))
        self.assertIs(value["active"], False)

    def test_unsynthesizable_pattern_requires_review(self):
        field = FieldContract("code", data_type="string", required=True, pattern=r"[A-Z]{3}[0-9]{4}")
        result = generate_field(field)
        self.assertEqual(result.value, "{{REQUIRED:request.code}}")
        self.assertEqual(result.status, "review-recommended")


class ApprovalBlockerTests(TestCase):
    def test_canonical_and_legacy_mandatory_markers_block(self):
        value = {
            "new": "{{REQUIRED:resource.id}}",
            "legacy": "{{SECRET_TEST_TOKEN}}",
        }
        self.assertEqual(len(approval_blockers(value)), 2)

    def test_synthetic_and_negative_markers_do_not_block(self):
        value = ["{{SYNTHETIC:email}}", "{{INVALID_PRODUCT_ID}}"]
        self.assertEqual(approval_blockers(value), ())

    def test_generator_source_contains_no_fixture_specific_rules(self):
        root = Path(__file__).parents[1]
        source = (root / "app" / "smart_data" / "generator.py").read_text(encoding="utf-8").lower()
        for forbidden in ("leaf.ads-ai.in", "/admin/products", "category_id", "product_name"):
            self.assertNotIn(forbidden, source)
