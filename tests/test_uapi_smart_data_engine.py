from pathlib import Path
from unittest import TestCase

from app.smart_data.contracts import (
    DependencyRelationship,
    FieldContract,
    SemanticType,
)
from app.smart_data.generator import (
    CandidateClass,
    classify_field,
    generate_candidates,
    generate_field,
)


class SmartDataEngineV2Tests(TestCase):
    def test_primitives_and_formats(self):
        cases = [
            (FieldContract("label", data_type="string"), str),
            (FieldContract("count", SemanticType.INTEGER, "integer"), int),
            (FieldContract("ratio", SemanticType.DECIMAL, "number"), float),
            (FieldContract("price", SemanticType.CURRENCY, "number"), float),
            (FieldContract("active", SemanticType.BOOLEAN, "boolean"), bool),
            (FieldContract("id", SemanticType.UUID, "string", format="uuid"), str),
            (FieldContract("born", SemanticType.DATE, "string", format="date"), str),
            (FieldContract("when", SemanticType.DATETIME, "string", format="date-time"), str),
            (FieldContract("clock", format="time"), str),
            (FieldContract("home", SemanticType.EMAIL, "string"), str),
            (FieldContract("phone", SemanticType.PHONE, "string"), str),
            (FieldContract("site", format="url"), str),
            (FieldContract("ref", format="uri"), str),
            (FieldContract("v4", format="ipv4"), str),
            (FieldContract("v6", format="ipv6"), str),
            (FieldContract("host", format="hostname"), str),
        ]
        for field, expected in cases:
            value = generate_field(field, seed=7).value
            self.assertIsInstance(value, expected, field.name)
        self.assertTrue(generate_field(FieldContract("home", format="email")).value.endswith("@example.test"))
        self.assertEqual(generate_field(FieldContract("v4", format="ipv4")).value, "192.0.2.1")
        self.assertEqual(generate_field(FieldContract("host", format="hostname")).value, "example.test")
        self.assertEqual(generate_field(FieldContract("clock", format="time")).value, "12:00:00")

    def test_numeric_constraints_and_exclusive_bounds(self):
        field = FieldContract(
            "quantity",
            SemanticType.INTEGER,
            "integer",
            True,
            minimum=3,
            maximum=9,
            exclusive_minimum=True,
            exclusive_maximum=True,
            multiple_of=2,
        )
        valid = generate_field(field, seed=1).value
        self.assertGreater(valid, 3)
        self.assertLess(valid, 9)
        self.assertEqual(valid % 2, 0)
        classes = {item.candidate_class: item for item in generate_candidates(field, seed=1)}
        self.assertLess(classes[CandidateClass.BELOW_MIN.value].value, 3)
        self.assertGreater(classes[CandidateClass.ABOVE_MAX.value].value, 9)
        self.assertEqual(classes[CandidateClass.INVALID_TYPE.value].value, "not-a-number")

    def test_string_length_regex_enum_and_special_characters(self):
        sized = FieldContract("title", data_type="string", min_length=2, max_length=8)
        classes = {item.candidate_class: item for item in generate_candidates(sized, seed=2)}
        self.assertEqual(len(classes[CandidateClass.BOUNDARY_MIN.value].value), 2)
        self.assertEqual(len(classes[CandidateClass.BOUNDARY_MAX.value].value), 8)
        self.assertEqual(len(classes[CandidateClass.TOO_SHORT.value].value), 1)
        self.assertEqual(len(classes[CandidateClass.TOO_LONG.value].value), 9)
        self.assertEqual(classes[CandidateClass.EMPTY.value].value, "")
        self.assertTrue(set(classes[CandidateClass.SPECIAL_CHARACTERS.value].value) <= set("A.-_~x"))
        self.assertNotIn("<", classes[CandidateClass.SPECIAL_CHARACTERS.value].value)
        patterned = generate_field(FieldContract("code", pattern=r"[A-Z]{3}[0-9]{4}"), seed=3)
        self.assertRegex(patterned.value, r"^[A-Z]{3}[0-9]{4}$")
        enum_field = FieldContract("genre", enum_values=("fiction", "reference"))
        self.assertEqual(generate_field(enum_field).value, "fiction")
        self.assertEqual(
            {item.candidate_class: item.value for item in generate_candidates(enum_field)}[CandidateClass.INVALID_ENUM.value],
            "not-in-enum",
        )

    def test_arrays_objects_composition_required_nullable(self):
        item = FieldContract("tag", data_type="string", min_length=1)
        array = FieldContract("tags", data_type="array", min_items=2, max_items=3, unique_items=True, items=item)
        valid = generate_field(array, seed=4).value
        self.assertIsInstance(valid, list)
        self.assertGreaterEqual(len(valid), 2)
        nested = FieldContract(
            "profile",
            SemanticType.OBJECT,
            "object",
            children=(
                FieldContract("email", SemanticType.EMAIL, "string", True),
                FieldContract("city", data_type="string"),
            ),
        )
        profile = generate_field(nested, seed=4).value
        self.assertTrue(profile["email"].endswith("@example.test"))
        self.assertEqual(profile["city"], "Example City")
        composed = FieldContract(
            "amount",
            data_type="number",
            all_of=(
                FieldContract("amount", SemanticType.DECIMAL, "number", minimum=1),
                FieldContract("amount", SemanticType.DECIMAL, "number", maximum=5),
            ),
        )
        amount = generate_field(composed, seed=5).value
        self.assertGreaterEqual(amount, 1)
        self.assertLessEqual(amount, 5)
        one_of = FieldContract(
            "flag",
            one_of=(
                FieldContract("flag", SemanticType.BOOLEAN, "boolean"),
                FieldContract("flag", SemanticType.INTEGER, "integer"),
            ),
        )
        self.assertIsInstance(generate_field(one_of, seed=5).value, bool)
        required = FieldContract("title", data_type="string", required=True, min_length=1)
        nullable = FieldContract("nickname", data_type="string", nullable=True)
        required_classes = {item.candidate_class: item for item in generate_candidates(required)}
        nullable_classes = {item.candidate_class: item for item in generate_candidates(nullable)}
        self.assertIn(CandidateClass.MISSING_REQUIRED.value, required_classes)
        self.assertIsNone(nullable_classes[CandidateClass.NULL.value].value)
        self.assertEqual(nullable_classes[CandidateClass.NULL.value].status, "ready")

    def test_secrets_foreign_keys_and_determinism(self):
        secret = generate_field(
            FieldContract("password", SemanticType.SECRET, "string", True, default_value="must-not-copy", secret=True),
            seed=9,
        )
        self.assertEqual(secret.value, "{{SECRET_REF:configuration.password}}")
        self.assertTrue(secret.masked)
        self.assertEqual(secret.secret_reference, secret.value)
        self.assertNotIn("must-not-copy", repr(secret))
        secret_classes = [item.candidate_class for item in generate_candidates(FieldContract("token", secret=True))]
        self.assertNotIn(CandidateClass.SPECIAL_CHARACTERS.value, secret_classes)
        fk = generate_field(
            FieldContract(
                "publisher_id",
                SemanticType.FOREIGN_KEY,
                "integer",
                True,
                dependency=DependencyRelationship("publisher", "id"),
            )
        )
        self.assertEqual(fk.value, "{{REQUIRED:publisher.id}}")
        self.assertEqual(fk.runtime_dependency, "publisher.id")
        field = FieldContract("contact", format="email")
        self.assertEqual(generate_field(field, seed=11).value, generate_field(field, seed=11).value)
        self.assertNotEqual(generate_field(field, seed=11).value, generate_field(field, seed=12).value)

    def test_semantic_names_are_generic_and_framework_neutral(self):
        names = {
            "email": SemanticType.EMAIL,
            "phone": SemanticType.PHONE,
            "mobile": SemanticType.PHONE,
            "first_name": SemanticType.HUMAN_NAME,
            "last_name": SemanticType.HUMAN_NAME,
            "full_name": SemanticType.HUMAN_NAME,
            "username": SemanticType.ENTITY_NAME,
            "password": SemanticType.SECRET,
            "city": SemanticType.ENTITY_NAME,
            "state": SemanticType.ENTITY_NAME,
            "country": SemanticType.ENTITY_NAME,
            "postal_code": SemanticType.ENTITY_NAME,
            "zip_code": SemanticType.ENTITY_NAME,
            "currency": SemanticType.CURRENCY,
            "amount": SemanticType.CURRENCY,
            "price": SemanticType.CURRENCY,
            "quantity": SemanticType.INTEGER,
            "latitude": SemanticType.DECIMAL,
            "longitude": SemanticType.DECIMAL,
            "date": SemanticType.DATE,
            "timestamp": SemanticType.DATETIME,
            "url": SemanticType.URL,
        }
        for name, expected in names.items():
            semantic, _, reason = classify_field(FieldContract(name))
            self.assertEqual(semantic, expected, name)
            self.assertIn("name-based", reason)
        left = generate_field(FieldContract("contact_email", format="email"), seed=3)
        right = generate_field(FieldContract("contact_email", SemanticType.EMAIL, "string", format="email"), seed=3)
        self.assertEqual(left.value, right.value)
        self.assertTrue(left.value.endswith("@example.test"))
        source = Path(__file__).parents[1].joinpath("app", "smart_data", "generator.py").read_text(encoding="utf-8").lower()
        for forbidden in ("leaf.ads-ai.in", "360.ads-ai.in", "category_id", "product_name"):
            self.assertNotIn(forbidden, source)

    def test_provenance_is_recorded(self):
        result = generate_field(FieldContract("title", data_type="string", min_length=2), seed=8)
        self.assertEqual(result.candidate_class, CandidateClass.VALID.value)
        self.assertEqual(result.seed, 8)
        self.assertEqual(result.source_constraint, "minLength")
        self.assertTrue(result.semantic_inference)
        self.assertFalse(result.masked)
        self.assertEqual(result.secret_reference, "")
        self.assertEqual(result.runtime_dependency, "")
