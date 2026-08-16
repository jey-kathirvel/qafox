from unittest import TestCase

from app.smart_data.assertions import (
    default_assertions,
    evaluate_assertions,
    success_response_fields,
)


class AssertionSpecTests(TestCase):
    def test_positive_cases_include_schema_when_response_fields_exist(self):
        specs = default_assertions(
            case_type="positive",
            expected_status_codes="200",
            response_fields=({"name": "id", "data_type": "integer", "required": True},),
        )
        kinds = [item["kind"] for item in specs]
        self.assertIn("status", kinds)
        self.assertIn("security.no_stack_trace", kinds)
        self.assertIn("security.no_secrets", kinds)
        self.assertIn("performance.duration", kinds)
        self.assertIn("schema.fields", kinds)

    def test_negative_cases_skip_schema_fields(self):
        kinds = [
            item["kind"]
            for item in default_assertions(
                case_type="authentication",
                expected_status_codes="401",
                response_fields=({"name": "id", "required": True},),
            )
        ]
        self.assertNotIn("schema.fields", kinds)


class AssertionEvaluationTests(TestCase):
    def test_status_security_schema_and_performance(self):
        specs = default_assertions(
            case_type="positive",
            expected_status_codes="201",
            response_fields=({"name": "id", "data_type": "integer", "required": True},),
        )
        passed, summary, outcomes = evaluate_assertions(
            specs,
            status_code=201,
            body='{"id": 9}',
            duration_ms=40,
            secret_values=["super-secret-token"],
            timeout_ms=1000,
        )
        self.assertTrue(passed, summary)
        self.assertTrue(all(item.passed for item in outcomes))

    def test_stack_trace_and_secret_echo_fail_security(self):
        specs = [
            {"id": "s", "kind": "security.no_stack_trace"},
            {"id": "k", "kind": "security.no_secrets"},
        ]
        passed, summary, _ = evaluate_assertions(
            specs,
            status_code=500,
            body='Traceback (most recent call last):\nSecret=super-secret-token',
            secret_values=["super-secret-token"],
        )
        self.assertFalse(passed)
        self.assertIn("stack trace", summary.lower())

    def test_missing_required_field_fails_schema(self):
        specs = [
            {
                "kind": "schema.fields",
                "fields": [{"name": "id", "data_type": "integer", "required": True}],
            }
        ]
        passed, summary, _ = evaluate_assertions(
            specs,
            status_code=200,
            body='{"title": "n"}',
        )
        self.assertFalse(passed)
        self.assertIn("id", summary)

    def test_duration_over_budget_fails(self):
        passed, summary, _ = evaluate_assertions(
            [{"kind": "performance.duration", "max_ms": 50}],
            status_code=200,
            body="{}",
            duration_ms=80,
            timeout_ms=50,
        )
        self.assertFalse(passed)
        self.assertIn("80ms", summary)

    def test_success_response_fields_prefer_2xx(self):
        fields = success_response_fields(
            {
                "responses": {
                    "400": {"fields": [{"name": "error", "required": True}]},
                    "201": {"fields": [{"name": "id", "required": True}]},
                }
            }
        )
        self.assertEqual(fields[0]["name"], "id")
