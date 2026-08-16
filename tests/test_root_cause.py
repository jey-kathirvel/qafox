from unittest import TestCase

from app.smart_data.root_cause import classify_root_cause


class RootCauseTests(TestCase):
    def test_maps_assertion_text_deterministically(self):
        label = classify_root_cause(
            status="failed",
            assertion_summary="Missing required response field id",
        )
        self.assertIn("Contract mismatch", label)

    def test_does_not_call_an_external_model(self):
        self.assertEqual(
            classify_root_cause(status="error", error_message="Only public HTTPS targets are allowed."),
            "Blocked: target must be public HTTPS.",
        )
