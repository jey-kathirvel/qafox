from pathlib import Path
from unittest import TestCase

from app.smart_data.placeholders import (
    PlaceholderKind,
    apply_placeholder_safety,
    approval_blockers,
    build_placeholder,
    request_payload,
)


ROOT = Path(__file__).resolve().parents[1]


class DiscoveryFailureIsolationTests(TestCase):
    def test_load_snapshot_does_not_bind_untyped_nulls(self):
        source = (ROOT / "app" / "smart_data" / "persistence.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(":public_id IS NOT NULL", source)
        self.assertNotIn(":discovery_run_id IS NOT NULL", source)

    def test_discovery_persists_inventory_if_adapter_snapshot_fails(self):
        source = (ROOT / "app" / "api_discovery.py").read_text(encoding="utf-8")
        self.assertIn("begin_nested", source)
        self.assertIn("inventory_display_run", source)
        self.assertIn("AdapterCollection", source)

    def test_plan_page_keeps_unresolved_cases_out_of_auto_include(self):
        source = (ROOT / "app" / "execution_planning.py").read_text(encoding="utf-8")
        self.assertIn("unresolved_test_data", source)
        self.assertIn("Needs test data", source)
        self.assertIn("Edit test data", source)


class PlaceholderSafetyTests(TestCase):
    def test_required_path_placeholder_blocks_auto_safe_get(self):
        case = {
            "http_method": "GET",
            "endpoint_path": build_placeholder(
                PlaceholderKind.REQUIRED, "resource.product_id"
            ),
            "request_headers": "{}",
            "request_query": "{}",
            "request_body": None,
            "safe_to_execute": True,
            "requires_approval": False,
        }
        apply_placeholder_safety(case)
        self.assertFalse(case["safe_to_execute"])
        self.assertEqual(
            approval_blockers(request_payload(case)),
            ("{{REQUIRED:resource.product_id}}",),
        )

    def test_plain_get_stays_safe(self):
        case = {
            "http_method": "GET",
            "endpoint_path": "/",
            "request_headers": "{}",
            "request_query": "{}",
            "request_body": None,
            "safe_to_execute": True,
            "requires_approval": False,
        }
        apply_placeholder_safety(case)
        self.assertTrue(case["safe_to_execute"])
        self.assertEqual(approval_blockers(request_payload(case)), ())
