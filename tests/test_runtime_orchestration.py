from unittest import TestCase

from app.smart_data.orchestration import (
    RuntimeStore,
    apply_orchestration_to_snapshot,
    build_orchestration,
    extract_runtime_value,
    infer_bindings,
    plan_blockers,
    remaining_dynamic,
    substitute_placeholders,
)
from app.smart_data.placeholders import build_placeholder, PlaceholderKind


def _case(public_id, method, path, **extra):
    payload = {
        "public_id": public_id,
        "http_method": method,
        "endpoint_path": path,
        "request_headers": "{}",
        "request_query": "{}",
        "request_body": extra.get("body"),
        "safe_to_execute": method in {"GET", "HEAD", "OPTIONS"},
    }
    payload.update(extra)
    return payload


class ExtractionTests(TestCase):
    def test_extracts_bounded_json_id_and_rejects_deep_or_secret_shapes(self):
        self.assertEqual(extract_runtime_value(body={"id": 42}, extraction="$.id"), "42")
        self.assertEqual(
            extract_runtime_value(body={"data": {"id": "ab12"}}, extraction="$.data.id"),
            "ab12",
        )
        self.assertIsNone(extract_runtime_value(body={"id": {"nested": 1}}, extraction="$.id"))
        self.assertIsNone(extract_runtime_value(body={"token": "a.b.c-secret-value-too-long-xxxxxxxxxxxxxxxxxxxxxxx"}, extraction="$.token"))
        self.assertEqual(
            extract_runtime_value(
                body={},
                headers={"Location": "https://example.test/items/99"},
                extraction="$.id",
            ),
            "99",
        )
        self.assertIsNone(extract_runtime_value(body={"id": 1}, extraction="$['id']"))
        self.assertIsNone(extract_runtime_value(body={"id": 1}, extraction="$.id; drop table"))


class BindingTests(TestCase):
    def test_post_collection_feeds_matching_resource_placeholder(self):
        create = _case("c1", "POST", "/v1/products", body={"name": "n"})
        read = _case(
            "c2",
            "GET",
            build_placeholder(PlaceholderKind.REQUIRED, "resource.product_id"),
        )
        # GET title path is the placeholder-only path used by generated cases.
        read["endpoint_path"] = (
            "/v1/products/"
            + build_placeholder(PlaceholderKind.REQUIRED, "resource.product_id")
        )
        bindings = infer_bindings([read, create])
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].producer_case_public_id, "c1")
        self.assertEqual(bindings[0].consumer_case_public_id, "c2")
        self.assertIn("DYNAMIC", bindings[0].placeholder)

    def test_unrelated_resources_are_not_bound(self):
        create = _case("c1", "POST", "/orders")
        read = _case(
            "c2",
            "GET",
            "/products/" + build_placeholder(PlaceholderKind.REQUIRED, "resource.product_id"),
        )
        self.assertEqual(infer_bindings([create, read]), ())


class SubstitutionAndPlanTests(TestCase):
    def test_dynamic_values_feed_dependents_and_block_when_missing(self):
        placeholder = build_placeholder(PlaceholderKind.DYNAMIC, "product.post.output.id")
        substituted = substitute_placeholders(
            {"path": f"/products/{placeholder}"},
            {"product.post.output.id": "17"},
        )
        self.assertEqual(substituted["path"], "/products/17")
        self.assertEqual(
            remaining_dynamic({"path": f"/products/{placeholder}"}),
            (placeholder,),
        )

    def test_plan_rewrites_required_and_allows_bound_dynamic(self):
        create = _case("c1", "POST", "/books", body={"title": "t"})
        read = _case(
            "c2",
            "GET",
            "/books/" + build_placeholder(PlaceholderKind.REQUIRED, "resource.book_id"),
        )
        plan = build_orchestration([create, read], cleanup_approved=True)
        self.assertTrue(plan.cleanup_approved)
        self.assertEqual(plan.execution_order[0], "c1")
        snapshot = apply_orchestration_to_snapshot(
            {
                "endpoint_path": read["endpoint_path"],
                "request_headers": {},
                "request_query": {},
                "request_body": None,
            },
            plan,
            "c2",
        )
        self.assertIn("DYNAMIC", snapshot["endpoint_path"])
        self.assertEqual(
            plan_blockers(
                {"path": snapshot["endpoint_path"]},
                plan,
                "c2",
            ),
            (),
        )
        self.assertEqual(plan.cleanup[0].method, "DELETE")
        self.assertTrue(plan.cleanup[0].same_run_only)

    def test_runtime_store_tracks_only_captured_values(self):
        store = RuntimeStore()
        store.remember("product.post.output.id", "9", created=True)
        self.assertEqual(store.created["product.post.output.id"], "9")
        store.failed_producers.add("c1")
        self.assertIn("c1", store.failed_producers)
