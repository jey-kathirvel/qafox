from unittest import TestCase

from app.smart_data.contracts import (
    ActionKind,
    AuthenticationMode,
    AuthFlowContract,
    PrerequisiteContract,
    RouteContract,
    RuntimeVariableContract,
    WorkflowActionContract,
)
from app.smart_data.dependency_graph import (
    DependencyEdge,
    DependencyGraphBuilder,
    DependencyNode,
    NodeKind,
    TestDependencyGraph,
)


class DependencyGraphTests(TestCase):
    def test_builds_auth_setup_request_extract_assert_cleanup_sequence(self):
        route = RouteContract(
            "POST",
            "/records",
            "fixture",
            operation_id="create_record",
            authentication=(
                AuthFlowContract(
                    "session",
                    (AuthenticationMode.SESSION,),
                    required=True,
                ),
            ),
            prerequisites=(
                PrerequisiteContract("tenant", "id"),
            ),
            runtime_variables=(
                RuntimeVariableContract(
                    "create_record.output.id",
                    "create_record",
                    "$.id",
                    "integer",
                ),
            ),
            setup_actions=(
                WorkflowActionContract(
                    "prepare_tenant",
                    ActionKind.SETUP,
                    "POST /tenants",
                    requires_approval=True,
                ),
            ),
            cleanup_actions=(
                WorkflowActionContract(
                    "remove_record",
                    ActionKind.CLEANUP,
                    "DELETE /records/{id}",
                    requires_approval=True,
                    same_run_only=True,
                ),
            ),
        )
        graph = DependencyGraphBuilder().build_route(route)
        ordered = graph.validate()
        kinds = [graph.nodes[node_id].kind for node_id in ordered]
        self.assertLess(kinds.index(NodeKind.AUTHENTICATION), kinds.index(NodeKind.SETUP))
        self.assertLess(kinds.index(NodeKind.REQUEST), kinds.index(NodeKind.RUNTIME_EXTRACTION))
        self.assertLess(kinds.index(NodeKind.ASSERTION), kinds.index(NodeKind.CLEANUP))

    def test_dynamic_output_can_feed_dependent_request(self):
        graph = TestDependencyGraph()
        graph.add_node(DependencyNode("request:create", NodeKind.REQUEST, "Create"))
        graph.add_node(DependencyNode("request:read", NodeKind.REQUEST, "Read"))
        variable = RuntimeVariableContract(
            "create.output.id",
            "request:create",
            "$.id",
            "integer",
        )
        binding = DependencyGraphBuilder().bind_dependent_route(
            graph,
            variable,
            "request:create",
            "request:read",
        )
        self.assertEqual(binding.placeholder, "{{DYNAMIC:create.output.id}}")
        self.assertEqual(graph.validate(), ("request:create", "request:read"))

    def test_cycle_is_rejected(self):
        graph = TestDependencyGraph()
        graph.add_node(DependencyNode("one", NodeKind.REQUEST, "One"))
        graph.add_node(DependencyNode("two", NodeKind.REQUEST, "Two"))
        graph.add_edge(DependencyEdge("one", "two", "depends"))
        graph.add_edge(DependencyEdge("two", "one", "depends"))
        with self.assertRaisesRegex(ValueError, "cycle"):
            graph.validate()

    def test_cleanup_without_approval_is_rejected(self):
        graph = TestDependencyGraph()
        graph.add_node(DependencyNode("create", NodeKind.REQUEST, "Create"))
        graph.add_node(
            DependencyNode(
                "cleanup",
                NodeKind.CLEANUP,
                "Cleanup",
                requires_approval=False,
                same_run_only=True,
                created_by_node_id="create",
            )
        )
        graph.add_edge(DependencyEdge("create", "cleanup", "created-resource"))
        with self.assertRaisesRegex(ValueError, "approval"):
            graph.validate()

    def test_cleanup_outside_same_run_is_rejected(self):
        graph = TestDependencyGraph()
        graph.add_node(DependencyNode("create", NodeKind.REQUEST, "Create"))
        graph.add_node(
            DependencyNode(
                "cleanup",
                NodeKind.CLEANUP,
                "Cleanup",
                requires_approval=True,
                same_run_only=False,
                created_by_node_id="create",
            )
        )
        graph.add_edge(DependencyEdge("create", "cleanup", "created-resource"))
        with self.assertRaisesRegex(ValueError, "same run"):
            graph.validate()

    def test_optional_authentication_does_not_block_public_route(self):
        route = RouteContract(
            "GET",
            "/status",
            "fixture",
            authentication=(
                AuthFlowContract(
                    "optional",
                    (AuthenticationMode.OPTIONAL,),
                    required=False,
                ),
            ),
        )
        graph = DependencyGraphBuilder().build_route(route)
        self.assertNotIn(NodeKind.AUTHENTICATION, {node.kind for node in graph.nodes.values()})
