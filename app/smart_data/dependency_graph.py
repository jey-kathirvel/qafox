"""Normalized, deterministic dependency graphs for smart test workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from app.smart_data.contracts import (
    ActionKind,
    AuthFlowContract,
    PrerequisiteContract,
    RouteContract,
    RuntimeVariableContract,
    WorkflowActionContract,
)
from app.smart_data.placeholders import PlaceholderKind, build_placeholder


class NodeKind(str, Enum):
    AUTHENTICATION = "authentication"
    SETUP = "setup"
    RESOURCE = "resource"
    REQUEST_FIELD = "request-field"
    RUNTIME_EXTRACTION = "runtime-extraction"
    REQUEST = "request"
    ASSERTION = "assertion"
    CLEANUP = "cleanup"


@dataclass(frozen=True, slots=True)
class DependencyNode:
    node_id: str
    kind: NodeKind
    label: str
    route_reference: str = ""
    required: bool = True
    requires_approval: bool = False
    same_run_only: bool = False
    created_by_node_id: str = ""


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    source: str
    target: str
    relationship: str


@dataclass(frozen=True, slots=True)
class DynamicBinding:
    variable: RuntimeVariableContract
    producer_node_id: str
    consumer_node_id: str
    placeholder: str


@dataclass(slots=True)
class TestDependencyGraph:
    nodes: dict[str, DependencyNode] = field(default_factory=dict)
    edges: list[DependencyEdge] = field(default_factory=list)
    bindings: list[DynamicBinding] = field(default_factory=list)

    def add_node(self, node: DependencyNode) -> None:
        if not node.node_id:
            raise ValueError("Dependency nodes require an ID")
        if node.node_id in self.nodes:
            raise ValueError(f"Duplicate dependency node: {node.node_id}")
        self.nodes[node.node_id] = node

    def add_edge(self, edge: DependencyEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError("Dependency edges must reference existing nodes")
        if edge.source == edge.target:
            raise ValueError("Dependency nodes cannot depend on themselves")
        if edge not in self.edges:
            self.edges.append(edge)

    def add_binding(self, binding: DynamicBinding) -> None:
        if binding.producer_node_id not in self.nodes:
            raise ValueError("Dynamic binding producer does not exist")
        if binding.consumer_node_id not in self.nodes:
            raise ValueError("Dynamic binding consumer does not exist")
        expected = build_placeholder(PlaceholderKind.DYNAMIC, binding.variable.name)
        if binding.placeholder != expected:
            raise ValueError("Dynamic binding placeholder is not canonical")
        self.bindings.append(binding)
        self.add_edge(DependencyEdge(binding.producer_node_id, binding.consumer_node_id, "provides-runtime-value"))

    def ordered_node_ids(self) -> tuple[str, ...]:
        incoming = {node_id: 0 for node_id in self.nodes}
        outgoing: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            incoming[edge.target] += 1
            outgoing[edge.source].append(edge.target)
        ready = sorted(node_id for node_id, count in incoming.items() if count == 0)
        ordered: list[str] = []
        while ready:
            current = ready.pop(0)
            ordered.append(current)
            for target in sorted(outgoing[current]):
                incoming[target] -= 1
                if incoming[target] == 0:
                    ready.append(target)
                    ready.sort()
        if len(ordered) != len(self.nodes):
            raise ValueError("Dependency graph contains a cycle")
        return tuple(ordered)

    def validate_cleanup(self) -> None:
        for node in self.nodes.values():
            if node.kind is not NodeKind.CLEANUP:
                continue
            if not node.requires_approval:
                raise ValueError("Cleanup actions require explicit approval")
            if not node.same_run_only:
                raise ValueError("Cleanup actions must be limited to the same run")
            creator = self.nodes.get(node.created_by_node_id)
            if creator is None or creator.kind not in {NodeKind.SETUP, NodeKind.REQUEST}:
                raise ValueError("Cleanup actions require a same-graph creator")
            if not any(edge.source == creator.node_id and edge.target == node.node_id for edge in self.edges):
                raise ValueError("Cleanup must depend on its creator")

    def validate(self) -> tuple[str, ...]:
        ordered = self.ordered_node_ids()
        self.validate_cleanup()
        return ordered


def _safe_id(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "step"


class DependencyGraphBuilder:
    def build_route(self, route: RouteContract) -> TestDependencyGraph:
        graph = TestDependencyGraph()
        route_key = f"{route.method.upper()} {route.path}"
        request_id = "request:" + _safe_id(route.operation_id or route_key)
        graph.add_node(DependencyNode(request_id, NodeKind.REQUEST, route_key, route_key))

        predecessors: list[str] = []
        for position, auth in enumerate(route.authentication, start=1):
            if not auth.required:
                continue
            node_id = f"auth:{position}:{_safe_id(auth.name)}"
            graph.add_node(DependencyNode(node_id, NodeKind.AUTHENTICATION, auth.name, required=True))
            predecessors.append(node_id)

        setup_ids: dict[str, str] = {}
        for position, action in enumerate(route.setup_actions, start=1):
            if action.kind is not ActionKind.SETUP:
                raise ValueError("Setup action has an invalid action kind")
            node_id = f"setup:{position}:{_safe_id(action.name)}"
            setup_ids[action.name] = node_id
            graph.add_node(DependencyNode(node_id, NodeKind.SETUP, action.name, action.route_reference, requires_approval=action.requires_approval, same_run_only=action.same_run_only))
            for predecessor in predecessors:
                graph.add_edge(DependencyEdge(predecessor, node_id, "must-complete-before"))
            predecessors = [node_id]

        for position, prerequisite in enumerate(route.prerequisites, start=1):
            node_id = f"resource:{position}:{_safe_id(prerequisite.resource)}"
            graph.add_node(DependencyNode(node_id, NodeKind.RESOURCE, prerequisite.resource, required=prerequisite.required))
            for predecessor in predecessors:
                graph.add_edge(DependencyEdge(predecessor, node_id, "must-complete-before"))
            graph.add_edge(DependencyEdge(node_id, request_id, "required-resource"))

        for predecessor in predecessors:
            graph.add_edge(DependencyEdge(predecessor, request_id, "must-complete-before"))

        extraction_ids: dict[str, str] = {}
        for position, variable in enumerate(route.runtime_variables, start=1):
            node_id = f"extract:{position}:{_safe_id(variable.name)}"
            extraction_ids[variable.name] = node_id
            graph.add_node(DependencyNode(node_id, NodeKind.RUNTIME_EXTRACTION, variable.name, route_key))
            graph.add_edge(DependencyEdge(request_id, node_id, "extracts-runtime-value"))

        assertion_id = "assertion:" + _safe_id(route.operation_id or route_key)
        graph.add_node(DependencyNode(assertion_id, NodeKind.ASSERTION, f"Assert {route_key}", route_key))
        graph.add_edge(DependencyEdge(request_id, assertion_id, "asserts-response"))

        creator_candidates = [*setup_ids.values(), request_id]
        for position, action in enumerate(route.cleanup_actions, start=1):
            if action.kind is not ActionKind.CLEANUP:
                raise ValueError("Cleanup action has an invalid action kind")
            creator_id = setup_ids.get(action.name) or creator_candidates[-1]
            node_id = f"cleanup:{position}:{_safe_id(action.name)}"
            graph.add_node(DependencyNode(node_id, NodeKind.CLEANUP, action.name, action.route_reference, requires_approval=action.requires_approval, same_run_only=action.same_run_only, created_by_node_id=creator_id))
            graph.add_edge(DependencyEdge(assertion_id, node_id, "cleanup-after-assertion"))
            graph.add_edge(DependencyEdge(creator_id, node_id, "created-resource"))
        return graph

    def bind_dependent_route(
        self,
        graph: TestDependencyGraph,
        variable: RuntimeVariableContract,
        producer_node_id: str,
        consumer_node_id: str,
    ) -> DynamicBinding:
        binding = DynamicBinding(variable, producer_node_id, consumer_node_id, build_placeholder(PlaceholderKind.DYNAMIC, variable.name))
        graph.add_binding(binding)
        return binding
