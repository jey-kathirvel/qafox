"""Project-agnostic smart-data domain and adapter extension points."""

from app.smart_data.adapters import AdapterRegistry, FrameworkAdapter
from app.smart_data.contracts import (
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    FieldContract,
    PrerequisiteContract,
    RouteContract,
    RuntimeVariableContract,
    SchemaContract,
    SourceEvidence,
    TestDataSource,
    WorkflowActionContract,
)
from app.smart_data.dependency_graph import (
    DependencyGraphBuilder,
    TestDependencyGraph,
)

__all__ = [
    "AdapterRegistry",
    "AuthFlowContract",
    "ConstraintContract",
    "DetectionResult",
    "DependencyGraphBuilder",
    "FieldContract",
    "FrameworkAdapter",
    "PrerequisiteContract",
    "RouteContract",
    "RuntimeVariableContract",
    "SchemaContract",
    "SourceEvidence",
    "TestDataSource",
    "TestDependencyGraph",
    "WorkflowActionContract",
]
