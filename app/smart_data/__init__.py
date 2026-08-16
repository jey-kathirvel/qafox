"""Project-agnostic smart-data domain and adapter extension points."""

from app.smart_data.adapters import AdapterRegistry, FrameworkAdapter, default_registry
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
from app.smart_data.persistence import (
    PersistenceIsolationError,
    persist_contracts,
    load_snapshot,
)

__all__ = [
    "AdapterRegistry",
    "PersistenceIsolationError",
    "AuthFlowContract",
    "ConstraintContract",
    "DetectionResult",
    "default_registry",
    "DependencyGraphBuilder",
    "FieldContract",
    "FrameworkAdapter",
    "load_snapshot",
    "persist_contracts",
    "PrerequisiteContract",
    "RouteContract",
    "RuntimeVariableContract",
    "SchemaContract",
    "SourceEvidence",
    "TestDataSource",
    "TestDependencyGraph",
    "WorkflowActionContract",
]
