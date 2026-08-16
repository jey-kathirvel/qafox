"""Interface implemented independently by every framework adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.smart_data.contracts import (
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    ProjectRef,
    RouteContract,
    SchemaContract,
    TestDataSource,
)


class FrameworkAdapter(ABC):
    name: str

    @abstractmethod
    def detect(self, project: ProjectRef) -> DetectionResult:
        raise NotImplementedError

    @abstractmethod
    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        raise NotImplementedError

    @abstractmethod
    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        raise NotImplementedError

    @abstractmethod
    def extract_constraints(
        self, project: ProjectRef
    ) -> list[ConstraintContract]:
        raise NotImplementedError

    @abstractmethod
    def extract_auth_flows(
        self, project: ProjectRef
    ) -> list[AuthFlowContract]:
        raise NotImplementedError

    @abstractmethod
    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        raise NotImplementedError
