"""Interface implemented independently by every framework adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from app.smart_data.contracts import (
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    ProjectRef,
    RouteContract,
    SchemaContract,
    TestDataSource,
)

if TYPE_CHECKING:
    from app.smart_data.uapi import AdapterCapability, ApiContract


class FrameworkAdapter(ABC):
    name: str
    adapter_version: str = ""

    @property
    def capabilities(self) -> frozenset[AdapterCapability]:
        from app.smart_data.capabilities import capabilities_for

        return capabilities_for(self.name)

    def normalize_contract(self, project: ProjectRef) -> ApiContract:
        from app.smart_data.uapi import UniversalContractNormalizer

        return UniversalContractNormalizer().normalize_adapter(self, project)

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
