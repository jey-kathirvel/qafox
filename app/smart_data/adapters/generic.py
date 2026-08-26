"""Conservative route fallback for otherwise unsupported source frameworks."""

from __future__ import annotations

import re

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.source_text import iter_source_text
from app.smart_data.contracts import (
    AuthFlowContract,
    AuthenticationMode,
    ConstraintContract,
    DetectionResult,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SourceEvidence,
    TestDataSource,
)

HTTP_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
CALL_ROUTE = re.compile(
    rf"(?:@?[A-Za-z_$][\w$]*(?:(?:\.|::)[A-Za-z_$][\w$]*)*)"
    rf"(?:\.|::)({HTTP_METHODS})\s*\(\s*([\"'])(/[^\"']*)\2",
    re.IGNORECASE,
)
KEYWORD_ROUTE = re.compile(
    rf"(?m)^\s*({HTTP_METHODS})\s+([\"'])(/[^\"']*)\2",
    re.IGNORECASE,
)
HANDLE_ROUTE = re.compile(
    r"\b(?:HandleFunc|Handle)\s*\(\s*([\"'])(/[^\"']*)\1"
)


def _canonical_path(value: str) -> str:
    path = re.sub(r"/+", "/", value.strip().replace("\\", "/"))
    path = re.sub(r"\{([A-Za-z_][\w]*)[^}]*\}", r"{\1}", path)
    path = re.sub(r"<[^:>]*:([^>]+)>", r"{\1}", path)
    path = re.sub(r":([A-Za-z_][\w]*)", r"{\1}", path)
    return path if path.startswith("/") else "/" + path


class GenericAdapter(FrameworkAdapter):
    name = "generic"
    adapter_version = "1"
    suffixes = frozenset(
        {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".cs", ".php", ".rb", ".go", ".rs"}
    )

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        found: dict[tuple[str, str], RouteContract] = {}
        for item in iter_source_text(project, self.suffixes):
            for pattern in (CALL_ROUTE, KEYWORD_ROUTE):
                for match in pattern.finditer(item.text):
                    method = match.group(1).upper()
                    path = _canonical_path(match.group(3))
                    line = item.text.count("\n", 0, match.start()) + 1
                    found.setdefault(
                        (method, path),
                        RouteContract(
                            method,
                            path,
                            "Generic",
                            confidence_score=58,
                            evidence=(
                                SourceEvidence(
                                    item.relative_path,
                                    source_line=line,
                                    evidence_type="generic-static-route",
                                    confidence_score=58,
                                ),
                            ),
                            warnings=("Framework was not identified; verify the fallback route.",),
                        ),
                    )
            for match in HANDLE_ROUTE.finditer(item.text):
                path = _canonical_path(match.group(2))
                line = item.text.count("\n", 0, match.start()) + 1
                found.setdefault(
                    ("GET", path),
                    RouteContract(
                        "GET",
                        path,
                        "Generic",
                        confidence_score=35,
                        evidence=(
                            SourceEvidence(
                                item.relative_path,
                                source_line=line,
                                evidence_type="generic-handler-path",
                                confidence_score=35,
                            ),
                        ),
                        warnings=("HTTP method was not declared and was inferred as GET.",),
                    ),
                )
        return list(found.values())

    def detect(self, project: ProjectRef) -> DetectionResult:
        routes = self.discover_routes(project)
        evidence = routes[0].evidence if routes else ()
        return DetectionResult(self.name, bool(routes), 58 if routes else 0, evidence=evidence)

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        return []

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return []

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [
            AuthFlowContract(
                "generic-unknown-auth",
                (AuthenticationMode.UNKNOWN,),
                False,
                confidence_score=20,
                evidence=route.evidence,
            )
            for route in self.discover_routes(project)
        ]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        return []
