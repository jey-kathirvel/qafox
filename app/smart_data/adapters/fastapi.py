"""AST-only FastAPI/Pydantic adapter."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.python_source import (
    ParsedPython,
    annotation_name,
    call_string,
    dotted_name,
    iter_python,
    keyword,
    source_excerpt,
    static_value,
)
from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    DependencyRelationship,
    FieldContract,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SemanticType,
    SourceEvidence,
    TestDataSource,
)


HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "api_route"}
FIELD_CONSTRAINTS = {"gt", "ge", "lt", "le", "min_length", "max_length", "pattern", "regex", "multiple_of"}


def _join(*parts: str) -> str:
    value = "/" + "/".join(part.strip("/") for part in parts if part and part != "/")
    return value if value != "" else "/"


def _relative_module(current: str, imported: str | None, level: int) -> str:
    if level == 0:
        return imported or ""
    package = current.split(".")[:-1]
    keep = max(0, len(package) - level + 1)
    prefix = package[:keep]
    if imported:
        prefix.extend(imported.split("."))
    return ".".join(prefix)


def _evidence(parsed: ParsedPython, node: ast.AST, kind: str) -> tuple[SourceEvidence, ...]:
    return (
        SourceEvidence(
            parsed.relative_path,
            getattr(node, "lineno", None),
            getattr(node, "col_offset", None),
            kind,
            source_excerpt(parsed, node),
            95,
        ),
    )


def _semantic(name: str, annotation: str, constraints: dict[str, Any]) -> SemanticType:
    lowered, kind = name.lower(), annotation.lower()
    schema_format = str(constraints.get("format", "")).lower()
    if schema_format == "email" or "email" in kind:
        return SemanticType.EMAIL
    if "uuid" in kind:
        return SemanticType.UUID
    if "datetime" in kind:
        return SemanticType.DATETIME
    if kind.endswith("date") or "date" == kind:
        return SemanticType.DATE
    if "secret" in kind or "password" in lowered or "token" in lowered:
        return SemanticType.SECRET
    if lowered.endswith("_id") or (lowered.endswith("id") and lowered != "id"):
        return SemanticType.FOREIGN_KEY
    if lowered == "id":
        return SemanticType.IDENTIFIER
    if "bool" in kind:
        return SemanticType.BOOLEAN
    if "int" in kind:
        return SemanticType.INTEGER
    if any(item in kind for item in ("float", "decimal")):
        return SemanticType.DECIMAL
    if any(item in kind for item in ("list", "tuple", "set")):
        return SemanticType.ARRAY
    if constraints.get("enum"):
        return SemanticType.ENUM
    return SemanticType.UNKNOWN


def _field_from_nodes(
    parsed: ParsedPython,
    name: str,
    annotation_node: ast.AST | None,
    default_node: ast.AST | None,
) -> FieldContract:
    annotation = annotation_name(annotation_node) or "unknown"
    required = default_node is None
    default: Any = static_value(default_node)
    constraints: dict[str, Any] = {}
    if isinstance(default_node, ast.Call) and dotted_name(default_node.func).split(".")[-1] in {"Field", "Query", "Path", "Header", "Cookie", "Body", "Form", "File"}:
        if default_node.args:
            first = static_value(default_node.args[0])
            required = isinstance(default_node.args[0], ast.Constant) and default_node.args[0].value is Ellipsis
            default = None if required else first
        for item in default_node.keywords:
            if item.arg:
                value = static_value(item.value)
                if item.arg in FIELD_CONSTRAINTS or item.arg in {"format", "enum"}:
                    constraints[item.arg] = value
                elif item.arg == "default":
                    default, required = value, False
    optional = "optional[" in annotation.lower() or "none" in annotation.lower()
    semantic = _semantic(name, annotation, constraints)
    dependency = DependencyRelationship(name.removesuffix("_id"), "id", confidence_score=75) if semantic is SemanticType.FOREIGN_KEY else None
    minimum = constraints.get("ge", constraints.get("gt"))
    maximum = constraints.get("le", constraints.get("lt"))
    contracts = tuple(ConstraintContract(key, value, confidence_score=95, evidence=_evidence(parsed, default_node or annotation_node or parsed.tree, "pydantic-constraint")) for key, value in constraints.items())
    return FieldContract(
        name=name,
        semantic_type=semantic,
        data_type=annotation,
        required=required and not optional,
        default_value=default,
        minimum=minimum,
        maximum=maximum,
        min_length=constraints.get("min_length"),
        max_length=constraints.get("max_length"),
        pattern=str(constraints.get("pattern") or constraints.get("regex") or ""),
        nullable=optional,
        secret=semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN},
        dependency=dependency,
        confidence_score=95,
        source_file=parsed.relative_path,
        source_line=getattr(annotation_node, "lineno", None),
        constraints=contracts,
        evidence=_evidence(parsed, annotation_node or default_node or parsed.tree, "pydantic-field"),
    )


@dataclass(slots=True)
class _Router:
    parsed: ParsedPython
    variable: str
    prefix: str
    is_root: bool


@dataclass(slots=True)
class _Route:
    parsed: ParsedPython
    router: tuple[str, str]
    function: ast.FunctionDef | ast.AsyncFunctionDef
    decorator: ast.Call
    method: str
    path: str


@dataclass(slots=True)
class _Index:
    routers: dict[tuple[str, str], _Router] = field(default_factory=dict)
    imports: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    edges: list[tuple[tuple[str, str], tuple[str, str], str]] = field(default_factory=list)
    routes: list[_Route] = field(default_factory=list)
    models: dict[str, SchemaContract] = field(default_factory=dict)


class FastAPIAdapter(FrameworkAdapter):
    name = "fastapi"

    def _index(self, project: ProjectRef) -> _Index:
        index = _Index()
        parsed_files = list(iter_python(project))
        for parsed in parsed_files:
            for node in parsed.tree.body:
                if isinstance(node, ast.ImportFrom):
                    target_module = _relative_module(parsed.module, node.module, node.level)
                    for alias in node.names:
                        index.imports[(parsed.module, alias.asname or alias.name)] = (target_module, alias.name)
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if isinstance(value, ast.Call):
                        constructor = dotted_name(value.func).split(".")[-1]
                        if constructor in {"FastAPI", "APIRouter"}:
                            prefix = call_string(value, keyword_name="prefix")
                            for target in targets:
                                if isinstance(target, ast.Name):
                                    index.routers[(parsed.module, target.id)] = _Router(parsed, target.id, prefix, constructor == "FastAPI")
                if isinstance(node, ast.ClassDef) and any(dotted_name(base).split(".")[-1] in {"BaseModel", "GenericModel"} for base in node.bases):
                    fields = []
                    for child in node.body:
                        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                            fields.append(_field_from_nodes(parsed, child.target.id, child.annotation, child.value))
                    index.models[node.name] = SchemaContract(node.name, "object", tuple(fields), confidence_score=96, evidence=_evidence(parsed, node, "pydantic-model"))
        for parsed in parsed_files:
            for node in ast.walk(parsed.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router" and isinstance(node.func.value, ast.Name) and node.args:
                    parent = (parsed.module, node.func.value.id)
                    child_expr = node.args[0]
                    if isinstance(child_expr, ast.Name):
                        child = index.imports.get((parsed.module, child_expr.id), (parsed.module, child_expr.id))
                        index.edges.append((parent, child, call_string(node, keyword_name="prefix")))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                            continue
                        method = decorator.func.attr.lower()
                        if method not in HTTP_DECORATORS or not isinstance(decorator.func.value, ast.Name):
                            continue
                        methods = static_value(keyword(decorator, "methods")) if method == "api_route" else None
                        route_methods = [str(item).upper() for item in methods] if isinstance(methods, (list, tuple)) else [method.upper()]
                        for route_method in route_methods:
                            index.routes.append(_Route(parsed, (parsed.module, decorator.func.value.id), node, decorator, route_method, call_string(decorator)))
        return index

    @staticmethod
    def _bases(index: _Index) -> dict[tuple[str, str], str]:
        bases: dict[tuple[str, str], str] = {key: "" for key, router in index.routers.items() if router.is_root}
        changed = True
        while changed:
            changed = False
            for parent, child, edge_prefix in index.edges:
                if parent not in bases or child not in index.routers:
                    continue
                candidate = _join(bases[parent], index.routers[parent].prefix, edge_prefix)
                if child not in bases or len(candidate) < len(bases[child]):
                    bases[child] = candidate
                    changed = True
        return bases

    def detect(self, project: ProjectRef) -> DetectionResult:
        index = self._index(project)
        routers = list(index.routers.values())
        if not routers:
            return DetectionResult(self.name, False, 0)
        evidence = tuple(SourceEvidence(item.parsed.relative_path, evidence_type="fastapi-constructor", confidence_score=98) for item in routers[:10])
        return DetectionResult(self.name, True, 98, evidence=evidence)

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        index = self._index(project)
        bases = self._bases(index)
        contracts: list[RouteContract] = []
        for route in index.routes:
            router = index.routers.get(route.router)
            if router is None:
                continue
            full_path = _join(bases.get(route.router, ""), router.prefix, route.path)
            request_fields: list[FieldContract] = []
            request_schemas: list[SchemaContract] = []
            for argument, default in self._arguments(route.function):
                annotation = annotation_name(argument.annotation)
                model_name = annotation.split("[")[-1].rstrip("]") if "[" in annotation else annotation
                if model_name in index.models:
                    request_schemas.append(index.models[model_name])
                elif argument.arg not in {"request", "response", "db", "session", "self"}:
                    request_fields.append(_field_from_nodes(route.parsed, argument.arg, argument.annotation, default))
            if request_fields:
                request_schemas.append(SchemaContract("parameters", "object", tuple(request_fields), confidence_score=92, evidence=_evidence(route.parsed, route.function, "route-parameters")))
            authentication = (self._authentication(route),)
            contracts.append(RouteContract(route.method, full_path, "FastAPI", route.function.name, ast.get_docstring(route.function) or "", tuple(request_schemas), authentication=authentication, confidence_score=97, evidence=_evidence(route.parsed, route.decorator, "fastapi-route")))
        return contracts

    @staticmethod
    def _arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.AST | None]]:
        args = [*function.args.posonlyargs, *function.args.args]
        defaults: list[ast.AST | None] = [None] * (len(args) - len(function.args.defaults)) + list(function.args.defaults)
        return list(zip(args, defaults))

    def _authentication(self, route: _Route) -> AuthFlowContract:
        names = {dotted_name(node) for node in ast.walk(route.function) if isinstance(node, (ast.Call, ast.Attribute, ast.Name))}
        lowered = " ".join(names).lower()
        modes: list[AuthenticationMode] = []
        if any(signal in lowered for signal in ("oauth2", "securityscopes")):
            modes.append(AuthenticationMode.OAUTH2)
        if any(signal in lowered for signal in ("bearer", "get_current_user", "current_user")):
            modes.append(AuthenticationMode.BEARER)
        if "api_key" in lowered or "apikey" in lowered:
            modes.append(AuthenticationMode.API_KEY)
        if "session" in lowered:
            modes.append(AuthenticationMode.SESSION)
        if "csrf" in lowered:
            modes.append(AuthenticationMode.DYNAMIC_CSRF)
        modes = list(dict.fromkeys(modes))
        return AuthFlowContract("fastapi-source-auth", tuple(modes) or (AuthenticationMode.PUBLIC,), bool(modes), confidence_score=85 if modes else 65, evidence=_evidence(route.parsed, route.function, "authentication"))

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        return list(self._index(project).models.values())

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return [constraint for schema in self.extract_schemas(project) for field in schema.fields for constraint in field.constraints]

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [flow for route in self.discover_routes(project) for flow in route.authentication]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        return []
