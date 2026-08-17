"""AST-only FastAPI/Pydantic adapter."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.python_source import (
    ParsedPython,
    annotation_is_optional,
    annotation_name,
    call_string,
    dotted_name,
    iter_python,
    keyword,
    source_excerpt,
    static_value,
    unwrap_annotated,
)
from app.smart_data.adapters.semantics import field_contract
from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    FieldContract,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SourceEvidence,
    TestDataSource,
)


HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "api_route"}
FIELD_CONSTRAINTS = {"gt", "ge", "lt", "le", "min_length", "max_length", "pattern", "regex", "multiple_of"}
PARAM_CTORS = {"Field", "Query", "Path", "Header", "Cookie", "Body", "Form", "File"}
LOCATION_BY_CTOR = {
    "Path": "path-parameters",
    "Query": "query-parameters",
    "Header": "header-parameters",
    "Cookie": "cookie-parameters",
    "Body": "request-body",
    "Form": "form-data",
    "File": "form-data",
    "Field": "",
}


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


def _literal_values(node: ast.AST | None) -> tuple[Any, ...]:
    if not isinstance(node, ast.Subscript) or dotted_name(node.value).split(".")[-1] != "Literal":
        return ()
    slice_node = node.slice
    elts = slice_node.elts if isinstance(slice_node, ast.Tuple) else [slice_node]
    values = [static_value(item) for item in elts]
    return tuple(item for item in values if item is not None)


def _ctor_constraints(call: ast.Call) -> tuple[dict[str, Any], bool, Any]:
    constraints: dict[str, Any] = {}
    required = bool(call.args) and isinstance(call.args[0], ast.Constant) and call.args[0].value is Ellipsis
    default: Any = None if required else (static_value(call.args[0]) if call.args else None)
    for item in call.keywords:
        if not item.arg:
            continue
        value = static_value(item.value)
        if item.arg in FIELD_CONSTRAINTS or item.arg in {"format", "enum"}:
            constraints[item.arg] = value
        elif item.arg == "default":
            default, required = value, False
    return constraints, required, default


def _field_from_nodes(
    parsed: ParsedPython,
    name: str,
    annotation_node: ast.AST | None,
    default_node: ast.AST | None,
    *,
    enums: dict[str, tuple[Any, ...]] | None = None,
    models: dict[str, SchemaContract] | None = None,
) -> FieldContract:
    core, extras = unwrap_annotated(annotation_node)
    annotation = annotation_name(core) or annotation_name(annotation_node) or "unknown"
    required = default_node is None
    default: Any = static_value(default_node)
    constraints: dict[str, Any] = {}
    calls: list[ast.Call] = [item for item in extras if isinstance(item, ast.Call)]
    if isinstance(default_node, ast.Call) and dotted_name(default_node.func).split(".")[-1] in PARAM_CTORS:
        calls.append(default_node)
    for call in calls:
        ctor = dotted_name(call.func).split(".")[-1]
        if ctor not in PARAM_CTORS:
            continue
        extra, ctor_required, ctor_default = _ctor_constraints(call)
        constraints.update(extra)
        required = ctor_required
        default = ctor_default
    optional = annotation_is_optional(core) or "optional[" in annotation.lower() or "| none" in annotation.lower()
    enum_values = _literal_values(core)
    simple = annotation.split("[")[0].split(".")[-1]
    if enums and simple in enums:
        enum_values = enums[simple] or enum_values
        constraints["enum"] = list(enum_values)
    children: tuple[FieldContract, ...] = ()
    model_name = annotation.split("[")[-1].rstrip("]").split(".")[-1] if "[" in annotation else simple
    if models and model_name in models and model_name not in {"list", "dict", "optional", "union", "annotated"}:
        children = models[model_name].fields
    exclusive_min = constraints["gt"] if "gt" in constraints else None
    exclusive_max = constraints["lt"] if "lt" in constraints else None
    ev = _evidence(parsed, annotation_node or default_node or parsed.tree, "pydantic-field")
    return field_contract(
        name,
        type_hint=annotation,
        format_hint=str(constraints.get("format") or ""),
        validators=[annotation, *constraints.keys()],
        required=required and not optional,
        nullable=optional,
        default_value=default,
        minimum=constraints.get("ge", constraints.get("gt")),
        maximum=constraints.get("le", constraints.get("lt")),
        min_length=constraints.get("min_length"),
        max_length=constraints.get("max_length"),
        pattern=str(constraints.get("pattern") or constraints.get("regex") or ""),
        enum_values=enum_values,
        evidence=ev,
        source_file=parsed.relative_path,
        source_line=getattr(annotation_node, "lineno", None),
        extra_constraints=tuple(
            ConstraintContract(key, value, confidence_score=95, evidence=ev)
            for key, value in constraints.items()
        ),
        children=children,
        confidence_score=95,
        exclusive_minimum=exclusive_min,
        exclusive_maximum=exclusive_max,
    )


def _parameter_location(
    name: str,
    path: str,
    annotation_node: ast.AST | None,
    default_node: ast.AST | None,
    models: dict[str, SchemaContract],
) -> str:
    core, extras = unwrap_annotated(annotation_node)
    calls = [item for item in extras if isinstance(item, ast.Call)]
    if isinstance(default_node, ast.Call):
        calls.append(default_node)
    for call in calls:
        ctor = dotted_name(call.func).split(".")[-1]
        if ctor in LOCATION_BY_CTOR and LOCATION_BY_CTOR[ctor]:
            return LOCATION_BY_CTOR[ctor]
        if ctor == "Depends" or ctor == "Security":
            return "depends"
    annotation = annotation_name(core) or annotation_name(annotation_node)
    simple = annotation.split("[")[-1].rstrip("]").split(".")[-1]
    if simple in models:
        return "request-body"
    path_names = {token.strip("{}<>").split(":")[-1] for token in re.findall(r"\{[^}]+\}|<[^>]+>", path)}
    if name in path_names or "{" + name + "}" in path:
        return "path-parameters"
    return "query-parameters"


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
    model_nodes: dict[str, tuple[ParsedPython, ast.ClassDef]] = field(default_factory=dict)
    enums: dict[str, tuple[Any, ...]] = field(default_factory=dict)


class FastAPIAdapter(FrameworkAdapter):
    name = "fastapi"
    adapter_version = "2"

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
                if isinstance(node, ast.ClassDef):
                    base_names = {dotted_name(base).split(".")[-1] for base in node.bases}
                    if base_names & {"Enum", "IntEnum", "StrEnum"}:
                        values = []
                        for child in node.body:
                            if isinstance(child, ast.Assign):
                                for target in child.targets:
                                    if isinstance(target, ast.Name):
                                        value = static_value(child.value)
                                        values.append(value if value is not None else target.id)
                        index.enums[node.name] = tuple(values)
                    if base_names & {"BaseModel", "GenericModel"}:
                        index.model_nodes[node.name] = (parsed, node)
        changed = True
        while changed:
            changed = False
            for parsed in parsed_files:
                for node in parsed.tree.body:
                    if not isinstance(node, ast.ClassDef) or node.name in index.model_nodes:
                        continue
                    if any(dotted_name(base).split(".")[-1] in index.model_nodes for base in node.bases):
                        index.model_nodes[node.name] = (parsed, node)
                        changed = True
        self._materialize_models(index)
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

    def _materialize_models(self, index: _Index, pending: set[str] | None = None) -> None:
        pending = pending or set()
        progress = True
        while progress:
            progress = False
            for name, (parsed, node) in list(index.model_nodes.items()):
                if name in index.models:
                    continue
                parent_fields: list[FieldContract] = []
                ready = True
                for base in node.bases:
                    base_name = dotted_name(base).split(".")[-1]
                    if base_name in {"BaseModel", "GenericModel"}:
                        continue
                    if base_name in index.model_nodes and base_name not in index.models:
                        ready = False
                        break
                    if base_name in index.models:
                        parent_fields.extend(index.models[base_name].fields)
                if not ready:
                    continue
                fields = list(parent_fields)
                seen = {field.name for field in fields}
                for child in node.body:
                    if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                        field = _field_from_nodes(
                            parsed,
                            child.target.id,
                            child.annotation,
                            child.value,
                            enums=index.enums,
                            models=index.models,
                        )
                        if field.name in seen:
                            fields = [item for item in fields if item.name != field.name]
                        fields.append(field)
                        seen.add(field.name)
                index.models[name] = SchemaContract(
                    name,
                    "object",
                    tuple(fields),
                    "application/json",
                    confidence_score=96,
                    evidence=_evidence(parsed, node, "pydantic-model"),
                )
                progress = True

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        index = self._index(project)
        bases = self._bases(index)
        contracts: list[RouteContract] = []
        for route in index.routes:
            router = index.routers.get(route.router)
            if router is None:
                continue
            full_path = _join(bases.get(route.router, ""), router.prefix, route.path)
            grouped: dict[str, list[FieldContract]] = {}
            request_schemas: list[SchemaContract] = []
            for argument, default in self._arguments(route.function):
                if argument.arg in {"request", "response", "db", "session", "self"}:
                    continue
                location = _parameter_location(argument.arg, full_path, argument.annotation, default, index.models)
                if location == "depends":
                    continue
                annotation = annotation_name(argument.annotation)
                core, _extras = unwrap_annotated(argument.annotation)
                model_name = annotation_name(core).split("[")[-1].rstrip("]").split(".")[-1]
                if location == "request-body" and model_name in index.models:
                    request_schemas.append(index.models[model_name])
                    continue
                grouped.setdefault(location, []).append(
                    _field_from_nodes(
                        route.parsed,
                        argument.arg,
                        argument.annotation,
                        default,
                        enums=index.enums,
                        models=index.models,
                    )
                )
            for name, fields in grouped.items():
                content = "application/json" if name == "request-body" else "application/x-www-form-urlencoded" if name == "form-data" else ""
                request_schemas.append(
                    SchemaContract(name, "object", tuple(fields), content, confidence_score=92, evidence=_evidence(route.parsed, route.function, "route-parameters"))
                )
            responses = self._responses(route, index)
            authentication = (self._authentication(route),)
            contracts.append(
                RouteContract(
                    route.method,
                    full_path,
                    "FastAPI",
                    route.function.name,
                    ast.get_docstring(route.function) or "",
                    tuple(request_schemas),
                    responses,
                    authentication,
                    confidence_score=97,
                    evidence=_evidence(route.parsed, route.decorator, "fastapi-route"),
                )
            )
        return contracts

    def _responses(self, route: _Route, index: _Index) -> dict[str, SchemaContract]:
        status_node = keyword(route.decorator, "status_code")
        status = static_value(status_node)
        status_key = str(status if status is not None else (201 if route.method == "POST" else 200))
        model_node = keyword(route.decorator, "response_model")
        name = annotation_name(model_node) if model_node is not None else ""
        simple = name.split(".")[-1]
        if simple in index.models:
            schema = index.models[simple]
            return {status_key: SchemaContract(schema.name, schema.schema_type, schema.fields, "application/json", False, schema.confidence_score, schema.evidence)}
        return {}

    def _authentication(self, route: _Route) -> AuthFlowContract:
        names = {dotted_name(node) for node in ast.walk(route.function) if isinstance(node, (ast.Call, ast.Attribute, ast.Name))}
        lowered = " ".join(names).lower()
        modes: list[AuthenticationMode] = []
        if any(signal in lowered for signal in ("oauth2", "oauth2passwordbearer", "securityscopes", "security(")):
            modes.append(AuthenticationMode.OAUTH2)
        if any(signal in lowered for signal in ("bearer", "get_current_user", "current_user", "httpbearer")):
            modes.append(AuthenticationMode.BEARER)
        if "api_key" in lowered or "apikey" in lowered or "api_key_header" in lowered:
            modes.append(AuthenticationMode.API_KEY)
        if "session" in lowered:
            modes.append(AuthenticationMode.SESSION)
        if "csrf" in lowered:
            modes.append(AuthenticationMode.DYNAMIC_CSRF)
        modes = list(dict.fromkeys(modes))
        return AuthFlowContract("fastapi-source-auth", tuple(modes) or (AuthenticationMode.PUBLIC,), bool(modes), confidence_score=85 if modes else 65, evidence=_evidence(route.parsed, route.function, "authentication"))

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

    @staticmethod
    def _arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.AST | None]]:
        args = [*function.args.posonlyargs, *function.args.args]
        defaults: list[ast.AST | None] = [None] * (len(args) - len(function.args.defaults)) + list(function.args.defaults)
        return list(zip(args, defaults))

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        return list(self._index(project).models.values())

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return [constraint for schema in self.extract_schemas(project) for field in schema.fields for constraint in field.constraints]

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [flow for route in self.discover_routes(project) for flow in route.authentication]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        return []
