"""AST-only Flask/Blueprint adapter."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.fastapi import _join, _relative_module
from app.smart_data.adapters.python_source import ParsedPython, call_string, dotted_name, iter_python, keyword, source_excerpt, static_value
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


HTTP_DECORATORS = {"get", "post", "put", "patch", "delete"}


def _evidence(parsed: ParsedPython, node: ast.AST, kind: str) -> tuple[SourceEvidence, ...]:
    return (
        SourceEvidence(
            parsed.relative_path,
            getattr(node, "lineno", None),
            getattr(node, "col_offset", None),
            kind,
            source_excerpt(parsed, node),
            94,
        ),
    )


def _marshmallow_fields(parsed: ParsedPython, node: ast.ClassDef) -> list[FieldContract]:
    fields: list[FieldContract] = []
    for child in node.body:
        if not isinstance(child, ast.Assign):
            continue
        if not child.targets or not isinstance(child.targets[0], ast.Name):
            continue
        if not isinstance(child.value, ast.Call):
            continue
        ctor = dotted_name(child.value.func)
        if "fields." not in ctor and not ctor.split(".")[-1][0].isupper():
            continue
        name = child.targets[0].id
        required = static_value(keyword(child.value, "required")) is True
        type_hint = ctor.split(".")[-1]
        min_length = max_length = None
        for arg in child.value.args:
            pass
        for item in child.value.keywords:
            if item.arg == "validate" and isinstance(item.value, ast.Call):
                min_length = static_value(keyword(item.value, "min"))
                max_length = static_value(keyword(item.value, "max"))
        fields.append(
            field_contract(
                name,
                type_hint=type_hint,
                validators=[ctor],
                required=bool(required),
                min_length=min_length if isinstance(min_length, int) else None,
                max_length=max_length if isinstance(max_length, int) else None,
                evidence=_evidence(parsed, child, "marshmallow-field"),
                source_file=parsed.relative_path,
                source_line=getattr(child, "lineno", None),
                confidence_score=90,
            )
        )
    return fields


def _semantic_field(name: str, parsed: ParsedPython, node: ast.AST, required: bool, type_hint: str = "string") -> FieldContract:
    ev = _evidence(parsed, node, "flask-request-field")
    return field_contract(
        name,
        type_hint=type_hint,
        required=required,
        evidence=ev,
        source_file=parsed.relative_path,
        source_line=getattr(node, "lineno", None),
        confidence_score=82,
    )


@dataclass(slots=True)
class _Container:
    parsed: ParsedPython
    variable: str
    prefix: str
    root: bool


@dataclass(slots=True)
class _Route:
    parsed: ParsedPython
    container: tuple[str, str]
    function: ast.FunctionDef | ast.AsyncFunctionDef
    decorator: ast.Call
    method: str
    path: str


@dataclass(slots=True)
class _Index:
    containers: dict[tuple[str, str], _Container] = field(default_factory=dict)
    imports: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    edges: list[tuple[tuple[str, str], tuple[str, str], str]] = field(default_factory=list)
    routes: list[_Route] = field(default_factory=list)
    marshmallow: dict[str, SchemaContract] = field(default_factory=dict)


class FlaskAdapter(FrameworkAdapter):
    name = "flask"
    adapter_version = "2"

    def _index(self, project: ProjectRef) -> _Index:
        index = _Index()
        parsed_files = list(iter_python(project))
        for parsed in parsed_files:
            for node in parsed.tree.body:
                if isinstance(node, ast.ImportFrom):
                    target = _relative_module(parsed.module, node.module, node.level)
                    for alias in node.names:
                        index.imports[(parsed.module, alias.asname or alias.name)] = (target, alias.name)
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                    constructor = dotted_name(node.value.func).split(".")[-1]
                    if constructor not in {"Flask", "Blueprint"}:
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    prefix = call_string(node.value, keyword_name="url_prefix")
                    for target in targets:
                        if isinstance(target, ast.Name):
                            index.containers[(parsed.module, target.id)] = _Container(parsed, target.id, prefix, constructor == "Flask")
                if isinstance(node, ast.ClassDef) and any("Schema" in dotted_name(base) for base in node.bases):
                    fields = _marshmallow_fields(parsed, node)
                    if fields:
                        index.marshmallow[node.name] = SchemaContract(
                            node.name,
                            "object",
                            tuple(fields),
                            "application/json",
                            confidence_score=90,
                            evidence=_evidence(parsed, node, "marshmallow-schema"),
                        )
        for parsed in parsed_files:
            for node in ast.walk(parsed.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register_blueprint" and isinstance(node.func.value, ast.Name) and node.args:
                    child_expr = node.args[0]
                    if isinstance(child_expr, ast.Name):
                        child = index.imports.get((parsed.module, child_expr.id), (parsed.module, child_expr.id))
                        index.edges.append(((parsed.module, node.func.value.id), child, call_string(node, keyword_name="url_prefix")))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute) or not isinstance(decorator.func.value, ast.Name):
                            continue
                        name = decorator.func.attr.lower()
                        if name == "route":
                            methods = static_value(keyword(decorator, "methods"))
                            route_methods = [str(item).upper() for item in methods] if isinstance(methods, (list, tuple)) else ["GET"]
                        elif name in HTTP_DECORATORS:
                            route_methods = [name.upper()]
                        else:
                            continue
                        for method in route_methods:
                            index.routes.append(_Route(parsed, (parsed.module, decorator.func.value.id), node, decorator, method, call_string(decorator)))
        return index

    @staticmethod
    def _bases(index: _Index) -> dict[tuple[str, str], str]:
        bases = {key: "" for key, value in index.containers.items() if value.root}
        changed = True
        while changed:
            changed = False
            for parent, child, edge_prefix in index.edges:
                if parent not in bases or child not in index.containers:
                    continue
                candidate = _join(bases[parent], index.containers[parent].prefix, edge_prefix)
                if child not in bases or len(candidate) < len(bases[child]):
                    bases[child] = candidate
                    changed = True
        return bases

    def detect(self, project: ProjectRef) -> DetectionResult:
        index = self._index(project)
        containers = list(index.containers.values())
        if not containers:
            return DetectionResult(self.name, False, 0)
        evidence = tuple(SourceEvidence(item.parsed.relative_path, evidence_type="flask-constructor", confidence_score=97) for item in containers[:10])
        return DetectionResult(self.name, True, 97, evidence=evidence)

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        index = self._index(project)
        bases = self._bases(index)
        contracts: list[RouteContract] = []
        for route in index.routes:
            container = index.containers.get(route.container)
            if container is None:
                continue
            fields = self._request_fields(route)
            schemas: list[SchemaContract] = []
            if fields:
                schemas.append(
                    SchemaContract(
                        "request-fields",
                        "object",
                        tuple(fields),
                        self._content_type(route),
                        confidence_score=82,
                        evidence=_evidence(route.parsed, route.function, "flask-request-fields"),
                    )
                )
            for schema in index.marshmallow.values():
                if schema.name.lower().replace("schema", "") in route.function.name.lower() or any(
                    field.name in {item.name for item in fields} for field in schema.fields
                ):
                    schemas.append(schema)
            contracts.append(
                RouteContract(
                    route.method,
                    _join(bases.get(route.container, ""), container.prefix, route.path),
                    "Flask",
                    route.function.name,
                    ast.get_docstring(route.function) or "",
                    tuple(schemas),
                    authentication=(self._authentication(route),),
                    confidence_score=95,
                    evidence=_evidence(route.parsed, route.decorator, "flask-route"),
                )
            )
        return contracts

    def _request_fields(self, route: _Route) -> list[FieldContract]:
        fields: dict[str, FieldContract] = {}
        json_aliases = set()
        for node in ast.walk(route.function):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and "get_json" in dotted_name(node.value.func):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        json_aliases.add(target.id)
            if isinstance(node, ast.Subscript):
                access = dotted_name(node.value)
                if any(signal in access for signal in ("request.json", "request.args", "request.form", "request.headers", *json_aliases)):
                    name = static_value(node.slice)
                    if isinstance(name, str) and name not in fields:
                        fields[name] = _semantic_field(name, route.parsed, node, True)
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            access = dotted_name(node.func.value)
            if node.func.attr not in {"get", "pop"} or not any(
                signal in access for signal in ("request.form", "request.args", "request.values", "request.files", "request.headers", "request.json", "payload", "data", *json_aliases)
            ):
                continue
            name = call_string(node)
            if not name or name in fields:
                continue
            required = len(node.args) < 2 and keyword(node, "default") is None
            fields[name] = _semantic_field(name, route.parsed, node, required)
        return list(fields.values())

    @staticmethod
    def _content_type(route: _Route) -> str:
        names = " ".join(dotted_name(node) for node in ast.walk(route.function) if isinstance(node, (ast.Call, ast.Attribute)))
        if "request.form" in names:
            return "application/x-www-form-urlencoded"
        if "request.files" in names:
            return "multipart/form-data"
        if "request.get_json" in names or "request.json" in names:
            return "application/json"
        return ""

    def _authentication(self, route: _Route) -> AuthFlowContract:
        decorators = {dotted_name(item.func if isinstance(item, ast.Call) else item).lower() for item in route.function.decorator_list}
        names = {dotted_name(node).lower() for node in ast.walk(route.function) if isinstance(node, (ast.Call, ast.Attribute, ast.Name))}
        combined = " ".join(decorators | names)
        modes: list[AuthenticationMode] = []
        if any(signal in combined for signal in ("login_required", "current_user", "session")):
            modes.append(AuthenticationMode.SESSION)
        if "jwt" in combined or "bearer" in combined:
            modes.append(AuthenticationMode.BEARER)
        if "api_key" in combined or "apikey" in combined:
            modes.append(AuthenticationMode.API_KEY)
        if "csrf" in combined:
            modes.append(AuthenticationMode.DYNAMIC_CSRF)
        modes = list(dict.fromkeys(modes))
        return AuthFlowContract("flask-source-auth", tuple(modes) or (AuthenticationMode.PUBLIC,), bool(modes), confidence_score=84 if modes else 65, evidence=_evidence(route.parsed, route.function, "authentication"))

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        index = self._index(project)
        return list(index.marshmallow.values()) + [
            schema for route in self.discover_routes(project) for schema in route.request_schemas
        ]

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return [
            constraint
            for schema in self.extract_schemas(project)
            for field in schema.fields
            for constraint in field.constraints
        ]

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [flow for route in self.discover_routes(project) for flow in route.authentication]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        return []
