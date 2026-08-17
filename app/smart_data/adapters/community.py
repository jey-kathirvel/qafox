"""Text-only Express, NestJS, Django, Spring, Laravel, and ASP.NET adapters.

Uploaded source is never executed. Nested Express `use()` prefixes and Nest
`@Controller` paths are composed from static strings only.
"""

from __future__ import annotations

import re
from collections import defaultdict

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.semantics import field_contract
from app.smart_data.adapters.source_text import SourceText, iter_source_text, join_path
from app.smart_data.adapters.text_intelligence import (
    aspnet_action_parameters,
    aspnet_auth_modes,
    bean_validation_classes,
    class_validator_fields,
    dataannotation_classes,
    eloquent_relationships,
    express_request_fields,
    js_auth_modes,
    js_validator_fields,
    laravel_auth_modes,
    laravel_resource_routes,
    laravel_validation_fields,
    LARAVEL_RESOURCE_RE,
    mongoose_fields,
    nest_parameter_locations,
    prisma_fields,
    schemas_from_fields,
    sequelize_fields,
    spring_method_parameters,
)
from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    FieldContract,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SemanticType,
    SourceEvidence,
    TestDataSource,
)

JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
PY_SUFFIXES = frozenset({".py"})
JAVA_SUFFIXES = frozenset({".java", ".kt"})
PHP_SUFFIXES = frozenset({".php"})
CS_SUFFIXES = frozenset({".cs"})
HTTP = ("get", "post", "put", "patch", "delete", "head", "options")
USE_RE = re.compile(
    r"""(\w+)\.use\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)""",
    re.IGNORECASE,
)
EXPRESS_ROUTE_RE = re.compile(
    r"""(\w+)\.(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
NEST_CONTROLLER_RE = re.compile(
    r"""@Controller\(\s*(?:['"`]([^'"`]*)['"`]|{\s*path\s*:\s*['"`]([^'"`]+)['"`])""",
    re.IGNORECASE,
)
NEST_METHOD_RE = re.compile(
    r"""@(Get|Post|Put|Patch|Delete|Head|Options)\(\s*['"`]?([^'"`)]*)['"`]?\s*\)""",
    re.IGNORECASE,
)
DJANGO_PATH_RE = re.compile(
    r"""\b(?:path|re_path)\(\s*['"]([^'"]+)['"]""",
)
SPRING_CLASS_MAP_RE = re.compile(
    r"""@RequestMapping\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
SPRING_METHOD_RE = re.compile(
    r"""@(Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?['"]([^'"]*)['"]""",
    re.IGNORECASE,
)
LARAVEL_ROUTE_RE = re.compile(
    r"""Route::(get|post|put|patch|delete|head|options)\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
LARAVEL_PREFIX_RE = re.compile(
    r"""(?:Route::prefix|->prefix)\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
ASPNET_ROUTE_RE = re.compile(
    r"""\[Route\(\s*"([^"]+)"\s*\)\]""",
    re.IGNORECASE,
)
ASPNET_METHOD_RE = re.compile(
    r"""\[Http(Get|Post|Put|Patch|Delete|Head|Options)(?:\(\s*"([^"]*)"\s*\))?\]""",
    re.IGNORECASE,
)


def _evidence(relative: str, kind: str) -> tuple[SourceEvidence, ...]:
    return (SourceEvidence(relative, evidence_type=kind, confidence_score=88),)


def _auth(name: str, modes: tuple[AuthenticationMode, ...], required: bool, relative: str) -> tuple[AuthFlowContract, ...]:
    return (
        AuthFlowContract(name, modes or (AuthenticationMode.PUBLIC,), required, confidence_score=80, evidence=_evidence(relative, "authentication")),
    )


def _param_schemas(path: str) -> tuple[SchemaContract, ...]:
    names = re.findall(r":([A-Za-z_][\w]*)|\{([A-Za-z_][\w]*)\}|<[^:>]*:([^>]+)>", path)
    fields = []
    seen = set()
    for colon, brace, angle in names:
        name = colon or brace or angle
        if not name or name in seen:
            continue
        seen.add(name)
        semantic = "id" if name.lower().endswith("id") else ""
        fields.append(
            field_contract(name, required=True, validators=[semantic], confidence_score=70)
        )
    if not fields:
        return ()
    return (SchemaContract("parameters", "object", tuple(fields), confidence_score=70),)


def _django_serializer_fields(parsed) -> list[FieldContract]:
    import ast
    from app.smart_data.adapters.python_source import dotted_name, keyword, static_value

    fields: list[FieldContract] = []
    for node in parsed.tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = " ".join(dotted_name(base) for base in node.bases)
        if "Serializer" not in bases:
            continue
        for child in node.body:
            if isinstance(child, ast.Assign) and child.targets and isinstance(child.targets[0], ast.Name) and isinstance(child.value, ast.Call):
                ctor = dotted_name(child.value.func)
                if "Field" not in ctor:
                    continue
                max_length = static_value(keyword(child.value, "max_length"))
                min_length = static_value(keyword(child.value, "min_length"))
                fields.append(
                    field_contract(
                        child.targets[0].id,
                        type_hint=ctor.split(".")[-1],
                        validators=[ctor],
                        required=static_value(keyword(child.value, "required")) is not False,
                        max_length=max_length if isinstance(max_length, int) else None,
                        min_length=min_length if isinstance(min_length, int) else None,
                        source_file=parsed.relative_path,
                        source_line=getattr(child, "lineno", None),
                        confidence_score=92,
                    )
                )
            if isinstance(child, ast.ClassDef) and child.name == "Meta":
                for meta in child.body:
                    if isinstance(meta, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "fields" for t in meta.targets):
                        names = static_value(meta.value)
                        if isinstance(names, (list, tuple)):
                            for item in names:
                                if isinstance(item, str) and item != "__all__":
                                    fields.append(field_contract(item, validators=["Meta.fields"], source_file=parsed.relative_path))
    return fields


def _django_model_fields(parsed) -> list[FieldContract]:
    import ast
    from app.smart_data.adapters.python_source import dotted_name, keyword, static_value

    fields: list[FieldContract] = []
    for node in parsed.tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = " ".join(dotted_name(base) for base in node.bases)
        if "models.Model" not in bases and not bases.endswith("Model"):
            continue
        if "Serializer" in bases:
            continue
        for child in node.body:
            if not isinstance(child, ast.Assign) or not child.targets:
                continue
            if not isinstance(child.targets[0], ast.Name) or not isinstance(child.value, ast.Call):
                continue
            ctor = dotted_name(child.value.func)
            if "models." not in ctor and not ctor.endswith("Field"):
                continue
            name = child.targets[0].id
            rel = ctor.split(".")[-1] in {"ForeignKey", "OneToOneField", "ManyToManyField"}
            max_length = static_value(keyword(child.value, "max_length"))
            fields.append(
                field_contract(
                    f"{name}_id" if rel and not name.endswith("_id") else name,
                    type_hint=ctor.split(".")[-1],
                    validators=[ctor],
                    max_length=max_length if isinstance(max_length, int) else None,
                    source_file=parsed.relative_path,
                    source_line=getattr(child, "lineno", None),
                    confidence_score=88,
                )
            )
    return fields


class _TextAdapter(FrameworkAdapter):
    suffixes: frozenset[str] = frozenset()
    detect_needles: tuple[str, ...] = ()

    def _files(self, project: ProjectRef):
        return list(iter_source_text(project, self.suffixes))

    def detect(self, project: ProjectRef) -> DetectionResult:
        for item in self._files(project):
            lowered = item.text.lower()
            if any(needle.lower() in lowered for needle in self.detect_needles):
                return DetectionResult(self.name, True, 90, evidence=_evidence(item.relative_path, "detect"))
        return DetectionResult(self.name, False, 0)

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        return [schema for route in self.discover_routes(project) for schema in route.request_schemas]

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


def _express_prefixes(text: str) -> dict[str, list[tuple[str, str]]]:
    mapping: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for match in USE_RE.finditer(text):
        parent, prefix, child = match.groups()
        mapping[child].append((parent, prefix))
    return mapping


def _resolve_express(variable: str, mapping: dict[str, list[tuple[str, str]]], seen: frozenset[str] | None = None) -> list[str]:
    seen = seen or frozenset()
    if variable in seen:
        return [""]
    parents = mapping.get(variable)
    if not parents:
        return [""]
    resolved: list[str] = []
    for parent, prefix in parents:
        for base in _resolve_express(parent, mapping, seen | {variable}):
            resolved.append(join_path(base, prefix))
    return resolved or [""]


class ExpressAdapter(_TextAdapter):
    name = "express"
    adapter_version = "2"
    suffixes = JS_SUFFIXES
    detect_needles = ("express()", "from 'express'", 'from "express"', "require('express')", 'require("express")')

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            mapping = _express_prefixes(item.text)
            file_validators = js_validator_fields(item.text, item.relative_path)
            model_fields = mongoose_fields(item.text, item.relative_path) + prisma_fields(item.text, item.relative_path) + sequelize_fields(item.text, item.relative_path)
            access = express_request_fields(item.text, item.relative_path)
            auth_modes = js_auth_modes(item.text)
            for match in EXPRESS_ROUTE_RE.finditer(item.text):
                variable, method, path = match.groups()
                prefixes = _resolve_express(variable, mapping)
                schemas = list(_param_schemas(path))
                schemas.extend(schemas_from_fields(access))
                if file_validators and method.upper() in {"POST", "PUT", "PATCH"}:
                    schemas.append(SchemaContract("request-body", "object", tuple(file_validators), "application/json", confidence_score=90, evidence=_evidence(item.relative_path, "js-validator")))
                if model_fields:
                    schemas.append(SchemaContract("model-relationships", "object", tuple(model_fields), confidence_score=80, evidence=_evidence(item.relative_path, "orm-model")))
                required = bool(auth_modes)
                for prefix in prefixes:
                    full = join_path(prefix, path)
                    routes.append(
                        RouteContract(
                            method.upper(),
                            full,
                            "Express.js",
                            "",
                            "",
                            tuple(schemas),
                            authentication=_auth("express-source-auth", auth_modes or (AuthenticationMode.UNKNOWN,), required, item.relative_path),
                            confidence_score=88,
                            evidence=_evidence(item.relative_path, "express-route"),
                        )
                    )
        return routes


class NestJSAdapter(_TextAdapter):
    name = "nestjs"
    adapter_version = "2"
    suffixes = JS_SUFFIXES
    detect_needles = ("@nestjs/common", "@Controller", "NestFactory")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        dto_map: dict[str, list[FieldContract]] = {}
        for item in self._files(project):
            dto_map.update(class_validator_fields(item.text, item.relative_path))
        for item in self._files(project):
            controller = NEST_CONTROLLER_RE.search(item.text)
            prefix = ""
            if controller:
                prefix = controller.group(1) or controller.group(2) or ""
            guarded = bool(re.search(r"@UseGuards\(|AuthGuard|JwtAuthGuard", item.text))
            modes = (AuthenticationMode.BEARER,) if guarded else js_auth_modes(item.text) or (AuthenticationMode.UNKNOWN,)
            for match in NEST_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(prefix, path or "")
                snippet = item.text[match.start() : match.start() + 500]
                grouped: dict[str, list[FieldContract]] = {}
                for kind, name in nest_parameter_locations(snippet):
                    bag = {
                        "param": "path-parameters",
                        "query": "query-parameters",
                        "headers": "header-parameters",
                        "header": "header-parameters",
                        "body": "request-body",
                    }.get(kind, "query-parameters")
                    if kind == "body":
                        for dto_name, fields in dto_map.items():
                            if dto_name in snippet:
                                grouped.setdefault("request-body", []).extend(fields)
                    elif name:
                        grouped.setdefault(bag, []).append(
                            field_contract(name, required=kind == "param", source_file=item.relative_path)
                        )
                schemas = list(_param_schemas(full)) + list(schemas_from_fields(grouped, {"request-body": "application/json"}))
                if method.upper() in {"POST", "PUT", "PATCH"} and "request-body" not in grouped and dto_map:
                    first = next(iter(dto_map.values()))
                    schemas.append(SchemaContract("request-body", "object", tuple(first), "application/json", confidence_score=88, evidence=_evidence(item.relative_path, "nestjs-dto")))
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "NestJS",
                        "",
                        "",
                        tuple(schemas),
                        authentication=_auth("nestjs-guard-auth", modes, guarded, item.relative_path),
                        confidence_score=87,
                        evidence=_evidence(item.relative_path, "nestjs-route"),
                    )
                )
        return routes


class DjangoAdapter(_TextAdapter):
    name = "django"
    adapter_version = "2"
    suffixes = PY_SUFFIXES
    detect_needles = ("django.urls", "urlpatterns", "from django")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        from app.smart_data.adapters.python_source import iter_python

        routes: list[RouteContract] = []
        include_prefixes: list[str] = []
        files = self._files(project)
        for item in files:
            for match in re.finditer(
                r"""(?:path|re_path)\(\s*['"]([^'"]+)['"]\s*,\s*include\(""",
                item.text,
            ):
                include_prefixes.append(match.group(1))
        serializer_fields: list[FieldContract] = []
        model_fields: list[FieldContract] = []
        auth_modes: tuple[AuthenticationMode, ...] = (AuthenticationMode.UNKNOWN,)
        required_auth = False
        view_methods: dict[str, list[str]] = {}
        for parsed in iter_python(project):
            serializer_fields.extend(_django_serializer_fields(parsed))
            model_fields.extend(_django_model_fields(parsed))
            blob = parsed.text.lower()
            if "isauthenticated" in blob or "tokenauthentication" in blob:
                auth_modes = (AuthenticationMode.BEARER,)
                required_auth = True
            if "sessionauthentication" in blob:
                auth_modes = tuple(dict.fromkeys([*auth_modes, AuthenticationMode.SESSION]))
                required_auth = True
            if "allowany" in blob:
                auth_modes = (AuthenticationMode.PUBLIC,)
                required_auth = False
            for match in re.finditer(r"def\s+(get|post|put|patch|delete|list|create|retrieve|update|partial_update|destroy)\s*\(", parsed.text):
                view_methods.setdefault(parsed.relative_path, []).append(
                    {
                        "list": "GET",
                        "retrieve": "GET",
                        "create": "POST",
                        "update": "PUT",
                        "partial_update": "PATCH",
                        "destroy": "DELETE",
                    }.get(match.group(1), match.group(1).upper())
                )
        extra_schema = []
        if serializer_fields:
            extra_schema.append(SchemaContract("serializer", "object", tuple(serializer_fields), "application/json", confidence_score=90, evidence=_evidence("serializers.py", "drf-serializer")))
        if model_fields:
            extra_schema.append(SchemaContract("model", "object", tuple(model_fields), confidence_score=86, evidence=_evidence("models.py", "django-model")))
        for item in files:
            if "urlpatterns" not in item.text:
                continue
            has_include = "include(" in item.text
            prefixes = [""] if has_include else (include_prefixes or [""])
            for match in DJANGO_PATH_RE.finditer(item.text):
                path = match.group(1)
                if "include(" in item.text[match.end():match.end() + 80]:
                    continue
                methods = ["GET"]
                if any(view_methods.values()):
                    methods = list(dict.fromkeys(m for items in view_methods.values() for m in items)) or ["GET"]
                    if "POST" not in "".join(view_methods) and path.endswith("/"):
                        methods = ["GET"]
                for prefix in prefixes:
                    full = join_path(prefix, path)
                    schemas = list(_param_schemas(full)) + extra_schema
                    methods = ["GET"]
                    combined = "\n".join(entry.text for entry in files)
                    if re.search(r"class\s+\w+\(.*(?:ViewSet|APIView)", combined):
                        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
                    for method in methods:
                        routes.append(
                            RouteContract(
                                method,
                                full,
                                "Django",
                                "",
                                "" if method != "GET" else "HTTP method requires view analysis",
                                tuple(schemas),
                                authentication=_auth("django-source-auth", auth_modes, required_auth, item.relative_path),
                                confidence_score=82 if extra_schema else 70,
                                evidence=_evidence(item.relative_path, "django-path"),
                                warnings=("HTTP method requires view analysis",) if method == "GET" and not extra_schema else (),
                            )
                        )
        return routes


class SpringAdapter(_TextAdapter):
    name = "spring"
    adapter_version = "2"
    suffixes = JAVA_SUFFIXES
    detect_needles = ("org.springframework.web.bind.annotation", "@RestController", "@RequestMapping")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        dto_map: dict[str, list[FieldContract]] = {}
        for item in self._files(project):
            dto_map.update(bean_validation_classes(item.text, item.relative_path))
        for item in self._files(project):
            class_prefix = ""
            mapped = SPRING_CLASS_MAP_RE.search(item.text)
            if mapped:
                class_prefix = mapped.group(1)
            secured = "@PreAuthorize" in item.text or "Authenticated" in item.text or "@Secured" in item.text
            modes = (AuthenticationMode.BEARER,) if secured else (AuthenticationMode.UNKNOWN,)
            params = spring_method_parameters(item.text, item.relative_path)
            for match in SPRING_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(class_prefix, path or "")
                grouped: dict[str, list[FieldContract]] = {}
                for http_method, _handler, kind, field in params:
                    if http_method != method.upper():
                        continue
                    bag = {
                        "PathVariable": "path-parameters",
                        "RequestParam": "query-parameters",
                        "RequestHeader": "header-parameters",
                        "RequestBody": "request-body",
                    }.get(kind, "query-parameters")
                    if kind == "RequestBody":
                        type_name = field.data_type.split("<")[0].split(".")[-1]
                        grouped.setdefault("request-body", []).extend(dto_map.get(type_name, [field]))
                    else:
                        grouped.setdefault(bag, []).append(field)
                schemas = list(_param_schemas(full)) + list(schemas_from_fields(grouped, {"request-body": "application/json"}))
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "Spring",
                        "",
                        "",
                        tuple(schemas),
                        authentication=_auth("spring-source-auth", modes, secured, item.relative_path),
                        confidence_score=86,
                        evidence=_evidence(item.relative_path, "spring-route"),
                    )
                )
        return routes


class LaravelAdapter(_TextAdapter):
    name = "laravel"
    adapter_version = "2"
    suffixes = PHP_SUFFIXES
    detect_needles = ("Illuminate\\Support\\Facades\\Route", "Route::get", "Route::prefix")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            prefixes = [match.group(1) for match in LARAVEL_PREFIX_RE.finditer(item.text)] or [""]
            validation = laravel_validation_fields(item.text, item.relative_path)
            relations = eloquent_relationships(item.text, item.relative_path)
            auth_modes = laravel_auth_modes(item.text)
            extra = []
            if validation:
                extra.append(SchemaContract("request-body", "object", tuple(validation), "application/json", True, 90, _evidence(item.relative_path, "laravel-validation")))
            if relations:
                extra.append(SchemaContract("model-relationships", "object", tuple(relations), confidence_score=80, evidence=_evidence(item.relative_path, "eloquent")))
            for match in LARAVEL_ROUTE_RE.finditer(item.text):
                method, path = match.groups()
                for prefix in prefixes:
                    full = join_path(prefix, path)
                    routes.append(
                        RouteContract(
                            method.upper(),
                            full,
                            "Laravel",
                            "",
                            "",
                            tuple(_param_schemas(full)) + tuple(extra),
                            authentication=_auth("laravel-source-auth", auth_modes or (AuthenticationMode.UNKNOWN,), bool(auth_modes), item.relative_path),
                            confidence_score=84,
                            evidence=_evidence(item.relative_path, "laravel-route"),
                        )
                    )
            for match in LARAVEL_RESOURCE_RE.finditer(item.text):
                kind, name = match.groups()
                for method, path in laravel_resource_routes(name, kind.lower() == "apiresource"):
                    for prefix in prefixes:
                        full = join_path(prefix, path)
                        routes.append(
                            RouteContract(
                                method,
                                full,
                                "Laravel",
                                "",
                                "",
                                tuple(_param_schemas(full)) + tuple(extra),
                                authentication=_auth("laravel-source-auth", auth_modes or (AuthenticationMode.UNKNOWN,), bool(auth_modes), item.relative_path),
                                confidence_score=84,
                                evidence=_evidence(item.relative_path, "laravel-resource"),
                            )
                        )
        return routes


class AspNetAdapter(_TextAdapter):
    name = "aspnet"
    adapter_version = "2"
    suffixes = CS_SUFFIXES
    detect_needles = ("Microsoft.AspNetCore.Mvc", "[ApiController]", "[HttpGet")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        dto_map: dict[str, list[FieldContract]] = {}
        for item in self._files(project):
            dto_map.update(dataannotation_classes(item.text, item.relative_path))
        for item in self._files(project):
            class_route = ""
            mapped = ASPNET_ROUTE_RE.search(item.text)
            if mapped:
                class_route = mapped.group(1).replace("[controller]", "").replace("[action]", "")
            modes, required = aspnet_auth_modes(item.text)
            action_params = aspnet_action_parameters(item.text, item.relative_path)
            for match in ASPNET_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(class_route, path or "")
                grouped: dict[str, list[FieldContract]] = {}
                for kind, field in action_params:
                    bag = {
                        "FromRoute": "path-parameters",
                        "FromQuery": "query-parameters",
                        "FromHeader": "header-parameters",
                        "FromBody": "request-body",
                    }.get(kind, "query-parameters")
                    if kind == "FromBody":
                        type_name = field.data_type.split("<")[0].split(".")[-1]
                        grouped.setdefault("request-body", []).extend(dto_map.get(type_name, [field]))
                    else:
                        grouped.setdefault(bag, []).append(field)
                if method.upper() in {"POST", "PUT", "PATCH"} and "request-body" not in grouped and dto_map:
                    grouped["request-body"] = next(iter(dto_map.values()))
                schemas = list(_param_schemas(full)) + list(schemas_from_fields(grouped, {"request-body": "application/json"}))
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "ASP.NET",
                        "",
                        "",
                        tuple(schemas),
                        authentication=_auth("aspnet-source-auth", modes, required, item.relative_path),
                        confidence_score=84,
                        evidence=_evidence(item.relative_path, "aspnet-route"),
                    )
                )
        return routes
