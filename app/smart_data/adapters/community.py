"""Text-only Express, NestJS, Django, Spring, Laravel, and ASP.NET adapters.

Uploaded source is never executed. Nested Express `use()` prefixes and Nest
`@Controller` paths are composed from static strings only.
"""

from __future__ import annotations

import re
from collections import defaultdict

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.source_text import SourceText, iter_source_text, join_path
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
    r"""Route::prefix\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
ASPNET_ROUTE_RE = re.compile(
    r"""\[Route\(\s*"([^"]+)"\s*\)\]""",
    re.IGNORECASE,
)
ASPNET_METHOD_RE = re.compile(
    r"""\[Http(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]*)"\s*\)\]""",
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
        semantic = SemanticType.FOREIGN_KEY if name.lower().endswith("id") else SemanticType.UNKNOWN
        fields.append(FieldContract(name, semantic, "string", True, confidence_score=70))
    if not fields:
        return ()
    return (SchemaContract("parameters", "object", tuple(fields), confidence_score=70),)


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
        return []

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
    suffixes = JS_SUFFIXES
    detect_needles = ("express()", "from 'express'", 'from "express"', "require('express')", 'require("express")')

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            mapping = _express_prefixes(item.text)
            for match in EXPRESS_ROUTE_RE.finditer(item.text):
                variable, method, path = match.groups()
                prefixes = _resolve_express(variable, mapping)
                schemas = _param_schemas(path)
                for prefix in prefixes:
                    full = join_path(prefix, path)
                    routes.append(
                        RouteContract(
                            method.upper(),
                            full,
                            "Express.js",
                            "",
                            "",
                            schemas,
                            authentication=_auth("express-source-auth", (AuthenticationMode.UNKNOWN,), False, item.relative_path),
                            confidence_score=88,
                            evidence=_evidence(item.relative_path, "express-route"),
                        )
                    )
        return routes


class NestJSAdapter(_TextAdapter):
    name = "nestjs"
    suffixes = JS_SUFFIXES
    detect_needles = ("@nestjs/common", "@Controller", "NestFactory")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            controller = NEST_CONTROLLER_RE.search(item.text)
            prefix = ""
            if controller:
                prefix = controller.group(1) or controller.group(2) or ""
            guarded = bool(re.search(r"@UseGuards\(|AuthGuard|JwtAuthGuard", item.text))
            modes = (AuthenticationMode.BEARER,) if guarded else (AuthenticationMode.UNKNOWN,)
            for match in NEST_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(prefix, path or "")
                schemas = _param_schemas(full)
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "NestJS",
                        "",
                        "",
                        schemas,
                        authentication=_auth("nestjs-guard-auth", modes, guarded, item.relative_path),
                        confidence_score=87,
                        evidence=_evidence(item.relative_path, "nestjs-route"),
                    )
                )
        return routes


class DjangoAdapter(_TextAdapter):
    name = "django"
    suffixes = PY_SUFFIXES
    detect_needles = ("django.urls", "urlpatterns", "from django")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        include_prefixes: list[str] = []
        files = self._files(project)
        for item in files:
            for match in re.finditer(
                r"""(?:path|re_path)\(\s*['"]([^'"]+)['"]\s*,\s*include\(""",
                item.text,
            ):
                include_prefixes.append(match.group(1))
        for item in files:
            if "urlpatterns" not in item.text:
                continue
            has_include = "include(" in item.text
            prefixes = [""] if has_include else (include_prefixes or [""])
            for match in DJANGO_PATH_RE.finditer(item.text):
                path = match.group(1)
                if "include(" in item.text[match.end():match.end() + 80]:
                    continue
                for prefix in prefixes:
                    full = join_path(prefix, path)
                    routes.append(
                        RouteContract(
                            "GET",
                            full,
                            "Django",
                            "",
                            "HTTP method requires view analysis",
                            _param_schemas(full),
                            authentication=_auth("django-source-auth", (AuthenticationMode.UNKNOWN,), False, item.relative_path),
                            confidence_score=70,
                            evidence=_evidence(item.relative_path, "django-path"),
                            warnings=("HTTP method requires view analysis",),
                        )
                    )
        return routes


class SpringAdapter(_TextAdapter):
    name = "spring"
    suffixes = JAVA_SUFFIXES
    detect_needles = ("org.springframework.web.bind.annotation", "@RestController", "@RequestMapping")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            class_prefix = ""
            mapped = SPRING_CLASS_MAP_RE.search(item.text)
            if mapped:
                class_prefix = mapped.group(1)
            secured = "@PreAuthorize" in item.text or "Authenticated" in item.text
            modes = (AuthenticationMode.BEARER,) if secured else (AuthenticationMode.UNKNOWN,)
            for match in SPRING_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(class_prefix, path or "")
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "Spring",
                        "",
                        "",
                        _param_schemas(full),
                        authentication=_auth("spring-source-auth", modes, secured, item.relative_path),
                        confidence_score=86,
                        evidence=_evidence(item.relative_path, "spring-route"),
                    )
                )
        return routes


class LaravelAdapter(_TextAdapter):
    name = "laravel"
    suffixes = PHP_SUFFIXES
    detect_needles = ("Illuminate\\Support\\Facades\\Route", "Route::get", "Route::prefix")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            prefixes = [match.group(1) for match in LARAVEL_PREFIX_RE.finditer(item.text)] or [""]
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
                            _param_schemas(full),
                            authentication=_auth("laravel-source-auth", (AuthenticationMode.UNKNOWN,), False, item.relative_path),
                            confidence_score=84,
                            evidence=_evidence(item.relative_path, "laravel-route"),
                        )
                    )
        return routes


class AspNetAdapter(_TextAdapter):
    name = "aspnet"
    suffixes = CS_SUFFIXES
    detect_needles = ("Microsoft.AspNetCore.Mvc", "[ApiController]", "[HttpGet")

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for item in self._files(project):
            class_route = ""
            mapped = ASPNET_ROUTE_RE.search(item.text)
            if mapped:
                class_route = mapped.group(1).replace("[controller]", "").replace("[action]", "")
            for match in ASPNET_METHOD_RE.finditer(item.text):
                method, path = match.groups()
                full = join_path(class_route, path or "")
                routes.append(
                    RouteContract(
                        method.upper(),
                        full,
                        "ASP.NET",
                        "",
                        "",
                        _param_schemas(full),
                        authentication=_auth("aspnet-source-auth", (AuthenticationMode.UNKNOWN,), False, item.relative_path),
                        confidence_score=84,
                        evidence=_evidence(item.relative_path, "aspnet-route"),
                    )
                )
        return routes
