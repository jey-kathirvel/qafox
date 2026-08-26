"""Explicit adapter capability matrix for Universal API Contract V2.

Capabilities describe what each adapter actually emits today. Unsupported
protocols and unobserved features are omitted on purpose.
"""

from __future__ import annotations

from app.smart_data.uapi import AdapterCapability

C = AdapterCapability

ADAPTER_CAPABILITY_MATRIX: dict[str, frozenset[AdapterCapability]] = {
    "generic": frozenset({C.ROUTES}),
    "openapi": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.RESPONSE_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.DEPENDENCIES,
            C.SECURITY_HINTS,
        }
    ),
    "postman": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.AUTHENTICATION,
            C.FIXTURES,
            C.SECURITY_HINTS,
        }
    ),
    "fastapi": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.RESPONSE_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.DEPENDENCIES,
            C.PREFIX_COMPOSITION,
            C.SECURITY_HINTS,
            C.MODEL_RELATIONSHIPS,
        }
    ),
    "flask": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.PREFIX_COMPOSITION,
            C.SECURITY_HINTS,
        }
    ),
    "express": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.PREFIX_COMPOSITION,
            C.SECURITY_HINTS,
            C.MODEL_RELATIONSHIPS,
        }
    ),
    "nestjs": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.PREFIX_COMPOSITION,
            C.AUTHENTICATION,
            C.SECURITY_HINTS,
        }
    ),
    "django": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.PREFIX_COMPOSITION,
            C.MODEL_RELATIONSHIPS,
            C.SECURITY_HINTS,
        }
    ),
    "spring": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.PREFIX_COMPOSITION,
            C.AUTHENTICATION,
            C.SECURITY_HINTS,
        }
    ),
    "laravel": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.PREFIX_COMPOSITION,
            C.MODEL_RELATIONSHIPS,
            C.SECURITY_HINTS,
        }
    ),
    "aspnet": frozenset(
        {
            C.ROUTES,
            C.REQUEST_SCHEMA,
            C.VALIDATION,
            C.AUTHENTICATION,
            C.PREFIX_COMPOSITION,
            C.SECURITY_HINTS,
        }
    ),
}

REGISTERED_ADAPTERS = (
    "generic",
    "openapi",
    "postman",
    "fastapi",
    "flask",
    "express",
    "nestjs",
    "django",
    "spring",
    "laravel",
    "aspnet",
)


def capabilities_for(adapter_name: str) -> frozenset[AdapterCapability]:
    return ADAPTER_CAPABILITY_MATRIX.get(str(adapter_name).strip().lower(), frozenset())


def capability_matrix() -> dict[str, tuple[str, ...]]:
    return {
        name: tuple(sorted(cap.value for cap in ADAPTER_CAPABILITY_MATRIX[name]))
        for name in REGISTERED_ADAPTERS
    }
