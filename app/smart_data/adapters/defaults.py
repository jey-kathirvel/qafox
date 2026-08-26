"""Default production adapter set for PATCH-QAFOX-004B1A-7."""

from __future__ import annotations

from app.smart_data.adapters.community import (
    AspNetAdapter,
    DjangoAdapter,
    ExpressAdapter,
    LaravelAdapter,
    NestJSAdapter,
    SpringAdapter,
)
from app.smart_data.adapters.fastapi import FastAPIAdapter
from app.smart_data.adapters.flask import FlaskAdapter
from app.smart_data.adapters.generic import GenericAdapter
from app.smart_data.adapters.openapi import OpenAPIAdapter
from app.smart_data.adapters.postman import PostmanAdapter
from app.smart_data.adapters.registry import AdapterRegistry


def default_registry() -> AdapterRegistry:
    return AdapterRegistry(
        (
            OpenAPIAdapter(),
            PostmanAdapter(),
            FastAPIAdapter(),
            FlaskAdapter(),
            ExpressAdapter(),
            NestJSAdapter(),
            DjangoAdapter(),
            SpringAdapter(),
            LaravelAdapter(),
            AspNetAdapter(),
            GenericAdapter(),
        )
    )
