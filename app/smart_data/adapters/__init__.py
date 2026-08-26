"""Framework adapter interface and registry."""

from app.smart_data.adapters.community import (
    AspNetAdapter,
    DjangoAdapter,
    ExpressAdapter,
    LaravelAdapter,
    NestJSAdapter,
    SpringAdapter,
)
from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.defaults import default_registry
from app.smart_data.adapters.fastapi import FastAPIAdapter
from app.smart_data.adapters.flask import FlaskAdapter
from app.smart_data.adapters.generic import GenericAdapter
from app.smart_data.adapters.openapi import OpenAPIAdapter
from app.smart_data.adapters.postman import PostmanAdapter
from app.smart_data.adapters.registry import AdapterRegistry

__all__ = [
    "AdapterRegistry",
    "AspNetAdapter",
    "DjangoAdapter",
    "ExpressAdapter",
    "FrameworkAdapter",
    "FastAPIAdapter",
    "FlaskAdapter",
    "GenericAdapter",
    "LaravelAdapter",
    "NestJSAdapter",
    "OpenAPIAdapter",
    "PostmanAdapter",
    "SpringAdapter",
    "default_registry",
]
