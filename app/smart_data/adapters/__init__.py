"""Framework adapter interface and registry."""

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.defaults import default_registry
from app.smart_data.adapters.fastapi import FastAPIAdapter
from app.smart_data.adapters.flask import FlaskAdapter
from app.smart_data.adapters.openapi import OpenAPIAdapter
from app.smart_data.adapters.postman import PostmanAdapter
from app.smart_data.adapters.registry import AdapterRegistry

__all__ = [
    "AdapterRegistry",
    "FrameworkAdapter",
    "FastAPIAdapter",
    "FlaskAdapter",
    "OpenAPIAdapter",
    "PostmanAdapter",
    "default_registry",
]
