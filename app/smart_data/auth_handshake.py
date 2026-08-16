"""Build token-handshake requests without executing HTTP.

Cookie sessions stay blocked. OAuth2 is client-credentials only against a
public HTTPS token URL. JSON login extracts an access token from the body.
"""

from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.parse import urlencode


def handshake_request(auth_type: str, auth: Mapping[str, Any]) -> dict[str, Any] | None:
    auth_type = str(auth_type or "").strip().lower()
    if auth_type == "oauth2":
        token_url = str(auth.get("token_url") or "").strip()
        client_id = str(auth.get("client_id") or "").strip()
        client_secret = str(auth.get("client_secret") or "").strip()
        if not token_url or not client_id or not client_secret:
            raise ValueError("OAuth2 requires token URL, client id, and client secret.")
        scope = str(auth.get("scope") or "").strip()
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            payload["scope"] = scope
        return {
            "url": token_url,
            "method": "POST",
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": urlencode(payload).encode("utf-8"),
            "extract": "access_token",
            "secret_inputs": [client_secret],
        }
    if auth_type == "login_json":
        login_url = str(auth.get("login_url") or "").strip()
        username = str(auth.get("username") or "").strip()
        password = str(auth.get("password") or "").strip()
        if not login_url or not username or not password:
            raise ValueError("JSON login requires login URL, username, and password.")
        return {
            "url": login_url,
            "method": "POST",
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            "body": json.dumps({"username": username, "password": password}).encode("utf-8"),
            "extract": "access_token",
            "secret_inputs": [password],
        }
    return None


def extract_csrf_header(body: str) -> tuple[str, str] | None:
    """Optional CSRF header from JSON. Never copies Cookie/Set-Cookie."""
    try:
        payload = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("csrf_token", "csrfToken", "xsrf_token", "xsrfToken"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return ("X-CSRF-Token", value.strip())
    return None


def extract_access_token(body: str, extract_key: str = "access_token") -> str:
    lowered = body.lower()
    if "mfa" in lowered and "required" in lowered:
        raise ValueError("MFA was required; automated login stopped. Store a vault bearer token instead.")
    try:
        payload = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Handshake response was not JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Handshake response was not a JSON object.")
    token = payload.get(extract_key) or payload.get("token") or payload.get("accessToken")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("Handshake did not return an access token.")
    return token.strip()
