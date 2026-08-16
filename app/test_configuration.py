import ipaddress
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.main import (
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
)

router = APIRouter()

vault = Fernet(
    os.environ["TEST_VAULT_KEY"].encode("ascii")
)

ALLOWED_ENVIRONMENTS = {
    "development",
    "testing",
    "staging",
    "production",
}

ALLOWED_AUTH_TYPES = {
    "none",
    "bearer",
    "api_key",
    "basic",
    "oauth2",
    "login_json",
}

PROHIBITED_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "proxy-authorization",
    "proxy-authenticate",
    "upgrade",
    "cookie",
    "set-cookie",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
}

RESERVED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}


class ConfigurationRejected(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def encrypt_json(value: dict) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return vault.encrypt(raw).decode("ascii")


def decrypt_json(value: str | None) -> dict:
    if not value:
        return {}

    try:
        raw = vault.decrypt(
            value.encode("ascii")
        )
        parsed = json.loads(
            raw.decode("utf-8")
        )

        return parsed if isinstance(parsed, dict) else {}
    except (
        InvalidToken,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return {}


def is_public_ip(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    return bool(
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_reserved
        and not parsed.is_unspecified
    )


def validate_base_url(value: str) -> str:
    value = value.strip()

    if len(value) > 2048:
        raise ConfigurationRejected(
            "Base URL is too long."
        )

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ConfigurationRejected(
            "Enter a valid HTTPS base URL."
        ) from exc

    if parsed.scheme.lower() != "https":
        raise ConfigurationRejected(
            "Only HTTPS base URLs are allowed."
        )

    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ConfigurationRejected(
            "Base URL cannot contain credentials or fragments."
        )

    hostname = parsed.hostname.lower().rstrip(".")

    if (
        hostname in RESERVED_HOSTNAMES
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".localhost")
    ):
        raise ConfigurationRejected(
            "Local and internal hostnames are not allowed."
        )

    try:
        results = socket.getaddrinfo(
            hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ConfigurationRejected(
            "Base URL hostname could not be resolved."
        ) from exc

    addresses = {
        result[4][0]
        for result in results
        if result and result[4]
    }

    if not addresses:
        raise ConfigurationRejected(
            "Base URL did not resolve to an address."
        )

    if any(
        not is_public_ip(address)
        for address in addresses
    ):
        raise ConfigurationRejected(
            "Private, loopback and reserved targets are blocked."
        )

    path = parsed.path.rstrip("/")

    return urlunsplit(
        (
            "https",
            parsed.netloc.lower(),
            path,
            "",
            "",
        )
    )


def parse_custom_headers(raw: str) -> dict:
    raw = raw.strip()

    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationRejected(
            "Custom headers must be a valid JSON object."
        ) from exc

    if not isinstance(parsed, dict):
        raise ConfigurationRejected(
            "Custom headers must be a JSON object."
        )

    if len(parsed) > 30:
        raise ConfigurationRejected(
            "Maximum 30 custom headers are allowed."
        )

    headers = {}

    for name, value in parsed.items():
        name = str(name).strip()
        lower_name = name.lower()

        if (
            not name
            or lower_name in PROHIBITED_HEADERS
            or "\n" in name
            or "\r" in name
            or ":" in name
        ):
            raise ConfigurationRejected(
                f"Header '{name}' is not allowed."
            )

        value = str(value)

        if (
            len(name) > 100
            or len(value) > 4096
            or "\n" in value
            or "\r" in value
        ):
            raise ConfigurationRejected(
                f"Header '{name}' is invalid or too long."
            )

        headers[name] = value

    return headers


def owned_project(
    db: Session,
    owner_user_id: int,
    public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM projects
                WHERE public_id = :public_id
                  AND owner_user_id = :owner_user_id
                  AND deleted_at IS NULL
                LIMIT 1
                """
            ),
            {
                "public_id": public_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def owned_configuration(
    db: Session,
    owner_user_id: int,
    project_id: int,
    config_public_id: str,
):
    return (
        db.execute(
            text(
                """
                SELECT *
                FROM api_test_configurations
                WHERE public_id = :public_id
                  AND project_id = :project_id
                  AND owner_user_id = :owner_user_id
                  AND is_active = TRUE
                LIMIT 1
                """
            ),
            {
                "public_id": config_public_id,
                "project_id": project_id,
                "owner_user_id": owner_user_id,
            },
        )
        .mappings()
        .first()
    )


def auth_summary(
    auth_type: str,
    encrypted_config: str | None,
) -> str:
    config = decrypt_json(encrypted_config)

    if auth_type == "none":
        return "No authentication"

    if auth_type == "bearer":
        return "Bearer token configured"

    if auth_type == "basic":
        username = config.get("username", "")
        return (
            f"Basic authentication · {username}"
            if username
            else "Basic authentication configured"
        )

    if auth_type == "api_key":
        header = config.get(
            "name",
            "API key",
        )
        location = config.get(
            "location",
            "header",
        )

        return f"API key · {header} · {location}"

    if auth_type == "oauth2":
        return "OAuth2 client credentials configured"
    if auth_type == "login_json":
        return "JSON login handshake configured"

    return "Authentication configured"


@router.get("/projects/{project_public_id}/test-config")
def configuration_list_page(
    request: Request,
    project_public_id: str,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    try:
        uuid.UUID(project_public_id)
    except ValueError:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            project_public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        configurations = (
            db.execute(
                text(
                    """
                    SELECT *
                    FROM api_test_configurations
                    WHERE project_id = :project_id
                      AND owner_user_id = :owner_user_id
                      AND is_active = TRUE
                    ORDER BY updated_at DESC
                    """
                ),
                {
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                },
            )
            .mappings()
            .all()
        )

    cards = ""

    for config in configurations:
        config_id = esc(config["public_id"])

        cards += f"""
        <article class="test-config-card">
            <div class="config-card-top">
                <span class="environment-badge">
                    {esc(config["environment"].title())}
                </span>

                {
                    '<span class="safe-badge">Safe mode</span>'
                    if config["safe_mode"]
                    else '<span class="danger-badge">Expanded mode</span>'
                }
            </div>

            <h3>{esc(config["name"])}</h3>

            <div class="config-url-row">
                <code id="config-url-{config_id}">
                    {esc(config["base_url"])}
                </code>

                <button type="button"
                        class="copy-code-button"
                        data-copy-target="#config-url-{config_id}">
                    ⧉ Copy
                </button>
            </div>

            <p>
                {esc(
                    auth_summary(
                        config["auth_type"],
                        config["encrypted_auth_config"],
                    )
                )}
            </p>

            <div class="config-meta">
                <span>
                    Timeout:
                    {esc(str(config["request_timeout_seconds"]))}s
                </span>
                <span>
                    Retries:
                    {esc(str(config["retry_count"]))}
                </span>
                <span>
                    TLS verification:
                    {"On" if config["verify_tls"] else "Off"}
                </span>
            </div>

            <div class="config-actions">
                <a href="/projects/{esc(project_public_id)}/test-config/{config_id}">
                    Edit configuration
                </a>
            </div>
        </article>
        """

    if not cards:
        cards = """
        <div class="config-empty">
            <div>🦊</div>
            <h2>No test environment configured</h2>
            <p>
                Add a public HTTPS base URL and optional
                authentication credentials.
            </p>
        </div>
        """

    notice = (
        f'<div class="message">{esc(message)}</div>'
        if message
        else ""
    )

    content = f"""
<section class="test-config-shell">
    <div class="test-config-heading">
        <div>
            <a href="/projects/{esc(project_public_id)}">
                ← {esc(project["name"])}
            </a>
            <span>API TESTING</span>
            <h1>Test configurations</h1>
            <p>
                Secrets are encrypted and never displayed again
                after saving.
            </p>
        </div>

        <a class="primary-button"
           href="/projects/{esc(project_public_id)}/test-config/new">
            + New configuration
        </a>
    </div>

    {notice}

    <div class="vault-notice">
        <span>🔐</span>
        <div>
            <strong>Encrypted secrets vault</strong>
            <p>
                Authentication values and custom headers are
                encrypted at rest. Reports will automatically
                mask secret values.
            </p>
        </div>
    </div>

    <div class="test-config-grid">
        {cards}
    </div>
</section>
"""

    return layout(
        "API test configurations",
        content,
        request,
        public=False,
    )


def configuration_form_page(
    request: Request,
    project,
    configuration=None,
    message: str = "",
):
    csrf = csrf_token(request)
    editing = configuration is not None

    config_name = (
        configuration["name"]
        if editing
        else "Testing"
    )
    environment = (
        configuration["environment"]
        if editing
        else "testing"
    )
    base_url = (
        configuration["base_url"]
        if editing
        else ""
    )
    auth_type = (
        configuration["auth_type"]
        if editing
        else "none"
    )
    timeout = (
        configuration["request_timeout_seconds"]
        if editing
        else 15
    )
    retries = (
        configuration["retry_count"]
        if editing
        else 0
    )
    safe_mode = (
        bool(configuration["safe_mode"])
        if editing
        else True
    )

    auth_config = (
        decrypt_json(
            configuration["encrypted_auth_config"]
        )
        if editing
        else {}
    )

    custom_headers = (
        decrypt_json(
            configuration["encrypted_custom_headers"]
        )
        if editing
        else {}
    )

    action = (
        f"/projects/{project['public_id']}/"
        f"test-config/{configuration['public_id']}"
        if editing
        else (
            f"/projects/{project['public_id']}/"
            "test-config/new"
        )
    )

    notice = (
        f'<div class="message error">{esc(message)}</div>'
        if message
        else ""
    )

    content = f"""
<section class="config-form-shell">
    <div class="config-security-panel">
        <span class="pill">SAFE API TESTING</span>
        <div class="config-fox">🦊</div>
        <h1>Configure before Qubi tests.</h1>
        <p>
            QAFox validates targets and encrypts credentials
            before the execution engine can use them.
        </p>

        <div class="config-safety-list">
            <span>✓ HTTPS targets only</span>
            <span>✓ Private/internal targets blocked</span>
            <span>✓ Credentials encrypted at rest</span>
            <span>✓ Secret values masked in reports</span>
            <span>✓ TLS verification required</span>
            <span>✓ Safe methods enabled by default</span>
        </div>
    </div>

    <form class="config-form"
          method="post"
          action="{esc(action)}">

        <span class="auth-kicker">
            {
                "EDIT CONFIGURATION"
                if editing
                else "NEW CONFIGURATION"
            }
        </span>

        <h2>
            {
                "Update test configuration"
                if editing
                else "Configure test environment"
            }
        </h2>

        <p>
            Secret fields left blank while editing retain their
            existing encrypted values.
        </p>

        {notice}

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <label>
            Configuration name
            <input name="config_name"
                   required
                   minlength="2"
                   maxlength="120"
                   value="{esc(config_name)}">
        </label>

        <label>
            Environment
            <select name="environment">
                {
                    "".join(
                        f'<option value="{item}"'
                        + (
                            " selected"
                            if environment == item
                            else ""
                        )
                        + f'>{item.title()}</option>'
                        for item in sorted(
                            ALLOWED_ENVIRONMENTS
                        )
                    )
                }
            </select>
        </label>

        <label>
            HTTPS base URL
            <div class="input-with-copy">
                <input name="base_url"
                       id="qafox-base-url"
                       required
                       maxlength="2048"
                       placeholder="https://api.example.com"
                       value="{esc(base_url)}">

                <button type="button"
                        class="copy-button"
                        data-copy-target="#qafox-base-url">
                    ⧉ Copy
                </button>
            </div>
        </label>

        <label>
            Authentication
            <select name="auth_type"
                    id="qafox-auth-type">
                {
                    "".join(
                        f'<option value="{item}"'
                        + (
                            " selected"
                            if auth_type == item
                            else ""
                        )
                        + f'>{item.replace("_", " ").title()}</option>'
                        for item in sorted(
                            ALLOWED_AUTH_TYPES
                        )
                    )
                }
            </select>
        </label>

        <div class="auth-config-fields"
             data-auth-section="bearer">
            <label>
                Bearer token
                <input type="password"
                       name="bearer_token"
                       maxlength="8192"
                       autocomplete="off"
                       placeholder="{
                           'Leave blank to retain existing token'
                           if auth_config.get('token')
                           else 'Enter bearer token'
                       }">
            </label>
        </div>

        <div class="auth-config-fields"
             data-auth-section="api_key">
            <label>
                API key name
                <input name="api_key_name"
                       maxlength="100"
                       value="{esc(auth_config.get('name', ''))}"
                       placeholder="X-API-Key">
            </label>

            <label>
                API key location
                <select name="api_key_location">
                    <option value="header"
                        {
                            "selected"
                            if auth_config.get(
                                "location",
                                "header",
                            ) == "header"
                            else ""
                        }>
                        Request header
                    </option>
                    <option value="query"
                        {
                            "selected"
                            if auth_config.get("location") == "query"
                            else ""
                        }>
                        Query parameter
                    </option>
                </select>
            </label>

            <label>
                API key value
                <input type="password"
                       name="api_key_value"
                       maxlength="8192"
                       autocomplete="off"
                       placeholder="{
                           'Leave blank to retain existing key'
                           if auth_config.get('value')
                           else 'Enter API key'
                       }">
            </label>
        </div>

        <div class="auth-config-fields"
             data-auth-section="basic">
            <label>
                Basic-auth username
                <input name="basic_username"
                       maxlength="320"
                       autocomplete="off"
                       value="{esc(auth_config.get('username', ''))}">
            </label>

            <label>
                Basic-auth password
                <input type="password"
                       name="basic_password"
                       maxlength="8192"
                       autocomplete="new-password"
                       placeholder="{
                           'Leave blank to retain existing password'
                           if auth_config.get('password')
                           else 'Enter password'
                       }">
            </label>
        </div>

        <div class="auth-config-fields"
             data-auth-section="oauth2">
            <p>
                QAFox POSTs client credentials to a public HTTPS token URL,
                then sends <code>Authorization: Bearer</code> for this run.
                Cookie sessions are not used.
            </p>
            <label>
                Token URL
                <input type="url"
                       name="oauth_token_url"
                       maxlength="2048"
                       value="{esc(auth_config.get('token_url', ''))}"
                       placeholder="https://auth.example.com/oauth/token">
            </label>
            <label>
                Client ID
                <input name="oauth_client_id"
                       maxlength="320"
                       autocomplete="off"
                       value="{esc(auth_config.get('client_id', ''))}">
            </label>
            <label>
                Client secret
                <input type="password"
                       name="oauth_client_secret"
                       maxlength="8192"
                       autocomplete="new-password"
                       placeholder="{
                           'Leave blank to retain existing secret'
                           if auth_config.get('client_secret')
                           else 'Enter client secret'
                       }">
            </label>
        </div>

        <div class="auth-config-fields"
             data-auth-section="login_json">
            <p>
                QAFox POSTs username and password as JSON and reads an access
                token from the body. MFA challenges stop automation; store a
                vault bearer token instead.
            </p>
            <label>
                Login URL
                <input type="url"
                       name="login_url"
                       maxlength="2048"
                       value="{esc(auth_config.get('login_url', ''))}"
                       placeholder="https://api.example.com/login">
            </label>
            <label>
                Username
                <input name="login_username"
                       maxlength="320"
                       autocomplete="off"
                       value="{esc(auth_config.get('username', ''))}">
            </label>
            <label>
                Password
                <input type="password"
                       name="login_password"
                       maxlength="8192"
                       autocomplete="new-password"
                       placeholder="{
                           'Leave blank to retain existing password'
                           if auth_config.get('password')
                           else 'Enter password'
                       }">
            </label>
        </div>

        <label>
            Custom headers
            <small>
                Optional JSON object. Values are encrypted.
            </small>
            <textarea name="custom_headers"
                      rows="5"
                      maxlength="20000"
                      placeholder='{{"X-Tenant-ID":"demo"}}'>{esc(
                          json.dumps(
                              custom_headers,
                              ensure_ascii=False,
                              indent=2,
                          )
                          if custom_headers
                          else ""
                      )}</textarea>
        </label>

        <div class="config-form-grid">
            <label>
                Request timeout
                <select name="request_timeout_seconds">
                    {
                        "".join(
                            f'<option value="{item}"'
                            + (
                                " selected"
                                if timeout == item
                                else ""
                            )
                            + f'>{item} seconds</option>'
                            for item in (5, 10, 15, 30, 45)
                        )
                    }
                </select>
            </label>

            <label>
                Retry count
                <select name="retry_count">
                    {
                        "".join(
                            f'<option value="{item}"'
                            + (
                                " selected"
                                if retries == item
                                else ""
                            )
                            + f'>{item}</option>'
                            for item in (0, 1, 2)
                        )
                    }
                </select>
            </label>
        </div>

        <label class="checkbox config-checkbox">
            <input type="checkbox"
                   name="safe_mode"
                   value="yes"
                   {"checked" if safe_mode else ""}>
            <span>
                <strong>Safe mode</strong><br>
                Allow only GET, HEAD and OPTIONS until explicit
                destructive-method approval is implemented.
            </span>
        </label>

        <label class="checkbox config-checkbox mandatory">
            <input type="checkbox"
                   checked
                   disabled>
            <span>
                <strong>TLS verification required</strong><br>
                Invalid and untrusted HTTPS certificates are
                rejected.
            </span>
        </label>

        <button class="primary-button full"
                type="submit">
            Save encrypted configuration
        </button>

        <a class="cancel-link"
           href="/projects/{esc(project['public_id'])}/test-config">
            Cancel
        </a>
    </form>
</section>
"""

    return layout(
        "Test configuration",
        content,
        request,
        public=False,
    )


@router.get("/projects/{project_public_id}/test-config/new")
def new_configuration_page(
    request: Request,
    project_public_id: str,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            project_public_id,
        )

    if not project:
        return RedirectResponse(
            "/projects",
            status_code=303,
        )

    return configuration_form_page(
        request,
        project,
        message=message,
    )


def build_auth_configuration(
    auth_type: str,
    existing: dict,
    bearer_token: str,
    api_key_name: str,
    api_key_location: str,
    api_key_value: str,
    basic_username: str,
    basic_password: str,
    oauth_token_url: str = "",
    oauth_client_id: str = "",
    oauth_client_secret: str = "",
    login_url: str = "",
    login_username: str = "",
    login_password: str = "",
) -> dict:
    if auth_type == "none":
        return {}

    if auth_type == "bearer":
        token = bearer_token.strip() or existing.get(
            "token",
            "",
        )

        if not token:
            raise ConfigurationRejected(
                "Bearer token is required."
            )

        return {"token": token}

    if auth_type == "api_key":
        name = api_key_name.strip()
        location = api_key_location.strip()
        value = api_key_value.strip() or existing.get(
            "value",
            "",
        )

        if (
            not name
            or location not in {"header", "query"}
            or not value
        ):
            raise ConfigurationRejected(
                "API key name, location and value are required."
            )

        if (
            location == "header"
            and name.lower() in PROHIBITED_HEADERS
        ):
            raise ConfigurationRejected(
                "That API-key header is not allowed."
            )

        return {
            "name": name[:100],
            "location": location,
            "value": value,
        }

    if auth_type == "basic":
        username = basic_username.strip()
        password = basic_password or existing.get(
            "password",
            "",
        )

        if not username or not password:
            raise ConfigurationRejected(
                "Basic-auth username and password are required."
            )

        return {
            "username": username[:320],
            "password": password,
        }

    if auth_type == "oauth2":
        token_url = oauth_token_url.strip() or existing.get(
            "token_url",
            "",
        )
        client_id = oauth_client_id.strip() or existing.get(
            "client_id",
            "",
        )
        client_secret = oauth_client_secret.strip() or existing.get(
            "client_secret",
            "",
        )

        if not token_url or not client_id or not client_secret:
            raise ConfigurationRejected(
                "OAuth2 token URL, client ID, and client secret are required."
            )

        if not token_url.lower().startswith("https://"):
            raise ConfigurationRejected(
                "OAuth2 token URL must be public HTTPS."
            )

        return {
            "token_url": token_url[:2048],
            "client_id": client_id[:320],
            "client_secret": client_secret,
        }

    if auth_type == "login_json":
        resolved_login_url = login_url.strip() or existing.get(
            "login_url",
            "",
        )
        username = login_username.strip() or existing.get(
            "username",
            "",
        )
        password = login_password or existing.get(
            "password",
            "",
        )

        if not resolved_login_url or not username or not password:
            raise ConfigurationRejected(
                "JSON login URL, username, and password are required."
            )

        if not resolved_login_url.lower().startswith("https://"):
            raise ConfigurationRejected(
                "JSON login URL must be public HTTPS."
            )

        return {
            "login_url": resolved_login_url[:2048],
            "username": username[:320],
            "password": password,
        }

    raise ConfigurationRejected(
        "Choose a valid authentication type."
    )


def save_configuration(
    request: Request,
    project_public_id: str,
    configuration_public_id: str | None,
    config_name: str,
    environment: str,
    base_url: str,
    auth_type: str,
    bearer_token: str,
    api_key_name: str,
    api_key_location: str,
    api_key_value: str,
    basic_username: str,
    basic_password: str,
    oauth_token_url: str,
    oauth_client_id: str,
    oauth_client_secret: str,
    login_url: str,
    login_username: str,
    login_password: str,
    custom_headers: str,
    request_timeout_seconds: int,
    retry_count: int,
    safe_mode: str,
    csrf: str,
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    failure_path = (
        f"/projects/{project_public_id}/test-config/"
        f"{configuration_public_id}"
        if configuration_public_id
        else (
            f"/projects/{project_public_id}/"
            "test-config/new"
        )
    )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            failure_path + "?message=Session+expired.",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            project_public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        existing_config = None
        existing_auth = {}

        if configuration_public_id:
            existing_config = owned_configuration(
                db,
                user.id,
                project["id"],
                configuration_public_id,
            )

            if not existing_config:
                return RedirectResponse(
                    f"/projects/{project_public_id}/test-config",
                    status_code=303,
                )

            existing_auth = decrypt_json(
                existing_config[
                    "encrypted_auth_config"
                ]
            )

        try:
            config_name = config_name.strip()

            if len(config_name) < 2:
                raise ConfigurationRejected(
                    "Enter a configuration name."
                )

            environment = environment.strip().lower()

            if environment not in ALLOWED_ENVIRONMENTS:
                raise ConfigurationRejected(
                    "Choose a valid environment."
                )

            auth_type = auth_type.strip().lower()

            if auth_type not in ALLOWED_AUTH_TYPES:
                raise ConfigurationRejected(
                    "Choose a valid authentication type."
                )

            validated_url = validate_base_url(
                base_url
            )

            headers = parse_custom_headers(
                custom_headers
            )

            auth_config = build_auth_configuration(
                auth_type,
                existing_auth,
                bearer_token,
                api_key_name,
                api_key_location,
                api_key_value,
                basic_username,
                basic_password,
                oauth_token_url,
                oauth_client_id,
                oauth_client_secret,
                login_url,
                login_username,
                login_password,
            )

            timeout = int(request_timeout_seconds)
            retries = int(retry_count)

            if timeout not in {5, 10, 15, 30, 45}:
                raise ConfigurationRejected(
                    "Choose a valid timeout."
                )

            if retries not in {0, 1, 2}:
                raise ConfigurationRejected(
                    "Choose a valid retry count."
                )

        except (
            ConfigurationRejected,
            ValueError,
        ) as exc:
            return RedirectResponse(
                failure_path
                + "?message="
                + str(exc).replace(" ", "+"),
                status_code=303,
            )

        now = utc_now()

        try:
            if existing_config:
                db.execute(
                    text(
                        """
                        UPDATE api_test_configurations
                        SET
                            name = :name,
                            environment = :environment,
                            base_url = :base_url,
                            auth_type = :auth_type,
                            encrypted_auth_config =
                                :encrypted_auth_config,
                            encrypted_custom_headers =
                                :encrypted_custom_headers,
                            request_timeout_seconds = :timeout,
                            retry_count = :retry_count,
                            verify_tls = TRUE,
                            safe_mode = :safe_mode,
                            allow_destructive_methods = FALSE,
                            updated_at = :updated_at
                        WHERE id = :id
                          AND owner_user_id = :owner_user_id
                          AND project_id = :project_id
                        """
                    ),
                    {
                        "name": config_name[:120],
                        "environment": environment,
                        "base_url": validated_url,
                        "auth_type": auth_type,
                        "encrypted_auth_config": encrypt_json(
                            auth_config
                        ),
                        "encrypted_custom_headers": encrypt_json(
                            headers
                        ),
                        "timeout": timeout,
                        "retry_count": retries,
                        "safe_mode": safe_mode == "yes",
                        "updated_at": now,
                        "id": existing_config["id"],
                        "owner_user_id": user.id,
                        "project_id": project["id"],
                    },
                )

                summary = (
                    "API test configuration updated."
                )
            else:
                db.execute(
                    text(
                        """
                        INSERT INTO api_test_configurations (
                            public_id,
                            project_id,
                            owner_user_id,
                            name,
                            environment,
                            base_url,
                            auth_type,
                            encrypted_auth_config,
                            encrypted_custom_headers,
                            request_timeout_seconds,
                            retry_count,
                            verify_tls,
                            safe_mode,
                            allow_destructive_methods,
                            is_active,
                            created_at,
                            updated_at
                        )
                        VALUES (
                            :public_id,
                            :project_id,
                            :owner_user_id,
                            :name,
                            :environment,
                            :base_url,
                            :auth_type,
                            :encrypted_auth_config,
                            :encrypted_custom_headers,
                            :timeout,
                            :retry_count,
                            TRUE,
                            :safe_mode,
                            FALSE,
                            TRUE,
                            :created_at,
                            :updated_at
                        )
                        """
                    ),
                    {
                        "public_id": str(uuid.uuid4()),
                        "project_id": project["id"],
                        "owner_user_id": user.id,
                        "name": config_name[:120],
                        "environment": environment,
                        "base_url": validated_url,
                        "auth_type": auth_type,
                        "encrypted_auth_config": encrypt_json(
                            auth_config
                        ),
                        "encrypted_custom_headers": encrypt_json(
                            headers
                        ),
                        "timeout": timeout,
                        "retry_count": retries,
                        "safe_mode": safe_mode == "yes",
                        "created_at": now,
                        "updated_at": now,
                    },
                )

                summary = (
                    "Encrypted API test configuration created."
                )

            db.execute(
                text(
                    """
                    INSERT INTO project_audit_events (
                        project_id,
                        owner_user_id,
                        event_type,
                        event_summary,
                        created_at
                    )
                    VALUES (
                        :project_id,
                        :owner_user_id,
                        'test-configuration-saved',
                        :summary,
                        :created_at
                    )
                    """
                ),
                {
                    "project_id": project["id"],
                    "owner_user_id": user.id,
                    "summary": summary,
                    "created_at": now,
                },
            )

            db.commit()

        except Exception:
            db.rollback()

            return RedirectResponse(
                failure_path
                + "?message=Configuration+name+already+exists+or+could+not+be+saved.",
                status_code=303,
            )

    return RedirectResponse(
        f"/projects/{project_public_id}/test-config"
        "?message=Encrypted+configuration+saved.",
        status_code=303,
    )


@router.post("/projects/{project_public_id}/test-config/new")
def create_configuration(
    request: Request,
    project_public_id: str,
    config_name: str = Form(...),
    environment: str = Form(...),
    base_url: str = Form(...),
    auth_type: str = Form("none"),
    bearer_token: str = Form(""),
    api_key_name: str = Form(""),
    api_key_location: str = Form("header"),
    api_key_value: str = Form(""),
    basic_username: str = Form(""),
    basic_password: str = Form(""),
    oauth_token_url: str = Form(""),
    oauth_client_id: str = Form(""),
    oauth_client_secret: str = Form(""),
    login_url: str = Form(""),
    login_username: str = Form(""),
    login_password: str = Form(""),
    custom_headers: str = Form(""),
    request_timeout_seconds: int = Form(15),
    retry_count: int = Form(0),
    safe_mode: str = Form(""),
    csrf: str = Form(...),
):
    return save_configuration(
        request,
        project_public_id,
        None,
        config_name,
        environment,
        base_url,
        auth_type,
        bearer_token,
        api_key_name,
        api_key_location,
        api_key_value,
        basic_username,
        basic_password,
        oauth_token_url,
        oauth_client_id,
        oauth_client_secret,
        login_url,
        login_username,
        login_password,
        custom_headers,
        request_timeout_seconds,
        retry_count,
        safe_mode,
        csrf,
    )


@router.get(
    "/projects/{project_public_id}/"
    "test-config/{configuration_public_id}"
)
def edit_configuration_page(
    request: Request,
    project_public_id: str,
    configuration_public_id: str,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with Session(engine) as db:
        project = owned_project(
            db,
            user.id,
            project_public_id,
        )

        if not project:
            return RedirectResponse(
                "/projects",
                status_code=303,
            )

        configuration = owned_configuration(
            db,
            user.id,
            project["id"],
            configuration_public_id,
        )

    if not configuration:
        return RedirectResponse(
            f"/projects/{project_public_id}/test-config",
            status_code=303,
        )

    return configuration_form_page(
        request,
        project,
        configuration,
        message,
    )


@router.post(
    "/projects/{project_public_id}/"
    "test-config/{configuration_public_id}"
)
def update_configuration(
    request: Request,
    project_public_id: str,
    configuration_public_id: str,
    config_name: str = Form(...),
    environment: str = Form(...),
    base_url: str = Form(...),
    auth_type: str = Form("none"),
    bearer_token: str = Form(""),
    api_key_name: str = Form(""),
    api_key_location: str = Form("header"),
    api_key_value: str = Form(""),
    basic_username: str = Form(""),
    basic_password: str = Form(""),
    oauth_token_url: str = Form(""),
    oauth_client_id: str = Form(""),
    oauth_client_secret: str = Form(""),
    login_url: str = Form(""),
    login_username: str = Form(""),
    login_password: str = Form(""),
    custom_headers: str = Form(""),
    request_timeout_seconds: int = Form(15),
    retry_count: int = Form(0),
    safe_mode: str = Form(""),
    csrf: str = Form(...),
):
    return save_configuration(
        request,
        project_public_id,
        configuration_public_id,
        config_name,
        environment,
        base_url,
        auth_type,
        bearer_token,
        api_key_name,
        api_key_location,
        api_key_value,
        basic_username,
        basic_password,
        oauth_token_url,
        oauth_client_id,
        oauth_client_secret,
        login_url,
        login_username,
        login_password,
        custom_headers,
        request_timeout_seconds,
        retry_count,
        safe_mode,
        csrf,
    )
