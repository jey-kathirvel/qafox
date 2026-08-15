import base64
import io
import json
import os
import secrets
import string
from datetime import datetime, timezone

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.main import (
    User,
    csrf_token,
    csrf_valid,
    current_user,
    engine,
    esc,
    layout,
    password_hash,
)

router = APIRouter()

fernet = Fernet(
    os.environ["MFA_ENCRYPTION_KEY"].encode("ascii")
)

RECOVERY_ALPHABET = (
    string.ascii_uppercase
    + string.digits
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(
        secret.encode("utf-8")
    ).decode("ascii")


def decrypt_secret(encrypted: str | None) -> str | None:
    if not encrypted:
        return None

    try:
        return fernet.decrypt(
            encrypted.encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def normalize_totp_code(value: str) -> str:
    return "".join(
        character
        for character in value
        if character.isdigit()
    )


def normalize_recovery_code(value: str) -> str:
    return "".join(
        character
        for character in value.upper()
        if character.isalnum()
    )


def create_recovery_codes() -> list[str]:
    codes = []

    for _ in range(10):
        raw = "".join(
            secrets.choice(RECOVERY_ALPHABET)
            for _ in range(12)
        )

        codes.append(
            f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        )

    return codes


def hash_recovery_codes(
    codes: list[str],
) -> list[str]:
    return [
        password_hash.hash(
            normalize_recovery_code(code)
        )
        for code in codes
    ]


def verify_recovery_code(
    submitted: str,
    stored_json: str | None,
) -> tuple[bool, str | None]:
    normalized = normalize_recovery_code(submitted)

    if len(normalized) != 12 or not stored_json:
        return False, stored_json

    try:
        stored_hashes = json.loads(stored_json)
    except (TypeError, json.JSONDecodeError):
        return False, stored_json

    if not isinstance(stored_hashes, list):
        return False, stored_json

    matched_index = None

    for index, stored_hash in enumerate(stored_hashes):
        try:
            if password_hash.verify(
                normalized,
                stored_hash,
            ):
                matched_index = index
                break
        except Exception:
            continue

    if matched_index is None:
        return False, stored_json

    del stored_hashes[matched_index]

    return True, json.dumps(stored_hashes)


def matching_totp_counter(
    secret: str,
    submitted_code: str,
) -> int | None:
    code = normalize_totp_code(submitted_code)

    if len(code) != 6:
        return None

    totp = pyotp.TOTP(secret)
    current_counter = int(
        datetime.now(timezone.utc).timestamp()
        // totp.interval
    )

    for offset in (-1, 0, 1):
        counter = current_counter + offset
        expected = totp.at(
            counter * totp.interval
        )

        if secrets.compare_digest(expected, code):
            return counter

    return None


def qr_data_uri(provisioning_uri: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )

    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image(
        fill_color="#14213d",
        back_color="white",
    )

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    encoded = base64.b64encode(
        buffer.getvalue()
    ).decode("ascii")

    return f"data:image/png;base64,{encoded}"


def mfa_page(
    request: Request,
    title: str,
    body: str,
):
    content = f"""
<section class="mfa-shell">
    <div class="mfa-heading">
        <span class="pill dark">ACCOUNT SECURITY</span>
        <h1>{esc(title)}</h1>
        <p>
            Authenticator MFA adds a rotating verification code
            after your password or passcode.
        </p>
    </div>

    {body}
</section>
"""

    return layout(title, content, request)


@router.get("/security/mfa")
def mfa_security_page(
    request: Request,
    message: str = "",
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    csrf = csrf_token(request)

    if user.mfa_enabled:
        try:
            remaining = len(
                json.loads(
                    user.mfa_recovery_codes or "[]"
                )
            )
        except Exception:
            remaining = 0

        body = f"""
<div class="mfa-status enabled">
    <div class="mfa-status-icon">✓</div>
    <div>
        <span>MFA ENABLED</span>
        <h2>Your account has an extra security layer.</h2>
        <p>
            Authenticator verification is required after your
            password or passcode.
        </p>
    </div>
</div>

<div class="mfa-grid">
    <article class="mfa-card">
        <h3>Authenticator app</h3>
        <p>Status: <strong>Enabled</strong></p>
        <p>
            Enabled on:
            {esc(
                user.mfa_enabled_at.strftime("%d %b %Y")
                if user.mfa_enabled_at
                else "Active"
            )}
        </p>
    </article>

    <article class="mfa-card">
        <h3>Recovery codes</h3>
        <p>
            Remaining one-time codes:
            <strong>{remaining}</strong>
        </p>
        <a class="outline-dark-button"
           href="/security/mfa/recovery-codes">
            Generate new codes
        </a>
    </article>
</div>

<form class="mfa-danger"
      method="post"
      action="/security/mfa/disable">

    <input type="hidden"
           name="csrf"
           value="{esc(csrf)}">

    <h3>Disable authenticator MFA</h3>
    <p>
        Enter a current authenticator code to disable MFA.
    </p>

    <label>
        Authenticator code
        <input name="verification_code"
               required
               inputmode="numeric"
               minlength="6"
               maxlength="6"
               pattern="[0-9]{{6}}">
    </label>

    <button type="submit">
        Disable MFA
    </button>
</form>
"""
    else:
        body = f"""
<div class="mfa-status">
    <div class="mfa-status-icon">🛡</div>
    <div>
        <span>MFA AVAILABLE</span>
        <h2>Protect your private projects.</h2>
        <p>
            Use Google Authenticator, Microsoft Authenticator,
            Authy or another standard TOTP application.
        </p>
    </div>
</div>

<div class="mfa-benefits">
    <article>
        <i>1</i>
        <h3>Scan a QR code</h3>
        <p>Add QAFox to your authenticator application.</p>
    </article>

    <article>
        <i>2</i>
        <h3>Verify setup</h3>
        <p>Enter one rotating 6-digit authenticator code.</p>
    </article>

    <article>
        <i>3</i>
        <h3>Save recovery codes</h3>
        <p>Keep the ten one-time codes in a safe location.</p>
    </article>
</div>

<form method="post"
      action="/security/mfa/start"
      class="mfa-start-form">

    <input type="hidden"
           name="csrf"
           value="{esc(csrf)}">

    <button class="primary-button"
            type="submit">
        Set up authenticator MFA
    </button>
</form>
"""

    if message:
        body = (
            f'<div class="message">{esc(message)}</div>'
            + body
        )

    return mfa_page(
        request,
        "Multi-factor authentication",
        body,
    )


@router.post("/security/mfa/start")
def start_mfa_setup(
    request: Request,
    csrf: str = Form(...),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/security/mfa?"
            "message=Your+session+expired.",
            status_code=303,
        )

    secret = pyotp.random_base32(length=32)
    encrypted = encrypt_secret(secret)

    with Session(engine) as db:
        database_user = db.get(User, user.id)

        if not database_user:
            return RedirectResponse(
                "/login",
                status_code=303,
            )

        database_user.mfa_pending_secret_encrypted = (
            encrypted
        )
        db.commit()

    return RedirectResponse(
        "/security/mfa/setup",
        status_code=303,
    )


@router.get("/security/mfa/setup")
def mfa_setup_page(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    with Session(engine) as db:
        database_user = db.get(User, user.id)

        secret = decrypt_secret(
            database_user.mfa_pending_secret_encrypted
            if database_user
            else None
        )

    if not secret:
        return RedirectResponse(
            "/security/mfa",
            status_code=303,
        )

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name="QAFox",
    )

    qr_image = qr_data_uri(provisioning_uri)
    csrf = csrf_token(request)

    body = f"""
<div class="mfa-setup-card">
    <div class="mfa-steps">
        <span>STEP 1 OF 2</span>
        <h2>Scan with your authenticator app</h2>
        <p>
            Open your authenticator application and scan this
            QR code.
        </p>

        <img class="mfa-qr"
             src="{qr_image}"
             alt="QAFox authenticator setup QR code">

        <details class="manual-secret">
            <summary>Cannot scan? Enter setup key manually</summary>
            <div class="copy-value-row">
                <code id="mfa-manual-secret">{esc(secret)}</code>
                <button type="button"
                        class="copy-button"
                        data-copy-target="#mfa-manual-secret">
                    <span>⧉</span>
                    Copy setup key
                </button>
            </div>
        </details>
    </div>

    <form method="post"
          action="/security/mfa/confirm"
          class="mfa-confirm-form">

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <span>STEP 2 OF 2</span>
        <h2>Verify your setup</h2>
        <p>
            Enter the current 6-digit code displayed by your
            authenticator app.
        </p>

        <label>
            Authenticator code
            <input name="verification_code"
                   required
                   autofocus
                   inputmode="numeric"
                   minlength="6"
                   maxlength="6"
                   pattern="[0-9]{{6}}"
                   autocomplete="one-time-code">
        </label>

        <button class="primary-button full"
                type="submit">
            Verify and enable MFA
        </button>

        <a class="cancel-link"
           href="/security/mfa">
            Cancel setup
        </a>
    </form>
</div>
"""

    return mfa_page(
        request,
        "Set up authenticator MFA",
        body,
    )


@router.post("/security/mfa/confirm")
def confirm_mfa_setup(
    request: Request,
    verification_code: str = Form(...),
    csrf: str = Form(...),
):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/security/mfa",
            status_code=303,
        )

    with Session(engine) as db:
        database_user = db.get(User, user.id)

        secret = decrypt_secret(
            database_user.mfa_pending_secret_encrypted
            if database_user
            else None
        )

        if not database_user or not secret:
            return RedirectResponse(
                "/security/mfa",
                status_code=303,
            )

        counter = matching_totp_counter(
            secret,
            verification_code,
        )

        if counter is None:
            return RedirectResponse(
                "/security/mfa/setup",
                status_code=303,
            )

        recovery_codes = create_recovery_codes()
        recovery_hashes = hash_recovery_codes(
            recovery_codes
        )

        database_user.mfa_enabled = True
        database_user.mfa_secret_encrypted = (
            database_user.mfa_pending_secret_encrypted
        )
        database_user.mfa_pending_secret_encrypted = None
        database_user.mfa_recovery_codes = json.dumps(
            recovery_hashes
        )
        database_user.mfa_enabled_at = now_utc()
        database_user.mfa_last_counter = counter
        database_user.auth_version = (
            database_user.auth_version or 1
        ) + 1

        new_auth_version = database_user.auth_version
        db.commit()

    request.session["auth_version"] = new_auth_version

    code_items = "".join(
        (
            '<li>'
            f'<code>{esc(code)}</code>'
            '<button type="button" '
            'class="copy-code-button" '
            'data-copy-code>'
            '<span>⧉</span>'
            '<span class="copy-label">Copy</span>'
            '</button>'
            '</li>'
        )
        for code in recovery_codes
    )

    csrf = csrf_token(request)

    body = f"""
<div class="recovery-codes-card">
    <div class="success-icon">✓</div>
    <span class="auth-kicker">MFA ENABLED</span>
    <h2>Save your recovery codes now</h2>
    <p>
        Each code works only once. Store them somewhere safe.
        QAFox cannot display these exact codes again.
    </p>

    <div class="recovery-copy-toolbar">
        <button type="button"
                class="copy-button copy-all-button"
                data-copy-list=".recovery-code-list code">
            <span>⧉</span>
            Copy all recovery codes
        </button>
    </div>

    <ul class="recovery-code-list">
        {code_items}
    </ul>

    <div class="recovery-warning">
        Do not store recovery codes inside an uploaded QAFox
        project.
    </div>

    <form method="get"
          action="/security/mfa">
        <button class="primary-button"
                type="submit">
            I have saved my recovery codes
        </button>
    </form>
</div>
"""

    return mfa_page(
        request,
        "MFA enabled",
        body,
    )


@router.get("/mfa/verify")
def mfa_verify_page(request: Request):
    pending_user_id = request.session.get(
        "pending_mfa_user_id"
    )

    if not pending_user_id:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    csrf = csrf_token(request)

    content = f"""
<section class="mfa-challenge">
    <div class="challenge-fox">🦊</div>
    <span class="pill dark">SECURITY CHECK</span>
    <h1>One more step.</h1>
    <p>
        Enter your authenticator code or one unused recovery
        code.
    </p>

    <form method="post"
          action="/mfa/verify">

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <label>
            Authenticator or recovery code
            <input name="verification_code"
                   required
                   autofocus
                   maxlength="20"
                   autocomplete="one-time-code">
        </label>

        <button class="primary-button full"
                type="submit">
            Verify and continue
        </button>
    </form>

    <a class="cancel-link" href="/logout">
        Cancel sign in
    </a>
</section>
"""

    return layout(
        "MFA verification",
        content,
        request,
    )


@router.post("/mfa/verify")
def verify_mfa_challenge(
    request: Request,
    verification_code: str = Form(...),
    csrf: str = Form(...),
):
    pending_user_id = request.session.get(
        "pending_mfa_user_id"
    )
    pending_auth_version = request.session.get(
        "pending_mfa_auth_version"
    )

    if not pending_user_id:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        request.session.clear()

        return RedirectResponse(
            "/login?"
            "message=Security+session+expired.",
            status_code=303,
        )

    attempts = int(
        request.session.get("mfa_attempts", 0)
    )

    with Session(engine) as db:
        user = db.get(User, int(pending_user_id))

        if (
            not user
            or not user.is_active
            or not user.mfa_enabled
            or user.auth_version != pending_auth_version
        ):
            request.session.clear()

            return RedirectResponse(
                "/login?"
                "message=Security+session+expired.",
                status_code=303,
            )

        verified = False
        recovery_used = False

        normalized_totp = normalize_totp_code(
            verification_code
        )

        if len(normalized_totp) == 6:
            secret = decrypt_secret(
                user.mfa_secret_encrypted
            )

            if secret:
                counter = matching_totp_counter(
                    secret,
                    normalized_totp,
                )

                last_counter = user.mfa_last_counter

                if (
                    counter is not None
                    and (
                        last_counter is None
                        or counter > last_counter
                    )
                ):
                    user.mfa_last_counter = counter
                    verified = True

        if not verified:
            (
                recovery_used,
                updated_codes,
            ) = verify_recovery_code(
                verification_code,
                user.mfa_recovery_codes,
            )

            if recovery_used:
                user.mfa_recovery_codes = updated_codes
                verified = True

        if not verified:
            attempts += 1
            request.session["mfa_attempts"] = attempts

            if attempts >= 5:
                request.session.clear()

                return RedirectResponse(
                    "/login?"
                    "message=Too+many+MFA+attempts.+Sign+in+again.",
                    status_code=303,
                )

            db.rollback()

            return RedirectResponse(
                "/mfa/verify",
                status_code=303,
            )

        db.commit()

        request.session.clear()
        request.session["user_id"] = user.id
        request.session["auth_version"] = (
            user.auth_version
        )
        request.session["csrf_token"] = (
            secrets.token_urlsafe(32)
        )

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


@router.get("/security/mfa/recovery-codes")
def regenerate_codes_page(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not user.mfa_enabled:
        return RedirectResponse(
            "/security/mfa",
            status_code=303,
        )

    csrf = csrf_token(request)

    body = f"""
<div class="mfa-confirm-card">
    <span class="auth-kicker">RECOVERY CODES</span>
    <h2>Replace all existing recovery codes?</h2>
    <p>
        Generating new codes permanently invalidates every
        remaining old recovery code.
    </p>

    <form method="post"
          action="/security/mfa/recovery-codes">

        <input type="hidden"
               name="csrf"
               value="{esc(csrf)}">

        <label>
            Current authenticator code
            <input name="verification_code"
                   required
                   inputmode="numeric"
                   minlength="6"
                   maxlength="6"
                   pattern="[0-9]{{6}}">
        </label>

        <button class="primary-button full"
                type="submit">
            Verify and generate new codes
        </button>
    </form>

    <a class="cancel-link"
       href="/security/mfa">
        Cancel
    </a>
</div>
"""

    return mfa_page(
        request,
        "Generate recovery codes",
        body,
    )


@router.post("/security/mfa/recovery-codes")
def regenerate_recovery_codes(
    request: Request,
    verification_code: str = Form(...),
    csrf: str = Form(...),
):
    user = current_user(request)

    if not user or not user.mfa_enabled:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/security/mfa",
            status_code=303,
        )

    with Session(engine) as db:
        database_user = db.get(User, user.id)
        secret = decrypt_secret(
            database_user.mfa_secret_encrypted
            if database_user
            else None
        )

        if not database_user or not secret:
            return RedirectResponse(
                "/security/mfa",
                status_code=303,
            )

        counter = matching_totp_counter(
            secret,
            verification_code,
        )

        if (
            counter is None
            or (
                database_user.mfa_last_counter is not None
                and counter <= database_user.mfa_last_counter
            )
        ):
            return RedirectResponse(
                "/security/mfa/recovery-codes",
                status_code=303,
            )

        recovery_codes = create_recovery_codes()
        database_user.mfa_recovery_codes = json.dumps(
            hash_recovery_codes(recovery_codes)
        )
        database_user.mfa_last_counter = counter
        db.commit()

    code_items = "".join(
        (
            '<li>'
            f'<code>{esc(code)}</code>'
            '<button type="button" '
            'class="copy-code-button" '
            'data-copy-code>'
            '<span>⧉</span>'
            '<span class="copy-label">Copy</span>'
            '</button>'
            '</li>'
        )
        for code in recovery_codes
    )

    body = f"""
<div class="recovery-codes-card">
    <div class="success-icon">✓</div>
    <h2>New recovery codes</h2>
    <p>
        Your previous recovery codes are now invalid.
        Save these new codes securely.
    </p>

    <div class="recovery-copy-toolbar">
        <button type="button"
                class="copy-button copy-all-button"
                data-copy-list=".recovery-code-list code">
            <span>⧉</span>
            Copy all recovery codes
        </button>
    </div>

    <ul class="recovery-code-list">
        {code_items}
    </ul>

    <a class="primary-button"
       href="/security/mfa">
        I have saved the new codes
    </a>
</div>
"""

    return mfa_page(
        request,
        "New recovery codes",
        body,
    )


@router.post("/security/mfa/disable")
def disable_mfa(
    request: Request,
    verification_code: str = Form(...),
    csrf: str = Form(...),
):
    user = current_user(request)

    if not user or not user.mfa_enabled:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/security/mfa",
            status_code=303,
        )

    with Session(engine) as db:
        database_user = db.get(User, user.id)

        secret = decrypt_secret(
            database_user.mfa_secret_encrypted
            if database_user
            else None
        )

        if not database_user or not secret:
            return RedirectResponse(
                "/security/mfa",
                status_code=303,
            )

        counter = matching_totp_counter(
            secret,
            verification_code,
        )

        if (
            counter is None
            or (
                database_user.mfa_last_counter is not None
                and counter <= database_user.mfa_last_counter
            )
        ):
            return RedirectResponse(
                "/security/mfa?"
                "message=Invalid+or+previously+used+code.",
                status_code=303,
            )

        database_user.mfa_enabled = False
        database_user.mfa_secret_encrypted = None
        database_user.mfa_pending_secret_encrypted = None
        database_user.mfa_recovery_codes = None
        database_user.mfa_enabled_at = None
        database_user.mfa_last_counter = None
        database_user.auth_version = (
            database_user.auth_version or 1
        ) + 1

        new_auth_version = database_user.auth_version
        db.commit()

    request.session["auth_version"] = new_auth_version

    return RedirectResponse(
        "/security/mfa?"
        "message=Authenticator+MFA+has+been+disabled.",
        status_code=303,
    )
