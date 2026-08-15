import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.main import (
    User,
    csrf_token,
    csrf_valid,
    engine,
    esc,
    layout,
    password_hash,
    send_email,
)

router = APIRouter()


WEAK_PASSCODES = {
    "000000",
    "111111",
    "123456",
    "121212",
    "654321",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999",
}

GENERIC_RECOVERY_MESSAGE = (
    "If the account details are valid, recovery "
    "instructions have been sent to the registered email."
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def normalize_database_datetime(
    value: datetime | None,
) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value


def recovery_notice(message: str, kind: str = "info") -> str:
    if not message:
        return ""

    return (
        f'<div class="message {esc(kind)}">'
        f'{esc(message)}'
        "</div>"
    )


def recovery_layout(
    request: Request,
    title: str,
    heading: str,
    description: str,
    form_content: str,
    message: str = "",
):
    content = f"""
<section class="recovery-shell">
    <div class="recovery-art">
        <span class="pill">SECURE ACCOUNT RECOVERY</span>
        <div class="recovery-fox">🦊</div>
        <h1>Qubi will help you<br>get back safely.</h1>
        <p>
            Recovery information is sent only to the registered
            email address. QAFox never displays whether an account
            exists.
        </p>
        <div class="recovery-security">
            <strong>🛡 Privacy protected</strong>
            <small>
                Recovery links expire automatically and can be
                used only once.
            </small>
        </div>
    </div>

    <div class="recovery-card">
        <span class="auth-kicker">ACCOUNT ACCESS</span>
        <h2>{esc(heading)}</h2>
        <p>{esc(description)}</p>

        {recovery_notice(message)}

        {form_content}

        <div class="auth-links">
            <a href="/login">← Return to secure sign in</a>
        </div>
    </div>
</section>
"""

    return layout(title, content, request)


def send_password_reset(user: User, raw_token: str) -> None:
    reset_url = (
        "https://qafox.ads-ai.in/reset-credential"
        f"?token={quote(raw_token)}"
    )

    send_email(
        user.email,
        "Reset your QAFox account credential",
        f"""Hello {user.full_name},

A request was received to reset the password or passcode for
your QAFox account.

Use this secure link:

{reset_url}

The link expires in 30 minutes and can be used only once.

If you did not request this change, do not use the link. Your
existing credential remains unchanged.

QAFox
Hunt Issues. Ship Quality.
Developed by ads-ai.in
""",
    )


def send_username_recovery(user: User) -> None:
    send_email(
        user.email,
        "Your QAFox username",
        f"""Hello {user.full_name},

Your QAFox username is:

{user.username}

Sign in securely:
https://qafox.ads-ai.in/login

If you did not request this reminder, you may safely ignore
this email.

QAFox
Hunt Issues. Ship Quality.
Developed by ads-ai.in
""",
    )


@router.get("/forgot-password")
def forgot_password_page(
    request: Request,
    message: str = "",
):
    token = csrf_token(request)

    form_content = f"""
<form method="post"
      action="/forgot-password"
      class="recovery-form">

    <input type="hidden"
           name="csrf"
           value="{esc(token)}">

    <label>
        Username or registered email
        <input name="identity"
               required
               maxlength="320"
               autocomplete="username">
    </label>

    <button class="primary-button full"
            type="submit">
        Send secure recovery link
    </button>
</form>
"""

    return recovery_layout(
        request,
        "Password or passcode recovery",
        "Reset password or passcode",
        (
            "Enter your username or registered email. "
            "If it matches an account, we will send a "
            "secure recovery link."
        ),
        form_content,
        message,
    )


@router.post("/forgot-password")
def forgot_password_request(
    request: Request,
    identity: str = Form(...),
    csrf: str = Form(...),
):
    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/forgot-password?"
            "message=Your+session+expired.+Please+try+again.",
            status_code=303,
        )

    identity = identity.strip().lower()
    now = utc_now()

    with Session(engine) as db:
        user = (
            db.query(User)
            .filter(
                (User.username == identity)
                | (User.email == identity)
            )
            .first()
        )

        if user and user.is_active:
            last_sent = normalize_database_datetime(
                user.last_recovery_email_at
            )

            allowed = (
                last_sent is None
                or now - last_sent >= timedelta(seconds=60)
            )

            if allowed:
                raw_token = secrets.token_urlsafe(48)
                token_digest = hash_token(raw_token)
                expires_at = now + timedelta(minutes=30)

                db.execute(
                    text(
                        """
                        UPDATE account_recovery_tokens
                        SET used_at = :used_at
                        WHERE user_id = :user_id
                          AND purpose = 'credential-reset'
                          AND used_at IS NULL
                        """
                    ),
                    {
                        "used_at": now,
                        "user_id": user.id,
                    },
                )

                db.execute(
                    text(
                        """
                        INSERT INTO account_recovery_tokens (
                            user_id,
                            token_hash,
                            purpose,
                            expires_at,
                            created_at
                        )
                        VALUES (
                            :user_id,
                            :token_hash,
                            'credential-reset',
                            :expires_at,
                            :created_at
                        )
                        """
                    ),
                    {
                        "user_id": user.id,
                        "token_hash": token_digest,
                        "expires_at": expires_at,
                        "created_at": now,
                    },
                )

                user.last_recovery_email_at = now
                db.commit()

                try:
                    send_password_reset(user, raw_token)
                except Exception:
                    db.execute(
                        text(
                            """
                            UPDATE account_recovery_tokens
                            SET used_at = :used_at
                            WHERE token_hash = :token_hash
                            """
                        ),
                        {
                            "used_at": now,
                            "token_hash": token_digest,
                        },
                    )
                    db.commit()

    return RedirectResponse(
        "/forgot-password?"
        "message="
        + quote(GENERIC_RECOVERY_MESSAGE),
        status_code=303,
    )


@router.get("/forgot-username")
def forgot_username_page(
    request: Request,
    message: str = "",
):
    token = csrf_token(request)

    form_content = f"""
<form method="post"
      action="/forgot-username"
      class="recovery-form">

    <input type="hidden"
           name="csrf"
           value="{esc(token)}">

    <label>
        Registered email address
        <input type="email"
               name="email"
               required
               maxlength="320"
               autocomplete="email">
    </label>

    <button class="primary-button full"
            type="submit">
        Send username reminder
    </button>
</form>
"""

    return recovery_layout(
        request,
        "Username recovery",
        "Forgot your username?",
        (
            "Enter your registered email. If it matches "
            "an account, the username will be sent there."
        ),
        form_content,
        message,
    )


@router.post("/forgot-username")
def forgot_username_request(
    request: Request,
    email: str = Form(...),
    csrf: str = Form(...),
):
    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/forgot-username?"
            "message=Your+session+expired.+Please+try+again.",
            status_code=303,
        )

    email = email.strip().lower()
    now = utc_now()

    with Session(engine) as db:
        user = (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

        if user and user.is_active:
            last_sent = normalize_database_datetime(
                user.last_recovery_email_at
            )

            allowed = (
                last_sent is None
                or now - last_sent >= timedelta(seconds=60)
            )

            if allowed:
                user.last_recovery_email_at = now
                db.commit()

                try:
                    send_username_recovery(user)
                except Exception:
                    pass

    return RedirectResponse(
        "/forgot-username?"
        "message="
        + quote(GENERIC_RECOVERY_MESSAGE),
        status_code=303,
    )


def get_valid_reset_record(
    raw_token: str,
):
    if not raw_token or len(raw_token) > 256:
        return None

    token_digest = hash_token(raw_token)
    now = utc_now()

    with engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        id,
                        user_id,
                        expires_at,
                        used_at
                    FROM account_recovery_tokens
                    WHERE token_hash = :token_hash
                      AND purpose = 'credential-reset'
                    LIMIT 1
                    """
                ),
                {"token_hash": token_digest},
            )
            .mappings()
            .first()
        )

    if not row:
        return None

    expires_at = normalize_database_datetime(
        row["expires_at"]
    )

    if (
        row["used_at"] is not None
        or expires_at is None
        or expires_at <= now
    ):
        return None

    return row


@router.get("/reset-credential")
def reset_credential_page(
    request: Request,
    token: str = "",
    message: str = "",
):
    record = get_valid_reset_record(token)

    if not record:
        content = """
<section class="simple-card">
    <div class="big-icon">⌛</div>
    <h1>Recovery link unavailable</h1>
    <p>
        This recovery link is invalid, expired or has already
        been used.
    </p>
    <a class="primary-button"
       href="/forgot-password">
        Request a new recovery link
    </a>
</section>
"""
        return layout(
            "Recovery link unavailable",
            content,
            request,
        )

    csrf = csrf_token(request)

    form_content = f"""
<form method="post"
      action="/reset-credential"
      class="recovery-form">

    <input type="hidden"
           name="csrf"
           value="{esc(csrf)}">

    <input type="hidden"
           name="token"
           value="{esc(token)}">

    <fieldset class="credential-choice">
        <legend>Choose your new sign-in method</legend>

        <label class="credential-option">
            <input type="radio"
                   name="credential_type"
                   value="password"
                   checked>
            <span>
                <strong>New password</strong>
                <small>Minimum 12 characters</small>
            </span>
        </label>

        <label class="credential-option">
            <input type="radio"
                   name="credential_type"
                   value="passcode">
            <span>
                <strong>New passcode</strong>
                <small>Exactly 6 digits</small>
            </span>
        </label>
    </fieldset>

    <div class="credential-fields password-fields">
        <label>
            New password
            <input type="password"
                   name="password"
                   minlength="12"
                   maxlength="128"
                   autocomplete="new-password">
        </label>

        <label>
            Confirm new password
            <input type="password"
                   name="confirm_password"
                   minlength="12"
                   maxlength="128"
                   autocomplete="new-password">
        </label>
    </div>

    <div class="credential-fields passcode-fields">
        <label>
            New 6-digit passcode
            <input type="password"
                   name="passcode"
                   inputmode="numeric"
                   pattern="[0-9]{{6}}"
                   minlength="6"
                   maxlength="6"
                   autocomplete="new-password">
        </label>

        <label>
            Confirm passcode
            <input type="password"
                   name="confirm_passcode"
                   inputmode="numeric"
                   pattern="[0-9]{{6}}"
                   minlength="6"
                   maxlength="6"
                   autocomplete="new-password">
        </label>
    </div>

    <button class="primary-button full"
            type="submit">
        Save new secure credential
    </button>
</form>
"""

    return recovery_layout(
        request,
        "Reset account credential",
        "Choose a new credential",
        (
            "You may create a strong password or a "
            "6-digit passcode."
        ),
        form_content,
        message,
    )


@router.post("/reset-credential")
def reset_credential(
    request: Request,
    token: str = Form(...),
    credential_type: str = Form("password"),
    password: str = Form(""),
    confirm_password: str = Form(""),
    passcode: str = Form(""),
    confirm_passcode: str = Form(""),
    csrf: str = Form(...),
):
    if not csrf_valid(request, csrf):
        return RedirectResponse(
            "/reset-credential?"
            f"token={quote(token)}&"
            "message=Your+session+expired.+Please+try+again.",
            status_code=303,
        )

    record = get_valid_reset_record(token)

    if not record:
        return RedirectResponse(
            "/forgot-password?"
            "message=Recovery+link+expired.+Request+a+new+one.",
            status_code=303,
        )

    credential_type = credential_type.strip().lower()
    password_digest = None
    passcode_digest = None

    if credential_type == "password":
        if len(password) < 12:
            return RedirectResponse(
                "/reset-credential?"
                f"token={quote(token)}&"
                "message=Password+must+have+at+least+12+characters.",
                status_code=303,
            )

        if password != confirm_password:
            return RedirectResponse(
                "/reset-credential?"
                f"token={quote(token)}&"
                "message=Passwords+do+not+match.",
                status_code=303,
            )

        password_digest = password_hash.hash(password)

    elif credential_type == "passcode":
        if (
            len(passcode) != 6
            or not passcode.isdigit()
        ):
            return RedirectResponse(
                "/reset-credential?"
                f"token={quote(token)}&"
                "message=Passcode+must+contain+exactly+6+digits.",
                status_code=303,
            )

        if passcode != confirm_passcode:
            return RedirectResponse(
                "/reset-credential?"
                f"token={quote(token)}&"
                "message=Passcodes+do+not+match.",
                status_code=303,
            )

        if passcode in WEAK_PASSCODES:
            return RedirectResponse(
                "/reset-credential?"
                f"token={quote(token)}&"
                "message=Choose+a+less+predictable+passcode.",
                status_code=303,
            )

        passcode_digest = password_hash.hash(passcode)
        password_digest = password_hash.hash(
            secrets.token_urlsafe(48)
        )

    else:
        return RedirectResponse(
            "/reset-credential?"
            f"token={quote(token)}&"
            "message=Choose+password+or+passcode.",
            status_code=303,
        )

    now = utc_now()
    token_digest = hash_token(token)

    with Session(engine) as db:
        user = db.get(User, int(record["user_id"]))

        if not user or not user.is_active:
            return RedirectResponse(
                "/forgot-password?"
                "message=Recovery+link+is+unavailable.",
                status_code=303,
            )

        update_result = db.execute(
            text(
                """
                UPDATE account_recovery_tokens
                SET used_at = :used_at
                WHERE token_hash = :token_hash
                  AND used_at IS NULL
                  AND expires_at > :now
                """
            ),
            {
                "used_at": now,
                "token_hash": token_digest,
                "now": now,
            },
        )

        if update_result.rowcount != 1:
            db.rollback()

            return RedirectResponse(
                "/forgot-password?"
                "message=Recovery+link+expired+or+already+used.",
                status_code=303,
            )

        user.password_digest = password_digest
        user.passcode_digest = passcode_digest
        user.credential_type = credential_type
        user.failed_login_attempts = 0
        user.locked_until = None
        user.auth_version = (user.auth_version or 1) + 1

        db.execute(
            text(
                """
                UPDATE account_recovery_tokens
                SET used_at = :used_at
                WHERE user_id = :user_id
                  AND used_at IS NULL
                """
            ),
            {
                "used_at": now,
                "user_id": user.id,
            },
        )

        db.commit()

    request.session.clear()

    return RedirectResponse(
        "/login?"
        "message=Credential+updated.+Sign+in+with+your+new+credential.",
        status_code=303,
    )
