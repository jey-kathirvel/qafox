"""Deterministic failure classification for UAT reports.

This is not an external model. It maps runner/assertion text to a short
root-cause label without sending payloads off-box.
"""

from __future__ import annotations


def classify_root_cause(*, status: str, assertion_summary: str = "", error_message: str = "") -> str:
    blob = f"{status} {assertion_summary} {error_message}".lower()
    rules = (
        ("private, loopback or reserved", "Blocked by SSRF/private-target controls."),
        ("local or internal targets", "Blocked by SSRF/private-target controls."),
        ("only public https", "Blocked: target must be public HTTPS."),
        ("stack trace", "Server leaked implementation details."),
        ("echoed a secret", "Response echoed a credential or secret."),
        ("exceeded the", "Response slower than the configured duration budget."),
        ("missing required response field", "Contract mismatch: documented JSON field missing."),
        ("type mismatch", "Contract mismatch: documented JSON field had the wrong type."),
        ("producer step failed", "Dependent step skipped because its producer failed."),
        ("dynamic placeholder was not supplied", "Runtime ID was not extracted from the producer."),
        ("unresolved", "Mandatory test data was not resolved."),
        ("mfa", "MFA/login challenge cannot be automated; use a vault token."),
        ("oauth token", "OAuth client-credentials handshake did not yield an access token."),
        ("redirect response was blocked", "Redirect was refused by the hardened runner."),
        ("integrity-failed", "Plan snapshot fingerprint did not match."),
        ("expected ", "HTTP status did not match the planned expectation."),
    )
    for needle, label in rules:
        if needle in blob:
            return label
    if status == "error":
        return "The request did not complete safely."
    if status == "skipped":
        return "The runner skipped this step under a safety gate."
    if status == "failed":
        return "The response did not satisfy the planned assertions."
    return ""
