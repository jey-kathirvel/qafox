from unittest import TestCase

from app.smart_data.auth_handshake import (
    extract_access_token,
    extract_csrf_header,
    handshake_request,
)


class AuthHandshakeTests(TestCase):
    def test_oauth2_client_credentials_form_body(self):
        request = handshake_request(
            "oauth2",
            {
                "token_url": "https://auth.example.com/oauth/token",
                "client_id": "client-a",
                "client_secret": "super-secret",
            },
        )
        self.assertEqual(request["method"], "POST")
        self.assertIn("grant_type=client_credentials", request["body"].decode("utf-8"))
        self.assertNotIn("Cookie", request["headers"])

    def test_login_json_and_token_extract(self):
        request = handshake_request(
            "login_json",
            {
                "login_url": "https://api.example.com/login",
                "username": "owner",
                "password": "pw",
            },
        )
        self.assertEqual(request["headers"]["Content-Type"], "application/json")
        token = extract_access_token('{"accessToken":"abc","csrf_token":"csrf-1"}')
        self.assertEqual(token, "abc")
        self.assertEqual(extract_csrf_header('{"csrf_token":"csrf-1"}'), ("X-CSRF-Token", "csrf-1"))

    def test_mfa_stops_automation(self):
        with self.assertRaises(ValueError) as raised:
            extract_access_token('{"error":"MFA required"}')
        self.assertIn("MFA", str(raised.exception))

    def test_bearer_needs_no_handshake(self):
        self.assertIsNone(handshake_request("bearer", {"token": "x"}))
