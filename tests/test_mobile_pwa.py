from json import loads
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[1]


class MobilePwaShellTests(TestCase):
    def test_layout_includes_mobile_menu_and_pwa_tags(self):
        source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn('id="qafox-nav-toggle"', source)
        self.assertIn('id="qafox-site-nav"', source)
        self.assertIn('id="qafox-nav-close"', source)
        self.assertIn("data-pwa-install", source)
        self.assertIn("Install App", source)
        self.assertIn("id=\"qafox-pwa-hint\"", source)
        self.assertIn('rel="manifest"', source)
        self.assertIn("apple-mobile-web-app-capable", source)
        self.assertIn("viewport-fit=cover", source)
        self.assertIn('("/dashboard", "Dashboard")', source)
        self.assertIn('("/signup", "Create workspace")', source)

    def test_manifest_is_installable(self):
        manifest = loads(
            (ROOT / "static" / "manifest.webmanifest").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["display"], "standalone")
        self.assertIn("standalone", manifest["display_override"])
        self.assertTrue(any(icon["sizes"] == "192x192" for icon in manifest["icons"]))
        self.assertTrue(any(icon["sizes"] == "512x512" for icon in manifest["icons"]))
        self.assertEqual(manifest["start_url"], "/")

    def test_assets_include_drawer_menu_behavior(self):
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        worker = (ROOT / "static" / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn(".site-nav.is-open", css)
        self.assertIn("justify-content: flex-start", css)
        self.assertIn("@media (max-width: 860px)", css)
        self.assertIn("qafox-nav-toggle", js)
        self.assertIn("qafox-nav-close", js)
        self.assertIn("beforeinstallprompt", js)
        self.assertIn("data-pwa-install", js)
        self.assertIn("aria-expanded", js)
        self.assertIn("qafox-shell-v8", worker)
