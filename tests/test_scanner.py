import unittest

from core.scanner import Detection, ScanResult, build_recon_plan, build_service_summary, run_fingerprints
from fingerprints.signatures import SIGNATURES


class ScannerSummaryTests(unittest.TestCase):
    def test_build_service_summary_lists_services_with_versions_and_confidence(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=120.5,
            technologies=[
                Detection(name="Nginx", category="Web Server", version="1.26.0", confidence="high", evidence="Server: nginx"),
                Detection(name="WordPress", category="CMS", version="6.5", confidence="medium", evidence="Meta generator"),
            ],
        )

        summary = build_service_summary(result)

        self.assertEqual(len(summary), 2)
        self.assertEqual(summary[0]["name"], "Nginx")
        self.assertEqual(summary[0]["version"], "1.26.0")
        self.assertEqual(summary[0]["confidence"], "high")
        self.assertIn("WordPress", [item["name"] for item in summary])

    def test_run_fingerprints_detects_services_and_versions(self):
        headers = {"Server": "nginx/1.26.1", "X-Powered-By": "PHP/8.1.2"}
        body = '<meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/themes/twentytwentyfour/style.css"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Nginx", names)
        self.assertIn("PHP", names)
        self.assertIn("WordPress", names)
        self.assertEqual(next(d.version for d in detections if d.name == "Nginx"), "1.26.1")

    def test_run_fingerprints_detects_deeper_service_signatures(self):
        headers = {"Server": "Apache/2.4.49"}
        body = '<meta name="generator" content="Jenkins 2.440"><script src="/static/jenkins.js"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Apache", names)
        self.assertIn("Jenkins", names)

    def test_run_fingerprints_detects_services_from_url_path(self):
        headers = {}
        body = ""

        detections = run_fingerprints(headers, {}, body, url="https://target.example/phpmyadmin/index.php")
        names = {d.name for d in detections}

        self.assertIn("phpMyAdmin", names)

    def test_run_fingerprints_detects_wordpress_plugin_signatures(self):
        headers = {}
        body = '<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Elementor", names)

    def test_run_fingerprints_detects_payment_gateway_signatures(self):
        headers = {}
        body = '<script src="https://js.stripe.com/v3"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Stripe", names)

    def test_run_fingerprints_detects_inline_source_code_signatures(self):
        headers = {}
        body = '<script>Sentry.init({dsn:"https://example@sentry.io/123"});</script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Sentry", names)

    def test_run_fingerprints_extracts_versions_from_html_and_scripts(self):
        headers = {}
        body = '<meta name="generator" content="WordPress 6.5.1"><script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?v=3.23.0"></script>'

        detections = run_fingerprints(headers, {}, body)
        versions = {d.name: d.version for d in detections if d.version}

        self.assertEqual(versions.get("WordPress"), "6.5.1")
        self.assertEqual(versions.get("Elementor"), "3.23.0")

    def test_run_fingerprints_detects_ecommerce_and_marketing_signatures(self):
        headers = {}
        body = '<script src="https://js.stripe.com/v3"></script><script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script><script src="https://js.hs-scripts.com/123456.js"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Stripe", names)
        self.assertIn("Google Analytics", names)
        self.assertIn("HubSpot", names)

    def test_signature_catalog_contains_large_cloud_and_ics_catalog(self):
        self.assertGreaterEqual(len(SIGNATURES), 5000)
        self.assertIn("OpenStack Horizon", SIGNATURES)
        self.assertIn("ScadaBR", SIGNATURES)
        self.assertIn("Cloudflare Dashboard", SIGNATURES)
        self.assertIn("Akamai Control Center", SIGNATURES)

    def test_run_fingerprints_detects_broader_service_families(self):
        headers = {}
        body = '<html><body><h1>OpenStack Horizon</h1><script src="/static/novnc.js"></script></body></html>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("OpenStack Horizon", names)
        self.assertIn("OpenStack Nova", names)

    def test_build_recon_plan_supports_requested_modules(self):
        plan = build_recon_plan(["dns", "ssl", "mail", "subdomains", "whois", "headers", "tech"])

        self.assertTrue(plan["dns"])
        self.assertTrue(plan["ssl"])
        self.assertTrue(plan["mail"])
        self.assertTrue(plan["subdomains"])
        self.assertTrue(plan["whois"])
        self.assertTrue(plan["headers"])
        self.assertTrue(plan["tech"])

    def test_build_recon_plan_supports_full_recon_preset(self):
        plan = build_recon_plan(["full-recon"])

        self.assertTrue(plan["dns"])
        self.assertTrue(plan["ssl"])
        self.assertTrue(plan["whois"])
        self.assertTrue(plan["subdomains"])
        self.assertTrue(plan["mail"])
        self.assertTrue(plan["tech"])
        self.assertTrue(plan["ports"])
        self.assertTrue(plan["extra"])

    def test_build_recon_plan_supports_fast_preset(self):
        plan = build_recon_plan(["fast"])

        self.assertTrue(plan["headers"])
        self.assertTrue(plan["tech"])
        self.assertFalse(plan["dns"])
        self.assertFalse(plan["ssl"])
        self.assertFalse(plan["whois"])
        self.assertFalse(plan["subdomains"])
        self.assertFalse(plan["mail"])
        self.assertFalse(plan["ports"])
        self.assertFalse(plan["extra"])


if __name__ == "__main__":
    unittest.main()
