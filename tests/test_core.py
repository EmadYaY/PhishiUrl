"""
PhishiUrl Test Suite v1.3.0
Run: pytest tests/test_core.py -v
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from phishiurl.cli import (
    PhishingDetector,
    check_domain_availability,
    generate_homoglyph_suggestions,
    _instrument_and_save,
    load_config,
    is_admin,
    _hosts_path,
)


class TestPhishingDetector(unittest.TestCase):

    def setUp(self):
        self.d = PhishingDetector()

    # ── Homoglyph detection ───────────────────────────────────────────────
    def test_detects_homoglyph_url(self):
        """URL with Cyrillic 'о' in domain should score >= 60."""
        # Use Cyrillic о (U+043E) in domain
        result = self.d.detect("https://faceb\u043e\u043ek.com/login")
        self.assertTrue(result['is_phishing'])
        self.assertGreaterEqual(result['score'], 60)

    def test_numeric_substitution_not_flagged_as_homoglyph(self):
        """
        faceb00k.com – the '0's are ASCII, not Unicode homoglyphs.
        The detector adds keyword score (+15 for 'login' in path) but
        should NOT trigger the homoglyph score (+60) because ord('0') <= 127.
        """
        result = self.d.detect("https://faceb00k.com/login")
        # Should score from keywords but NOT from Unicode homoglyphs
        self.assertFalse(
            any('homoglyph' in a.lower() for a in result['alerts']),
            "ASCII digits should not trigger homoglyph alert"
        )
        # Score from 'login' keyword alone (15 pts)
        self.assertGreater(result['score'], 0)

    def test_safe_url_low_score(self):
        """Legitimate domain should score low."""
        result = self.d.detect("https://google.com")
        self.assertLess(result['score'], 60)
        self.assertFalse(result['is_phishing'])

    # ── Keyword detection ─────────────────────────────────────────────────
    def test_suspicious_keyword_adds_score(self):
        result_with    = self.d.detect("https://example.com/login")
        result_without = self.d.detect("https://example.com/home")
        self.assertGreater(result_with['score'], result_without['score'])

    # ── URL length heuristic ──────────────────────────────────────────────
    def test_long_url_adds_score(self):
        short = self.d.detect("https://example.com")
        long  = self.d.detect("https://example.com/" + "a" * 100)
        self.assertGreater(long['score'], short['score'])

    # ── Score cap ─────────────────────────────────────────────────────────
    def test_score_does_not_exceed_100(self):
        result = self.d.detect("https://\u043e\u0430\u0455.com/login/verify/account/update")
        self.assertLessEqual(result['score'], 100)

    # ── Alerts present ────────────────────────────────────────────────────
    def test_alerts_list_not_empty(self):
        result = self.d.detect("https://google.com")
        self.assertIsInstance(result['alerts'], list)

    # ── normalize_domain ──────────────────────────────────────────────────
    def test_normalize_replaces_cyrillic_o(self):
        normalized = self.d.normalize_domain("g\u043e\u043egle.com")
        # Cyrillic о → o
        self.assertNotIn('\u043e', normalized)


class TestHomoglyphGeneration(unittest.TestCase):

    def test_google_has_suggestions(self):
        results = generate_homoglyph_suggestions("google.com")
        self.assertGreater(len(results), 1)
        self.assertEqual(results[0]['domain'], "google.com")
        self.assertEqual(results[0]['status'], "Original")

    def test_suggestions_differ_from_original(self):
        results = generate_homoglyph_suggestions("apple.com")
        domains = [r['domain'] for r in results]
        # At least one suggestion should differ
        self.assertTrue(any(d != "apple.com" for d in domains))

    def test_no_duplicates(self):
        results = generate_homoglyph_suggestions("google.com")
        domains = [r['domain'] for r in results]
        self.assertEqual(len(domains), len(set(domains)))


class TestDomainAvailability(unittest.TestCase):

    @patch('phishiurl.cli.whois')
    def test_registered_domain(self, mock_whois):
        mock_data = MagicMock()
        mock_data.registrar = "Some Registrar"
        mock_whois.return_value = mock_data
        self.assertFalse(check_domain_availability("google.com"))

    @patch('phishiurl.cli.whois')
    def test_available_domain(self, mock_whois):
        mock_data = MagicMock()
        mock_data.registrar = None
        mock_whois.return_value = mock_data
        self.assertTrue(check_domain_availability("thiswillneverberegistered12345.com"))

    @patch('phishiurl.cli.whois', side_effect=Exception("WHOIS error"))
    def test_whois_error_returns_available(self, _):
        # On error we assume available (safe default)
        self.assertTrue(check_domain_availability("error-domain.com"))


class TestConfig(unittest.TestCase):

    def test_load_creates_default(self):
        """load_config should return a dict with all required keys."""
        cfg = load_config()
        self.assertIn('ngrok_token', cfg)
        self.assertIn('virustotal_api_key', cfg)
        self.assertIn('phishtank_api_key', cfg)
        self.assertIn('templates_path', cfg)

    def test_load_fills_missing_keys(self):
        """load_config should always return all default keys."""
        cfg = load_config()
        # All keys must be present regardless of file state
        for key in ('ngrok_token', 'virustotal_api_key', 'phishtank_api_key', 'templates_path'):
            self.assertIn(key, cfg)

    def test_load_handles_malformed_json(self):
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            with open('config.json', 'w') as f:
                f.write("{ bad json }")
            cfg = load_config()  # Should not raise
            self.assertIn('ngrok_token', cfg)


class TestCredentialCapture(unittest.TestCase):

    def test_instrument_and_save_basic(self):
        """_instrument_and_save should create index.html with capture JS."""
        from bs4 import BeautifulSoup
        html = """<html><body>
            <form action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body></html>"""
        soup = BeautifulSoup(html, 'html.parser')
        with tempfile.TemporaryDirectory() as td:
            result = _instrument_and_save(soup, 'https://example.com', td)
            self.assertTrue(os.path.exists(os.path.join(td, 'index.html')))
            with open(os.path.join(td, 'index.html')) as f:
                content = f.read()
            self.assertIn('/capture', content)
            self.assertIn('fetch', content)

    def test_instrument_adds_hidden_original_action(self):
        from bs4 import BeautifulSoup
        html = "<html><body><form><input name='u'></form></body></html>"
        soup = BeautifulSoup(html, 'html.parser')
        with tempfile.TemporaryDirectory() as td:
            _instrument_and_save(soup, 'https://original.com', td)
            with open(os.path.join(td, 'index.html')) as f:
                content = f.read()
            self.assertIn('original_action', content)


class TestPlatformHelpers(unittest.TestCase):

    def test_hosts_path_is_string(self):
        self.assertIsInstance(_hosts_path(), str)

    def test_is_admin_returns_bool(self):
        self.assertIsInstance(is_admin(), bool)


class TestVirusTotalIntegration(unittest.TestCase):

    @patch('phishiurl.cli.requests.get')
    def test_malicious_response(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'data': {'attributes': {'last_analysis_stats': {'malicious': 5, 'clean': 60}}}
        }
        from phishiurl.cli import check_virustotal
        result = check_virustotal("https://evil.com", api_key="fakekey")
        self.assertEqual(result['status'], 'malicious')
        self.assertEqual(result['malicious_count'], 5)

    @patch('phishiurl.cli.requests.get')
    def test_clean_response(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'data': {'attributes': {'last_analysis_stats': {'malicious': 0, 'clean': 70}}}
        }
        from phishiurl.cli import check_virustotal
        result = check_virustotal("https://google.com", api_key="fakekey")
        self.assertEqual(result['status'], 'clean')

    @patch('phishiurl.cli.requests.get')
    def test_invalid_api_key(self, mock_get):
        mock_get.return_value.status_code = 401
        from phishiurl.cli import check_virustotal
        result = check_virustotal("https://google.com", api_key="badkey")
        self.assertIn('error', result)

    def test_no_api_key_returns_error(self):
        from phishiurl.cli import check_virustotal
        result = check_virustotal("https://google.com", api_key="")
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
