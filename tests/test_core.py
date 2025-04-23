import unittest
from phishiurl.cli import PhishingDetector

class TestPhishingDetection(unittest.TestCase):
    def setUp(self):
        self.detector = PhishingDetector()

    def test_phishing_url(self):
        result = self.detector.detect("https://faceb00k.com/login")
        self.assertTrue(result['is_phishing'])

    def test_safe_url(self):
        result = self.detector.detect("https://google.com")
        self.assertFalse(result['is_phishing'])

if __name__ == '__main__':
    unittest.main()