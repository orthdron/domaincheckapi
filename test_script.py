import unittest
from script import app, check_whois, check_dns
import json
import os

class TestDomainChecker(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Ensure rate limiting is disabled for tests
        os.environ['ENABLE_RATE_LIMITS'] = 'false'
        self.app = app.test_client()
        self.app.testing = True

    def tearDown(self):
        """Clean up after tests"""
        # Clean up environment variables
        if 'ENABLE_RATE_LIMITS' in os.environ:
            del os.environ['ENABLE_RATE_LIMITS']

    def test_health_check(self):
        """Test health check endpoint"""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')

    def test_metrics(self):
        """Test metrics endpoint"""
        response = self.app.get('/metrics')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('cache_stats', data)
        self.assertIn('uptime', data)

    def test_known_domains(self):
        """Test checking known domains (google.com and facebook.com)"""
        # Test google.com
        response = self.app.get('/?domain=google')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'taken')
        self.assertEqual(data['domain'], 'google.com')
        self.assertEqual(data['whois']['status'], 'taken')
        self.assertEqual(data['dns']['status'], 'taken')

        # Test facebook.com
        response = self.app.get('/?domain=facebook')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'taken')
        self.assertEqual(data['domain'], 'facebook.com')
        self.assertEqual(data['whois']['status'], 'taken')
        self.assertEqual(data['dns']['status'], 'taken')

    def test_invalid_domain(self):
        """Test invalid domain input"""
        invalid_domains = [
            'inv@lid',
            '-invalid',
            'invalid-',
            'inv--alid',
            'a' * 64,  # Too long
            '',  # Empty
            ' ',  # Just whitespace
            'domain.with.dots'
        ]
        
        for domain in invalid_domains:
            response = self.app.get(f'/?domain={domain}')
            self.assertEqual(response.status_code, 400,
                           f"Expected 400 for domain: {domain}")
            data = json.loads(response.data)
            self.assertIn('error', data)

    def test_invalid_tld(self):
        """Test invalid TLD input"""
        invalid_tlds = [
            '123',  # Numbers not allowed
            'a',    # Too short
            'com@', # Invalid characters
            '',     # Empty
            ' ',    # Just whitespace
            'com.', # Trailing dot
            'co.uk' # Compound TLD not supported
        ]
        
        for tld in invalid_tlds:
            response = self.app.get(f'/?domain=example&tld={tld}')
            self.assertEqual(response.status_code, 400,
                           f"Expected 400 for TLD: {tld}")
            data = json.loads(response.data)
        response = self.app.get('/?domain=inv@lid')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)

    def test_missing_domain(self):
        """Test missing domain parameter"""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)

    def test_bulk_check(self):
        """Test bulk domain checking"""
        domains = {
            "domains": [
                {"domain": "google", "tld": "com"},
                {"domain": "facebook", "tld": "com"}
            ]
        }
        response = self.app.post('/bulk', 
                               json=domains,
                               content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('results', data)
        self.assertIn('google.com', data['results'])
        self.assertIn('facebook.com', data['results'])
        self.assertEqual(data['results']['google.com']['status'], 'taken')
        self.assertEqual(data['results']['facebook.com']['status'], 'taken')

    def test_custom_tld(self):
        """Test custom TLD parameter"""
        response = self.app.get('/?domain=google&tld=org')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['domain'], 'google.org')
        self.assertEqual(data['tld'], 'org')

    def test_bulk_check_with_errors(self):
        """Test bulk domain checking with invalid entries"""
        domains = {
            "domains": [
                {"domain": "google", "tld": "com"},
                {"domain": "inv@lid", "tld": "com"},
                {"domain": "example", "tld": "123"},
                {"domain": "", "tld": "com"}
            ]
        }
        response = self.app.post('/bulk',
                               json=domains,
                               content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('results', data)
        self.assertIn('errors', data)
        self.assertIn('google.com', data['results'])
        self.assertEqual(len(data['errors']), 3)  # Should have 3 error messages

if __name__ == '__main__':
    unittest.main() 