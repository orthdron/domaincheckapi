import unittest
from app import create_app
from app.core.domain import check_whois, check_dns
import json
import os

class TestDomainChecker(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Ensure rate limiting is disabled for tests
        os.environ['ENABLE_RATE_LIMITS'] = 'false'
        self.app = create_app()
        self.client = self.app.test_client()
        self.app.testing = True

    def tearDown(self):
        """Clean up after tests"""
        # Clean up environment variables
        if 'ENABLE_RATE_LIMITS' in os.environ:
            del os.environ['ENABLE_RATE_LIMITS']

    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'ok')

    def test_metrics(self):
        """Test metrics endpoint"""
        response = self.client.get('/metrics')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('cache_stats', data)
        self.assertIn('uptime', data)
        self.assertIn('rate_limits', data)

    def test_known_domains(self):
        """Test checking known domains (google.com and facebook.com)"""
        # Test google.com
        response = self.client.get('/?domain=google')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'taken')
        self.assertEqual(data['domain'], 'google.com')
        self.assertEqual(data['whois']['status'], 'taken')
        self.assertEqual(data['dns']['status'], 'taken')

        # Test facebook.com
        response = self.client.get('/?domain=facebook')
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
            response = self.client.get(f'/?domain={domain}')
            self.assertEqual(response.status_code, 400,
                           f"Expected 400 for domain: {domain}")
            data = json.loads(response.data)
            self.assertIn('error', data)
            self.assertIn('message', data)

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
            response = self.client.get(f'/?domain=example&tld={tld}')
            self.assertEqual(response.status_code, 400,
                           f"Expected 400 for TLD: {tld}")
            data = json.loads(response.data)
            self.assertIn('error', data)
            self.assertIn('message', data)

    def test_missing_domain(self):
        """Test missing domain parameter"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('message', data)

    def test_bulk_check(self):
        """Test bulk domain checking"""
        data = {
            "domains": ["google", "facebook"],
            "tld": "com"
        }
        response = self.client.post('/bulk', 
                                  json=data,
                                  content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('results', data)
        
        # Check results
        results = data['results']
        self.assertEqual(len(results), 2)
        
        # Check google.com result
        google_result = next(r for r in results if r['domain'] == 'google.com')
        self.assertEqual(google_result['status'], 'taken')
        self.assertEqual(google_result['whois']['status'], 'taken')
        self.assertEqual(google_result['dns']['status'], 'taken')
        
        # Check facebook.com result
        facebook_result = next(r for r in results if r['domain'] == 'facebook.com')
        self.assertEqual(facebook_result['status'], 'taken')
        self.assertEqual(facebook_result['whois']['status'], 'taken')
        self.assertEqual(facebook_result['dns']['status'], 'taken')

    def test_custom_tld(self):
        """Test custom TLD parameter"""
        response = self.client.get('/?domain=google&tld=org')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['domain'], 'google.org')
        self.assertEqual(data['tld'], 'org')

    def test_bulk_check_with_invalid_domains(self):
        """Test bulk domain checking with invalid entries"""
        data = {
            "domains": ["google", "inv@lid", "-invalid", ""],
            "tld": "com"
        }
        response = self.client.post('/bulk',
                                  json=data,
                                  content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data['results'], list)
        
        # Should have one successful result (google.com) and three errors
        valid_results = [r for r in data['results'] if r['status'] == 'taken']
        error_results = [r for r in data['results'] if r['status'] == 'error']
        
        self.assertEqual(len(valid_results), 1)
        self.assertEqual(len(error_results), 3)
        
        # Check the successful result
        google_result = next(r for r in data['results'] if r['domain'] == 'google.com')
        self.assertEqual(google_result['status'], 'taken')

    def test_bulk_check_invalid_request(self):
        """Test bulk check with invalid request format"""
        # Test with missing domains field
        response = self.client.post('/bulk',
                                  json={},
                                  content_type='application/json')
        self.assertEqual(response.status_code, 400)
        
        # Test with domains not being a list
        response = self.client.post('/bulk',
                                  json={"domains": "not a list"},
                                  content_type='application/json')
        self.assertEqual(response.status_code, 400)
        
        # Test with too many domains
        response = self.client.post('/bulk',
                                  json={"domains": ["test"] * 11},
                                  content_type='application/json')
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main() 