import unittest
from script import app, check_whois, check_dns
import json

class TestDomainChecker(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

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
        self.assertIn('google.com', data)
        self.assertIn('facebook.com', data)
        self.assertEqual(data['google.com']['status'], 'taken')
        self.assertEqual(data['facebook.com']['status'], 'taken')

    def test_custom_tld(self):
        """Test custom TLD parameter"""
        response = self.app.get('/?domain=google&tld=org')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['domain'], 'google.org')
        self.assertEqual(data['tld'], 'org')

if __name__ == '__main__':
    unittest.main() 