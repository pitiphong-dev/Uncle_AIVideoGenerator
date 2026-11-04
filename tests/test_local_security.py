import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ.pop('OPENROUTER_API_KEY', None)
os.environ['UNCLE_LOCAL_PASSWORD'] = 'test-only-password-not-a-real-secret'
import base64
import app as target


class LocalSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_store = target.KEY_STORE
        target.KEY_STORE = Path(self.tmp.name) / 'api_keys.json'
        self.client = target.app.test_client()
        self.client.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'uncle:test-only-password-not-a-real-secret').decode()

    def test_missing_password_is_unauthorized(self):
        c = target.app.test_client()
        r = c.get('/api/episodes', headers={'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 401)

    def test_wrong_password_is_unauthorized(self):
        c = target.app.test_client()
        c.environ_base['HTTP_AUTHORIZATION'] = 'Basic ' + base64.b64encode(b'uncle:wrong').decode()
        r = c.get('/api/episodes', headers={'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 401)

    def test_missing_server_password_fails_closed(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {'UNCLE_LOCAL_PASSWORD': ''}):
            r = self.client.get('/api/episodes', headers={'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 503)

    def tearDown(self):
        target.KEY_STORE = self.old_store
        self.tmp.cleanup()

    def test_mutating_requests_require_non_simple_header(self):
        r = self.client.post('/api/settings/api-keys', data=json.dumps({'name':'test','key':'fake'}),
                             content_type='text/plain', headers={'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(target.KEY_STORE.exists())

    def test_templates_never_load_remote_scripts(self):
        import re
        for path in (Path(target.ROOT) / 'templates').glob('*.html'):
            with self.subTest(template=path.name):
                self.assertNotRegex(path.read_text(encoding='utf-8'), r'<script\b[^>]*\bsrc=["\']https?://')

    def test_security_response_headers(self):
        r = self.client.get('/api/episodes', headers={'Host':'127.0.0.1:5432'})
        self.assertEqual(r.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(r.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertIn('no-store', r.headers.get('Cache-Control', ''))
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("connect-src 'self'", csp)

    def test_cross_origin_simple_post_cannot_add_key(self):
        r = self.client.post('/api/settings/api-keys', data=json.dumps({'name':'test','key':'fake'}),
                             content_type='text/plain', headers={'Origin':'https://attacker.example', 'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(target.KEY_STORE.exists())

    def test_dns_rebinding_host_is_denied(self):
        r = self.client.get('/api/episodes', headers={'Host':'attacker.example:5432'})
        self.assertEqual(r.status_code, 403)

    def test_same_origin_browser_post_works(self):
        r = self.client.put('/api/settings/model-preferences', json={'preferences':{}},
                             headers={'Origin':'http://127.0.0.1:5432', 'Host':'127.0.0.1:5432', 'X-Requested-With':'UncleLocal'})
        self.assertEqual(r.status_code, 200)

    def test_originless_local_script_post_works(self):
        r = self.client.put('/api/settings/model-preferences', json={'preferences':{}},
                             headers={'Host':'127.0.0.1:5432', 'X-Requested-With':'UncleLocal'})
        self.assertEqual(r.status_code, 200)

    def test_new_keys_cannot_be_written_to_plaintext_store(self):
        r = self.client.post('/api/settings/api-keys', json={'name':'test','key':'fake'},
                             headers={'Host':'127.0.0.1:5432', 'X-Requested-With':'UncleLocal'})
        self.assertEqual(r.status_code, 410)
        self.assertFalse(target.KEY_STORE.exists())

    def test_legacy_plaintext_keys_not_used(self):
        target.KEY_STORE.write_text(json.dumps({'active_id':'old','keys':[{'id':'old','value':'fake-secret'}]}))
        self.assertEqual(target.active_api_key(), '')

    def test_save_rejects_plaintext_keys(self):
        with self.assertRaises(ValueError):
            target.save_key_config({'keys': [{'value': 'fake'}]})
        self.assertFalse(target.KEY_STORE.exists())

    def test_key_temp_file_is_private_before_replace(self):
        from unittest.mock import patch
        original = Path.replace
        modes = []
        def check_mode(path, destination):
            modes.append(path.stat().st_mode & 0o777)
            return original(path, destination)
        old_umask = os.umask(0o022)
        try:
            with patch.object(Path, 'replace', check_mode):
                target.save_key_config({'keys': [], 'model_preferences': {}})
        finally:
            os.umask(old_umask)
        self.assertEqual(modes, [0o600])

    def test_cross_origin_cannot_trigger_paid_generation(self):
        from unittest.mock import patch
        with patch.object(target, 'api') as paid_api:
            r = self.client.post('/api/generate', data='{}', content_type='text/plain',
                                 headers={'Origin':'https://attacker.example', 'Host':'127.0.0.1:5432'})
        self.assertEqual(r.status_code, 403)
        paid_api.assert_not_called()

    def test_cross_site_fetch_metadata_blocked_without_origin(self):
        r = self.client.post('/api/settings/api-keys', json={'name':'test','key':'fake'},
                             headers={'Host':'127.0.0.1:5432', 'Sec-Fetch-Site':'cross-site'})
        self.assertEqual(r.status_code, 403)


if __name__ == '__main__':
    unittest.main()
