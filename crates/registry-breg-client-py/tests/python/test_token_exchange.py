"""Language-level proof of the shared OAuth exchange contract using synthetic credentials."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import PrivateKeyJwt, BaseRegistryClientError


class TokenExchangeTests(unittest.TestCase):
    def test_exchange_is_uncached_and_preserves_service_cache(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers['content-length'])).decode())
                requests.append(form)
                body = json.dumps({'access_token':form.get('subject_token', ['service-token'])[0],
                    'token_type':'Bearer', 'expires_in':300, 'scope':form.get('scope', [''])[0],
                    'issued_token_type':'urn:ietf:params:oauth:token-type:access_token'}).encode()
                self.send_response(200)
                for name, value in [('content-type','application/json'), ('cache-control','no-store'),
                                    ('pragma','no-cache'), ('content-length',str(len(body)))]:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = {'token_endpoint':f'http://127.0.0.1:{server.server_port}/token',
                'client_id':'test-client', 'client_key':json.loads(Path(__file__).with_name('exchange-test-key.json').read_text()),
                'resource':'urn:test:resource', 'scopes':['records:get']}
            provider = PrivateKeyJwt(config)
            self.assertEqual(provider.bearer_token(), 'service-token')
            self.assertEqual(provider.exchange('first-subject'), 'first-subject')
            self.assertEqual(provider.exchange('second-subject'), 'second-subject')
            self.assertEqual(provider.bearer_token(), 'service-token')
            self.assertEqual(len(requests), 3)
            # The neutral auth facade aliases this canonical provider. Separate
            # instances request and cache only their configured resource token.
            casework = PrivateKeyJwt({**config, 'resource':'urn:test:casework', 'scopes':['casework:request']})
            messaging = PrivateKeyJwt({**config, 'resource':'urn:test:messaging', 'scopes':['messaging:send']})
            self.assertEqual(casework.bearer_token(), 'service-token')
            self.assertEqual(messaging.bearer_token(), 'service-token')
            self.assertEqual(casework.bearer_token(), 'service-token')
            self.assertEqual(len(requests), 5)
            self.assertEqual(requests[3]['resource'], ['urn:test:casework'])
            self.assertEqual(requests[3]['scope'], ['casework:request'])
            self.assertEqual(requests[4]['resource'], ['urn:test:messaging'])
            self.assertEqual(requests[4]['scope'], ['messaging:send'])
            for form in requests[1:3]:
                self.assertEqual(form['grant_type'], ['urn:ietf:params:oauth:grant-type:token-exchange'])
                self.assertEqual(form['subject_token_type'], ['urn:ietf:params:oauth:token-type:jwt'])
                self.assertEqual(form['resource'], ['urn:test:resource'])
                self.assertEqual(form['scope'], ['records:get'])
                self.assertNotIn('client_secret', form)
            self.assertNotEqual(requests[1]['client_assertion'], requests[2]['client_assertion'])
            with self.assertRaises(BaseRegistryClientError): provider.exchange('bad\nsubject')
            with self.assertRaises(BaseRegistryClientError): PrivateKeyJwt({**config, 'resource':None}).exchange('subject')
            self.assertEqual(len(requests), 5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
