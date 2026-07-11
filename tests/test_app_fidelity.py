'''
Fidelity tests: pybiss's REST surface must match the official BISS daemon
(as decompiled from biss-3.46) closely enough for portals to not notice.
'''

import json, sys, unittest
from unittest.mock import patch

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.app import app
from src.server import Request
# app.py imports ui_bridge as a bare module; use the same instance it sees
from ui_bridge import set_ui_provider
from tests.x509_helpers import build_cert, make_jws
from tests.mocks import ForbiddenUI
from src import jws


def post(path: str, body: dict = None):
    handler = app.routes[('POST', path)]
    return handler(Request('POST', path, {}, json.dumps(body or {}).encode('utf-8')))


def get(path: str):
    handler = app.routes[('GET', path)]
    return handler(Request('GET', path, {}, b''))


class TestRouteTable(unittest.TestCase):

    def test_all_biss_routes_registered(self):
        ''' Every endpoint of the official daemon exists with the right method '''

        expected_posts = [
            '/chainFound', '/close', '/delCert', '/delRSAPair', '/generatePfx',
            '/genRSAPair', '/genSPKAC', '/getInfo', '/getPfxKeyPair',
            '/getSerialNumber', '/getsigner', '/renew', '/setNewPUKNewPIN',
            '/setPIN', '/setPUK', '/sign', '/unblockPIN', '/v2/renew', '/writeCertSC',
        ]
        for path in expected_posts:
            self.assertIn(('POST', path), app.routes, f'missing POST {path}')
        for path in ('/version', '/status'):
            self.assertIn(('GET', path), app.routes, f'missing GET {path}')

    def test_get_serial_number_is_not_a_get_route(self):
        ''' The Java daemon only accepts POST here; a GET route would mask that '''

        self.assertNotIn(('GET', '/getSerialNumber'), app.routes)


class TestEnvelopes(unittest.TestCase):

    def test_status_returns_empty_json_string(self):
        ''' GET /status answers with the literal JSON string "" like the original '''

        self.assertEqual(get('/status'), '')
        self.assertEqual(json.dumps(get('/status')), '""')

    def test_version_shape_and_format(self):
        res = get('/version')
        for field in ('version', 'httpMethods', 'contentTypes', 'signatureTypes',
                      'selectorAvailable', 'hashAlgorithms'):
            self.assertIn(field, res)
        # Portals may version-gate; the value must mimic the Java "3.46" format
        self.assertRegex(res['version'], r'^\d+\.\d+$')

    def test_close_returns_bare_string_body(self):
        ''' /close answers with an unquoted string body despite the JSON content type '''

        res = post('/close')
        self.assertEqual(res, b'Signing service successfully closed!')

    def test_unimplemented_endpoints_return_biss_error_envelope(self):
        for path in ('/chainFound', '/genSPKAC', '/generatePfx',
                     '/getPfxKeyPair', '/setNewPUKNewPIN', '/v2/renew'):
            res = post(path)
            self.assertEqual(res['status'], 'error', path)
            self.assertEqual(res['reasonCode'], 501, path)
            self.assertIn('reasonText', res, path)


class TestJwsGating(unittest.TestCase):
    ''' PIN-family endpoints must reject requests lacking a valid jwsData '''

    def test_missing_jws_data_rejected(self):
        for path in ('/setPIN', '/setPUK', '/unblockPIN', '/getSerialNumber'):
            res = post(path, {})
            self.assertEqual(res['status'], 'error', path)
            self.assertEqual(res['reasonCode'], 403, path)

    def test_forged_jws_rejected(self):
        cert = build_cert(aki='AA' * 20, ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        forged = make_jws({'vendorName': 'X', 'serNum': '1'}, cert)
        for path in ('/setPIN', '/setPUK', '/unblockPIN', '/getSerialNumber'):
            res = post(path, {'jwsData': forged})
            self.assertEqual(res['reasonCode'], 403, path)

    def test_unblock_requires_admin_authorization(self):
        ''' A renew-level JWS is valid for setPIN but must not unlock unblockPIN '''

        cert = build_cert(aki='07DCAA307698B7854B6D0318C8E3CDA77B3682EF',
                          ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        renew_token = make_jws({'vendorName': 'X', 'serNum': '1'}, cert)
        res = post('/unblockPIN', {'jwsData': renew_token})
        self.assertEqual(res['status'], 'error')
        self.assertEqual(res['reasonCode'], 403)
        self.assertIn('authorization', res['reasonText'].lower())


class TestPinSafetyGate(unittest.TestCase):
    '''
    The JWS gate must run before anything else: on a failed verification,
    neither the hardware layer nor the user prompt may ever be reached.
    Insurance against a refactor reordering the checks.
    '''

    PIN_PATHS = ('/setPIN', '/setPUK', '/unblockPIN', '/getSerialNumber')

    def setUp(self):
        # Any prompt raises AssertionError straight out of the handler
        set_ui_provider(ForbiddenUI())

    def tearDown(self):
        set_ui_provider(None)

    def _post_all_with(self, body):
        # hardware/detector spies remain patch-based until the phase-3
        # backend resolver gives app.py a real injection seam
        with patch('src.app.hardware') as hw_spy, \
             patch('src.app.detector') as det_spy:
            for path in self.PIN_PATHS:
                res = post(path, body)
                self.assertEqual(res['reasonCode'], 403, path)
        self.assertEqual(hw_spy.mock_calls, [])
        det_spy.auto_detect_library.assert_not_called()

    def test_missing_jws_never_touches_hardware_or_ui(self):
        self._post_all_with({})

    def test_forged_jws_never_touches_hardware_or_ui(self):
        cert = build_cert(aki='AA' * 20, ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        forged = make_jws({'vendorName': 'X', 'serNum': '1'}, cert)
        self._post_all_with({'jwsData': forged})

    def test_tampered_jws_never_touches_hardware_or_ui(self):
        cert = build_cert(aki='07DCAA307698B7854B6D0318C8E3CDA77B3682EF',
                          ext_texts={jws.OID_ADMIN_FUNCTIONS: jws.ADMIN_MARKER})
        tampered = make_jws({'vendorName': 'X', 'serNum': '1'}, cert, tamper=True)
        self._post_all_with({'jwsData': tampered})


if __name__ == '__main__':
    unittest.main()
