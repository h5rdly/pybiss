'''
Fidelity tests: pybiss's REST surface must match the official BISS daemon
(as decompiled from biss-3.46) closely enough for portals to not notice.
'''

import json, sys, unittest
import re
from unittest.mock import patch

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.app import app
from src.server import Request
from src.ui_bridge import set_ui_provider
from src import i18n as biss_locale
from tests.x509_helpers import build_cert, build_test_chain, make_jws
from tests.mocks import ForbiddenUI, FakeUI
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
            assert ('POST', path) in app.routes, f'missing POST {path}'
        for path in ('/version', '/status'):
            assert ('GET', path) in app.routes, f'missing GET {path}'

    def test_get_serial_number_is_not_a_get_route(self):
        ''' The Java daemon only accepts POST here; a GET route would mask that '''

        assert ('GET', '/getSerialNumber') not in app.routes


class TestEnvelopes(unittest.TestCase):

    def test_status_returns_empty_json_string(self):
        ''' GET /status answers with the literal JSON string "" like the original '''

        assert get('/status') == ''
        assert json.dumps(get('/status')) == '""'

    def test_version_shape_and_format(self):
        res = get('/version')
        for field in ('version', 'httpMethods', 'contentTypes', 'signatureTypes',
                      'selectorAvailable', 'hashAlgorithms'):
            assert field in res
        # Portals may version-gate; the value must mimic the Java "3.46" format
        assert re.search(r'^\d+\.\d+$', res['version'])

    def test_advertised_hash_algorithms_are_all_implemented(self):
        ''' Never advertise a hash we cannot actually sign with (SHA1 was dropped) '''

        from src.app import _APDU_HASH
        advertised = {a.strip() for a in get('/version')['hashAlgorithms'].split(',')}
        assert advertised == set(_APDU_HASH)
        assert 'SHA1' not in advertised

    def test_close_returns_bare_string_body(self):
        ''' /close answers with an unquoted string body despite the JSON content type '''

        res = post('/close')
        assert res == b'Signing service successfully closed!'

    def test_unimplemented_endpoints_return_biss_error_envelope(self):
        for path in ('/generatePfx', '/getPfxKeyPair', '/setNewPUKNewPIN', '/v2/renew'):
            res = post(path)
            assert res['status'] == 'error', path
            assert res['reasonCode'] == 501, path
            assert 'reasonText' in res, path


# Every card-touching endpoint the official daemon gates behind jwsData.
# /sign and /getsigner are deliberately excluded (they take plain JSON).
JWS_GATED_PATHS = ('/setPIN', '/setPUK', '/unblockPIN', '/getSerialNumber',
                   '/writeCertSC', '/genRSAPair', '/delRSAPair', '/delCert',
                   '/getInfo', '/renew')


class TestJwsGating(unittest.TestCase):
    ''' Every card-touching endpoint must reject requests lacking a valid jwsData '''

    def test_missing_jws_data_rejected(self):
        for path in JWS_GATED_PATHS:
            res = post(path, {})
            assert res['status'] == 'error', path
            assert res['reasonCode'] == 403, path

    def test_forged_jws_rejected(self):
        cert = build_cert(aki='AA' * 20, ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        forged = make_jws({'vendorName': 'X', 'serNum': '1'}, cert)
        for path in JWS_GATED_PATHS:
            res = post(path, {'jwsData': forged})
            assert res['reasonCode'] == 403, path

    def test_plain_json_write_endpoints_are_not_ungated(self):
        ''' Regression guard: a write/delete op with no jwsData must never reach the card '''

        for path in ('/writeCertSC', '/genRSAPair', '/delRSAPair', '/delCert', '/renew'):
            with patch('src.app.hardware') as hw_spy, patch('src.app.detector') as det_spy:
                res = post(path, {'label': 'X', 'certificate': 'AAAA'})
                assert res['reasonCode'] == 403, path
                assert hw_spy.mock_calls == [], path
                det_spy.auto_detect_library.assert_not_called()

    def test_unblock_requires_admin_authorization(self):
        ''' A renew-level JWS is valid for setPIN but must not unlock unblockPIN '''

        cert = build_cert(aki='07DCAA307698B7854B6D0318C8E3CDA77B3682EF',
                          ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        renew_token = make_jws({'vendorName': 'X', 'serNum': '1'}, cert)
        res = post('/unblockPIN', {'jwsData': renew_token})
        assert res['status'] == 'error'
        assert res['reasonCode'] == 403
        assert 'authorization' in res['reasonText'].lower()


class TestChainFoundEndpoint(unittest.TestCase):

    def setUp(self):
        self.leaf, self.inter, self.root = build_test_chain()
        # Only the cert store is patched; the chain logic runs for real
        self.loader = patch('src.app.service.load_ca_certificates',
                            return_value=[self.leaf, self.inter, self.root])
        self.loader.start()

    def tearDown(self):
        self.loader.stop()

    def test_missing_key_identifier_rejected(self):
        res = post('/chainFound', {})
        assert not res['chainFound']
        assert res['reasonCode'] == 400

    def test_complete_chain_reported_found(self):
        res = post('/chainFound', {'keyIdentifier': '01' * 20, 'store': 'MY'})
        assert res['chainFound']
        assert res['status'] == 'ok'

    def test_incomplete_chain_reported_not_found(self):
        self.loader.stop()
        self.loader = patch('src.app.service.load_ca_certificates',
                            return_value=[self.leaf, self.inter])  # root missing
        self.loader.start()
        res = post('/chainFound', {'keyIdentifier': '01' * 20, 'store': 'MY'})
        assert not res['chainFound']
        assert res['status'] == 'ok'

    def test_unknown_identifier_reported_not_found(self):
        res = post('/chainFound', {'keyIdentifier': 'AB' * 20, 'store': 'MY'})
        assert not res['chainFound']
        assert res['status'] == 'ok'

    def test_never_touches_card_or_hardware(self):
        ''' The original daemon's chainFound is store-only; ours must be too '''

        with patch('src.app.hardware') as hw_spy, patch('src.app.detector') as det_spy:
            post('/chainFound', {'keyIdentifier': '01' * 20, 'store': 'MY'})
        assert hw_spy.mock_calls == []
        assert det_spy.mock_calls == []


class TestGenSpkacEndpoint(unittest.TestCase):

    ADMIN_CERT_AKI = '07DCAA307698B7854B6D0318C8E3CDA77B3682EF'

    def setUp(self):
        set_ui_provider(FakeUI(pin='1234'))
        # No hardware mock spies: inject a fake PKCS#11 table via the seam, so
        # the real hardware.generate_spkac runs against the fake token.
        from mocks import MockLoader
        import src.app as app_mod
        import src.hardware as hardware
        self.loader = MockLoader('mock-lib')
        self.token = self.loader.token
        self._app_mod = app_mod
        self._orig_load = app_mod._load_pkcs11
        app_mod._load_pkcs11 = lambda: hardware.load_pkcs11('mock-lib', loader=self.loader)

    def tearDown(self):
        set_ui_provider(None)
        self._app_mod._load_pkcs11 = self._orig_load

    def _valid_jws(self, key_size=2048):
        cert = build_cert(aki=self.ADMIN_CERT_AKI,
                          ext_texts={jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER})
        return make_jws({'vendorName': 'GEMALTO', 'serialNum': 'SN123', 'keySize': key_size}, cert)

    def test_valid_request_returns_pkcs10(self):
        res = post('/genSPKAC', {'jwsData': self._valid_jws()})
        assert res['status'] == 'ok'
        # the real generate_spkac ran against the fake token and produced a
        # non-trivial base64 SPKAC payload
        import base64
        assert len(base64.b64decode(res['pkcs10Data'])) > 32

    def test_requested_key_size_reaches_the_card(self):
        ''' A 3072-bit request (current B-Trust cards) must not silently become 2048 '''

        res = post('/genSPKAC', {'jwsData': self._valid_jws(key_size=3072)})
        assert res['status'] == 'ok'
        # the fake token recorded the CKA_MODULUS_BITS the keygen actually requested
        assert self.token.last_keygen_bits == 3072

    def test_invalid_key_size_returns_biss_envelope(self):
        ''' A junk keySize must produce a 400 T-envelope, not a raw 500 '''

        res = post('/genSPKAC', {'jwsData': self._valid_jws(key_size='4096-bit')})
        assert res['status'] == 'error'
        assert res['reasonCode'] == 400
        assert 'reasonText' in res

    def test_missing_jws_rejected_without_touching_card(self):
        with patch('src.app.hardware.generate_spkac') as spy:
            res = post('/genSPKAC', {})
            assert res['reasonCode'] == 403
            spy.assert_not_called()


class TestLocaleCatalog(unittest.TestCase):
    ''' The extracted BISS reasonText catalog (item 4) '''

    def setUp(self):
        # Pin the language so assertions don't depend on the machine's settings.ini
        from src.config import config
        self.config = config
        self._original_lang = config.parser.get('Settings', 'language')

    def tearDown(self):
        self.config.parser.set('Settings', 'language', self._original_lang)

    def _set_lang(self, lang):
        self.config.parser.set('Settings', 'language', lang)

    def test_known_key_returns_biss_english_text(self):
        self._set_lang('en')
        assert biss_locale.reason('response.success') == 'The process is successfully completed'
        assert biss_locale.reason('error.no-card-found') == 'No card found'

    def test_unknown_key_falls_back_to_key(self):
        self._set_lang('en')
        assert biss_locale.reason('no.such.key') == 'no.such.key'

    def test_bulgarian_translation_when_configured(self):
        self._set_lang('bg')
        assert biss_locale.reason('response.success') == 'Операцията завърши успешно'

    def test_bulgarian_falls_back_to_english_for_ui_only_key(self):
        # error.signature-type-not-supported exists only in the English catalog
        self._set_lang('bg')
        assert biss_locale.reason('error.signature-type-not-supported') == 'The signature type is not supported'


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
                assert res['reasonCode'] == 403, path
        assert hw_spy.mock_calls == []
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
