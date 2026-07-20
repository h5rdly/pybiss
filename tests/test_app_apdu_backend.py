import base64, hashlib, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import app
from x509_helpers import build_cert, TEST_N, TEST_E
from synthetic_card import synthetic_idprime_card


def _make_card():
    ''' A deterministic synthetic card for the signer used across these tests '''
    return synthetic_idprime_card(name='Replay Test Signer', personal_id='PNOBG-0000000001')


TEST_DER = _make_card().cert_der


class _FakeUI:
    def __init__(self, pin=None): self._pin = pin
    def choose_certificate(self, certs): return 0
    def prompt_pin(self, *a, **k): return self._pin


class TestApduBackendsNoMocks(unittest.TestCase):

    def setUp(self):
        self._orig_open = app._open_card
        app._open_card = lambda: _make_card()

    def tearDown(self):
        app._open_card = self._orig_open

    def test_getsigner_apdu_discovers_the_cert(self):
        result = app._getsigner_apdu(selector=None, show_valid_certs=False,
                                     ui_provider=_FakeUI())
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(result['chain'])
        self.assertEqual(base64.b64decode(result['chain'][0]), TEST_DER)

    def test_sign_apdu_produces_a_verifiable_signature(self):
        from src.verifier import verify_rsa_pkcs1_v1_5
        payload = b'a document to sign through the real _sign_apdu backend'
        result = app._sign_apdu([base64.b64encode(payload).decode()],
                                'SHA256', TEST_DER, _FakeUI(pin='1234'))
        self.assertEqual(result['status'], 'ok')
        sig = base64.b64decode(result['signatures'][0])
        self.assertTrue(verify_rsa_pkcs1_v1_5(payload, sig, TEST_N, TEST_E, 'SHA256'))

    def test_sign_apdu_cancelled_pin_is_user_canceled(self):
        result = app._sign_apdu([base64.b64encode(b'x').decode()],
                                'SHA256', TEST_DER, _FakeUI(pin=None))
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['reasonCode'], 401)

    def test_sign_apdu_unknown_cert_is_token_not_found(self):
        other = build_cert(cn='Someone Else', not_after='390101000000Z')
        result = app._sign_apdu([base64.b64encode(b'x').decode()],
                                'SHA256', other, _FakeUI(pin='1234'))
        self.assertEqual(result['reasonCode'], 404)


class TestApduBackendReplayRoundtrip(unittest.TestCase):
    '''
    Record a real _sign_apdu run against the synthetic card, then replay the
    captured trace through _sign_apdu again with ZERO hardware - proving the
    tracing.ReplayConnection drop-in works. This is the template for replaying
    a captured real-card trace locally (kept out of the repo for privacy).
    '''

    def test_record_then_replay(self):
        from src.tracing import TracingConnection, ReplayConnection
        from src.verifier import verify_rsa_pkcs1_v1_5

        payload_b64 = base64.b64encode(b'record then replay').decode()

        orig = app._open_card
        # 1) record: wrap the synthetic card in a tracer
        tracer_box = {}

        class RecordingCM:
            def __enter__(self):
                self._t = TracingConnection(_make_card())
                self._t.get_atr()
                tracer_box['t'] = self._t
                return self._t
            def __exit__(self, *e): return False

        try:
            app._open_card = lambda: RecordingCM()
            r1 = app._sign_apdu([payload_b64], 'SHA256', TEST_DER, _FakeUI(pin='1234'))
            self.assertEqual(r1['status'], 'ok')
            trace = tracer_box['t'].to_dict()

            # 2) replay: same trace, no synthetic card, via ReplayConnection
            app._open_card = lambda: ReplayConnection.from_dict(trace)
            r2 = app._sign_apdu([payload_b64], 'SHA256', TEST_DER, _FakeUI(pin='1234'))
        finally:
            app._open_card = orig

        self.assertEqual(r2['status'], 'ok')
        self.assertEqual(r1['signatures'], r2['signatures'])
        sig = base64.b64decode(r2['signatures'][0])
        self.assertTrue(verify_rsa_pkcs1_v1_5(b'record then replay', sig, TEST_N, TEST_E, 'SHA256'))


class TestSyntheticCardFactory(unittest.TestCase):
    ''' The factory builds a working card from arbitrary fake identity fields '''

    def test_identity_fields_land_in_the_cert_and_it_signs(self):
        from src.cards import BTrustDriver
        from src.cert_parser import get_x509_metadata, get_rsa_public_key
        from src.verifier import verify_rsa_pkcs1_v1_5

        card = synthetic_idprime_card(name='Ivan Petrov', personal_id='PNOBG-9', email='iv@x.bg')
        cert = BTrustDriver.create(card).discover_certificates()[0]
        subject = get_x509_metadata(cert['der'])['subject']
        self.assertIn('Ivan Petrov', subject)
        self.assertIn('PNOBG-9', subject)
        self.assertIn('iv@x.bg', subject)

        n, e = get_rsa_public_key(cert['der'])
        sig = BTrustDriver.create(card).sign('9999', hashlib.sha256(b'm').digest(),
                                             key_ref=cert['key_ref'])
        self.assertTrue(verify_rsa_pkcs1_v1_5(b'm', sig, n, e, 'SHA256'))

    def test_key_ref_is_configurable_and_discovered(self):
        from src.cards import BTrustDriver
        card = synthetic_idprime_card(name='X', key_ref=0x41)
        self.assertEqual(BTrustDriver.create(card).discover_certificates()[0]['key_ref'], 0x41)


if __name__ == '__main__':
    unittest.main()
