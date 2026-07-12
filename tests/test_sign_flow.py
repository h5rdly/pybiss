'''
Full HTTP-level /sign round trip: a portal-shaped request goes through the
real MiniServer HTTP parsing, server-signature verification, user
confirmation, and mocked PKCS#11 signing
'''

import base64, hashlib, json, sys, unittest
from unittest.mock import patch

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.app import app
from src.sc_apdu import pad_pkcs1_v15_sha256
from src.ui_bridge import set_ui_provider

from x509_helpers import build_cert, TEST_N, TEST_D
from test_server import MockReader, MockWriter
from mocks import FakeUI


def rsa_sign(payload: bytes) -> bytes:
    ''' RSASSA-PKCS1-v1_5/SHA-256 signature with the test key (scheme B: raw payload) '''

    block = pad_pkcs1_v15_sha256(hashlib.sha256(payload).digest(), 2048)
    return pow(int.from_bytes(block, 'big'), TEST_D, TEST_N).to_bytes(256, 'big')


def portal_sign_request(document: bytes, signer_der: bytes, server_der: bytes,
                        break_signature: bool = False) -> dict:
    ''' Builds the JSON body the B-Trust portal sends to /sign '''

    server_sig = rsa_sign(document)
    if break_signature:
        server_sig = bytes([server_sig[0] ^ 0xFF]) + server_sig[1:]

    return {
        'contents': [base64.b64encode(document).decode()],
        'signedContents': [base64.b64encode(server_sig).decode()],
        'signedContentsCert': [base64.b64encode(server_der).decode()],
        'hashAlgorithm': 'SHA256',
        'confirmText': ['Sign this document?'],
        'signerCertificateB64': base64.b64encode(signer_der).decode(),
    }


async def http_post(path: str, body: dict) -> tuple[int, bytes]:
    ''' Drives a request through the real HTTP handling and parses the response '''

    payload = json.dumps(body).encode('utf-8')
    raw = (f'POST {path} HTTP/1.1\r\ncontent-length: {len(payload)}\r\n\r\n').encode() + payload
    writer = MockWriter()
    await app.handle_client(MockReader(raw), writer)

    head, _, resp_body = writer.output.partition(b'\r\n\r\n')
    status = int(head.split(b' ')[1])
    return status, resp_body


class TestSignFlow(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.document = b'important contract bytes'
        self.signer_der = build_cert(cn='Signer', ski='01' * 20)
        self.server_der = build_cert(cn='B-Trust Server', ski='02' * 20)

        set_ui_provider(FakeUI())

        # PKCS#11/detector still need patching until the phase-3 backend
        # resolver gives app.py a real injection seam
        self.patchers = [
            patch('src.app.detector.auto_detect_library', return_value='/fake/pkcs11.so'),
            patch('src.app.hardware.load_pkcs11', return_value=object()),
            patch('src.app.hardware.get_slots', return_value=[0]),
            patch('src.app.hardware.get_certificates',
                  return_value=[{'der': self.signer_der, 'id': b'\x01'}]),
            patch('src.app.hardware.sign_payload', return_value=b'FAKE_CARD_SIGNATURE'),
        ]
        self.mocks = [p.start() for p in self.patchers]
        self.sign_mock = self.mocks[-1]

    def tearDown(self):
        set_ui_provider(None)
        for p in self.patchers:
            p.stop()

    async def test_sign_happy_path(self):
        ''' Valid portal request -> verified, confirmed, signed, BISS envelope out '''

        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        status, resp = await http_post('/sign', body)

        self.assertEqual(status, 200)
        data = json.loads(resp)
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['signatures'],
                         [base64.b64encode(b'FAKE_CARD_SIGNATURE').decode()])
        # The card was asked to sign the document itself
        self.assertEqual(self.sign_mock.call_args.kwargs['payload'], self.document)

    async def test_whitelisted_apdu_card_falls_through_to_pkcs11(self):
        '''
        A validated / whitelisted card resolves to [apdu, pkcs11] on Linux, but
        APDU signing is not enabled yet - it must fall through to PKCS#11 and
        still sign
        '''

        atr = '3B7F96000080318065B0855956FB120FFE829000'
        from src.app import config
        orig = config.parser.get('Settings', 'apduWhitelist', fallback=None)
        config.parser.set('Settings', 'apduWhitelist', atr)
        try:
            with patch('src.app.detector.get_connected_atrs', return_value=[atr]), \
                 patch('src.app.sys.platform', 'linux'):
                body = portal_sign_request(self.document, self.signer_der, self.server_der)
                status, resp = await http_post('/sign', body)
        finally:
            if orig is None:
                config.parser.remove_option('Settings', 'apduWhitelist')
            else:
                config.parser.set('Settings', 'apduWhitelist', orig)

        data = json.loads(resp)
        self.assertEqual(data['status'], 'ok')          # signed despite APDU being first
        self.sign_mock.assert_called()                  # via the PKCS#11 fallthrough

    async def test_bad_server_signature_never_reaches_the_card(self):
        ''' A tampered server signature is rejected before any signing happens '''

        body = portal_sign_request(self.document, self.signer_der, self.server_der,
                                   break_signature=True)
        status, resp = await http_post('/sign', body)

        data = json.loads(resp)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['reasonCode'], 403)
        self.assertEqual(data['signatures'], [])
        self.sign_mock.assert_not_called()

    async def test_user_refusal_aborts_signing(self):
        set_ui_provider(FakeUI(confirm=False))
        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        _, resp = await http_post('/sign', body)

        data = json.loads(resp)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['signatures'], [])
        self.sign_mock.assert_not_called()

    async def test_unknown_signer_certificate_rejected(self):
        ''' Requesting a cert that is not on the card yields 404, no signing '''

        stranger = build_cert(cn='Stranger', ski='09' * 20)
        body = portal_sign_request(self.document, stranger, self.server_der)
        _, resp = await http_post('/sign', body)

        data = json.loads(resp)
        self.assertEqual(data['reasonCode'], 404)
        self.sign_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
