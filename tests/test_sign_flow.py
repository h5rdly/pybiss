'''
Full HTTP-level /sign round trip: a portal-shaped request goes through the
real MiniServer HTTP parsing, server-signature verification, user
confirmation, and mocked PKCS#11 signing
'''

import base64, hashlib, json, sys, unittest
from unittest.mock import patch

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.app import app
from src import app as app_mod
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

        self.ui = FakeUI()
        set_ui_provider(self.ui)

        # No hardware/detector mock spies
        from mocks import MockLoader
        import src.hardware as hardware
        self.loader = MockLoader('mock-lib')
        self.token = self.loader.token
        self.token.mock_certs = [{'handle': 777, 'id': b'\x01', 'der': self.signer_der}]

        self._orig_load = app_mod._load_pkcs11
        app_mod._load_pkcs11 = lambda: hardware.load_pkcs11('mock-lib', loader=self.loader)

        # Neutralise ambient ATR detection so backend selection is deterministic
        # and never touches the real reader (matches a CI box with no card)
        self._orig_detected = app_mod._detected_atr
        app_mod._detected_atr = lambda: ''

    def tearDown(self):
        set_ui_provider(None)
        app_mod._load_pkcs11 = self._orig_load
        app_mod._detected_atr = self._orig_detected

    async def test_sign_happy_path(self):
        ''' Valid portal request -> verified, confirmed, signed, BISS envelope out '''

        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        status, resp = await http_post('/sign', body)

        assert status == 200
        data = json.loads(resp)
        assert data['status'] == 'ok'
        # the fake token returns a 256-byte signature beginning AA BB CC
        sig = base64.b64decode(data['signatures'][0])
        assert len(sig) == 256
        assert sig[:3] == b'\xAA\xBB\xCC'
        # the card was asked to sign the document itself (CKM_SHA256_RSA_PKCS)
        assert self.token.last_signed_data == self.document

    async def test_whitelisted_apdu_card_falls_through_to_pkcs11(self):
        '''
        A whitelisted card resolves to [apdu, pkcs11] on Linux. When no
        APDU-capable card is actually reachable (the backend raises
        BackendUnavailable), signing must fall through to PKCS#11 and still
        succeed. (When an APDU card IS present, _sign_apdu handles it - covered
        by the driver/backend tests.)
        '''

        import src.backends as backends_mod
        atr = '3B7F96000080318065B0855956FB120FFE829000'
        from src.app import config
        orig = config.parser.get('Settings', 'apduWhitelist', fallback=None)
        config.parser.set('Settings', 'apduWhitelist', atr)

        def apdu_unavailable(*a, **k):
            raise backends_mod.BackendUnavailable('no APDU card reachable')

        app_mod._detected_atr = lambda: atr        # this card IS detected + whitelisted
        try:
            with patch('src.app.sys.platform', 'linux'), \
                 patch.dict('src.app._SIGN', {'apdu': apdu_unavailable}):
                body = portal_sign_request(self.document, self.signer_der, self.server_der)
                status, resp = await http_post('/sign', body)
        finally:
            if orig is None:
                config.parser.remove_option('Settings', 'apduWhitelist')
            else:
                config.parser.set('Settings', 'apduWhitelist', orig)

        data = json.loads(resp)
        assert data['status'] == 'ok'
        assert self.token.last_signed_data == self.document

    async def test_bad_server_signature_never_reaches_the_card(self):
        ''' A tampered server signature is rejected before any signing happens '''

        body = portal_sign_request(self.document, self.signer_der, self.server_der,
                                   break_signature=True)
        status, resp = await http_post('/sign', body)

        data = json.loads(resp)
        assert data['status'] == 'error'
        assert data['reasonCode'] == 403
        assert data['signatures'] == []
        assert self.token.last_signed_data is None

    async def test_user_refusal_aborts_signing(self):
        set_ui_provider(FakeUI(confirm=False))
        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        _, resp = await http_post('/sign', body)

        data = json.loads(resp)
        assert data['status'] == 'error'
        assert data['signatures'] == []
        assert self.token.last_signed_data is None

    async def test_unknown_signer_certificate_rejected(self):
        ''' Requesting a cert that is not on the card yields 404, no signing '''

        stranger = build_cert(cn='Stranger', ski='09' * 20)
        body = portal_sign_request(self.document, stranger, self.server_der)
        _, resp = await http_post('/sign', body)

        data = json.loads(resp)
        assert data['reasonCode'] == 404
        assert self.token.last_signed_data is None

    async def test_plain_confirm_text_is_shown_verbatim(self):
        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        body['confirmText'] = ['Please authorize this signature']
        await http_post('/sign', body)
        assert self.ui.last_confirm_text == 'Please authorize this signature'

    async def test_hash_sentinel_shows_the_content_tail_not_the_word(self):
        ''' confirmText=="hash" means "content is a hash": show its tail, like the daemon '''

        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        body['confirmText'] = ['hash']
        await http_post('/sign', body)

        content_b64 = body['contents'][0]
        assert self.ui.last_confirm_text == '...' + content_b64[-20:]
        assert self.ui.last_confirm_text.lower() != 'hash'

    async def test_additional_confirm_text_is_forwarded(self):
        body = portal_sign_request(self.document, self.signer_der, self.server_der)
        body['additionalConfirmText'] = 'Amount: 100 BGN'
        await http_post('/sign', body)
        assert self.ui.last_confirm_additional == 'Amount: 100 BGN'


if __name__ == '__main__':
    unittest.main()


class TestSignApduHashGuard(unittest.TestCase):
    ''' _sign_apdu rejects unsupported hash algorithms before touching the card '''

    def test_unsupported_hash_returns_400(self):
        from src.app import _sign_apdu
        r = _sign_apdu(['deadbeef'], 'MD5', b'\x30\x82', ui_provider=None)
        assert r['status'] == 'error'
        assert r['reasonCode'] == 400

    def test_supported_hash_map(self):
        from src.app import _APDU_HASH
        assert _APDU_HASH['SHA256'] == ('sha256', 0x42)
        assert _APDU_HASH['SHA512'] == ('sha512', 0x62)
