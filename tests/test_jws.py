import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import jws
from src.service import build_certificate_chain, chain_exists_for_key_identifier
from tests.x509_helpers import build_cert, build_test_chain, make_jws


PROD_ACA = '07DCAA307698B7854B6D0318C8E3CDA77B3682EF'

RENEW_EXT = {jws.OID_RENEW_FUNCTIONS: jws.RENEW_MARKER}
ADMIN_EXT = {jws.OID_ADMIN_FUNCTIONS: jws.ADMIN_MARKER}

PAYLOAD = {'vendorName': 'GEMALTO', 'serNum': '1234567890'}


def _cert(**kw):
    kw.setdefault('aki', PROD_ACA)
    kw.setdefault('ext_texts', RENEW_EXT)
    return build_cert(**kw)


class TestJwsVerify(unittest.TestCase):

    def test_valid_renew_jws_returns_payload(self):
        ''' A correctly signed JWS from a renew-authorized cert decodes to its payload '''

        token = make_jws(PAYLOAD, _cert())
        assert jws.verify(token) == PAYLOAD

    def test_renew_cert_rejected_when_admin_required(self):
        ''' Renew-level authorization must not unlock admin-only operations '''

        token = make_jws(PAYLOAD, _cert())
        _raised = False
        try:
            jws.verify(token, admin_required=True)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_admin_cert_passes_admin_required(self):
        token = make_jws(PAYLOAD, _cert(ext_texts=ADMIN_EXT))
        assert jws.verify(token, admin_required=True) == PAYLOAD

    def test_cert_without_authorization_rejected(self):
        token = make_jws(PAYLOAD, _cert(ext_texts={}))
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_alg_none_rejected(self):
        ''' The classic alg:none forgery must be rejected before any other check '''

        token = make_jws(PAYLOAD, _cert(), alg='none')
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_hmac_alg_rejected(self):
        ''' HS* is rejected outright (HMAC key-confusion attack) '''

        token = make_jws(PAYLOAD, _cert(), alg='HS256')
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_tampered_payload_rejected(self):
        token = make_jws(PAYLOAD, _cert(), tamper=True)
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_unknown_issuer_rejected(self):
        ''' A cert not issued by a pinned B-Trust CA fails even with a valid signature '''

        token = make_jws(PAYLOAD, _cert(aki='AA' * 20))
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_expired_certificate_rejected(self):
        token = make_jws(PAYLOAD, _cert(not_before='200101000000Z', not_after='210101000000Z'))
        _raised = False
        try:
            jws.verify(token)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_missing_x5c_rejected(self):
        token = make_jws(PAYLOAD, _cert())
        # Strip the certificate by rebuilding the header segment
        import base64, json
        head = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
        del head['x5c']
        from tests.x509_helpers import b64url
        broken = b64url(json.dumps(head).encode()) + '.' + '.'.join(token.split('.')[1:])
        _raised = False
        try:
            jws.verify(broken)
        except jws.JwsError:
            _raised = True
        assert _raised, 'jws.JwsError not raised'

    def test_garbage_input_rejected(self):
        for garbage in ('', 'not-a-jws', 'a.b', 'a.b.c.d', '..'):
            _raised = False
            try:
                jws.verify(garbage)
            except jws.JwsError:
                _raised = True
            assert _raised, 'jws.JwsError not raised'


class TestBuildCertificateChain(unittest.TestCase):

    def setUp(self):
        self.leaf, self.inter, self.root = build_test_chain()
        self.stranger = build_cert(cn='Other', ski='09' * 20, aki='08' * 20)

    def test_chain_ordered_leaf_to_root(self):
        candidates = [self.stranger, self.root, self.inter]  # deliberately shuffled
        chain = build_certificate_chain(self.leaf, candidates)
        assert chain == [self.leaf, self.inter, self.root]

    def test_missing_intermediate_ends_chain_early(self):
        chain = build_certificate_chain(self.leaf, [self.root, self.stranger])
        assert chain == [self.leaf]

    def test_self_signed_leaf_stands_alone(self):
        lone = build_cert(cn='Lone', ski='05' * 20, aki='05' * 20)
        chain = build_certificate_chain(lone, [self.root, self.inter])
        assert chain == [lone]


class TestChainExists(unittest.TestCase):
    ''' Backs the /chainFound endpoint '''

    def setUp(self):
        self.leaf, self.inter, self.root = build_test_chain()

    def test_complete_chain_found(self):
        ok = chain_exists_for_key_identifier('01' * 20, [self.leaf, self.inter, self.root])
        assert ok

    def test_case_insensitive_key_identifier(self):
        # Alphabetic hex so the case actually differs between query and cert
        lone = build_cert(cn='Lower', ski='ab' * 20)
        assert chain_exists_for_key_identifier('AB' * 20, [lone])
        assert chain_exists_for_key_identifier('ab' * 20, [lone])

    def test_incomplete_chain_not_found(self):
        # Missing the root -> chain ends at a non-self-signed intermediate
        ok = chain_exists_for_key_identifier('01' * 20, [self.leaf, self.inter])
        assert not ok

    def test_unknown_key_identifier_not_found(self):
        ok = chain_exists_for_key_identifier('AB' * 20, [self.leaf, self.inter, self.root])
        assert not ok

    def test_empty_key_identifier_not_found(self):
        assert not chain_exists_for_key_identifier('', [self.leaf])


if __name__ == '__main__':
    unittest.main()
