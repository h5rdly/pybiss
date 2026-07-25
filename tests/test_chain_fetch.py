'''
AIA-driven chain completion: chain_fetch.py plus the resolver loop in
service.build_certificate_chain().
'''

import base64, sys, tempfile, unittest
from pathlib import Path

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])
sys.path.append(str(Path(__file__).resolve().parent))

from src import chain_fetch, service
from src.cert_parser import get_x509_subject
from x509_helpers import aia_extension, build_cert


def pem(der: bytes) -> bytes:
    ''' Wrap DER as PEM, the way the B-Trust caIssuers endpoint serves it. '''

    body = base64.encodebytes(der)
    return b'-----BEGIN CERTIFICATE-----\n' + body + b'-----END CERTIFICATE-----\n'


class FakeHttp:
    '''
    A stand-in for the network: maps URL -> response bytes and counts calls, so a
    test can assert "fetched once, then served from cache" without any patching.
    '''

    def __init__(self, responses: dict):
        self.responses = responses          # url -> bytes (or None for unreachable)
        self.calls = []

    def get(self, url, timeout=10):
        self.calls.append(url)
        return self.responses.get(url)


# --- the AIA parser --------------------------------------------------------

class TestCaIssuerUrls(unittest.TestCase):

    def test_extracts_the_ca_issuers_url(self):
        cert = build_cert(cn='Leaf', raw_exts=[aia_extension('http://ca.example/issuer.cer')])
        assert chain_fetch.ca_issuer_urls(cert) == ['http://ca.example/issuer.cer']

    def test_returns_multiple_urls_in_order(self):
        cert = build_cert(raw_exts=[aia_extension('http://a.example/1.cer',
                                                  'http://b.example/2.cer')])
        assert chain_fetch.ca_issuer_urls(cert) == ['http://a.example/1.cer', 'http://b.example/2.cer']

    def test_no_aia_extension_yields_empty(self):
        assert chain_fetch.ca_issuer_urls(build_cert(cn='Bare')) == []

    def test_ocsp_access_method_is_not_mistaken_for_ca_issuers(self):
        # AIA with only an OCSP AccessDescription (method 48.1) - not caIssuers (48.2)
        from x509_helpers import oid, seq, octet, tlv
        ocsp = seq(oid('1.3.6.1.5.5.7.1.1'),
                   octet(seq(seq(oid('1.3.6.1.5.5.7.48.1'),
                                 tlv(0x86, b'http://ocsp.example')))))
        cert = build_cert(raw_exts=[ocsp])
        assert chain_fetch.ca_issuer_urls(cert) == []

    def test_malformed_extension_does_not_raise(self):
        from x509_helpers import oid, seq, octet
        broken = seq(oid('1.3.6.1.5.5.7.1.1'), octet(b'\x30\x09not-valid-der'))
        cert = build_cert(raw_exts=[broken])
        assert chain_fetch.ca_issuer_urls(cert) == []


# --- the fetcher (transport seam) -----------------------------------------

class TestFetchIssuerCert(unittest.TestCase):

    def test_decodes_a_pem_response_to_der(self):
        issuer = build_cert(cn='Issuer')
        http = FakeHttp({'http://ca/issuer.cer': pem(issuer)})
        assert chain_fetch.fetch_issuer_cert('http://ca/issuer.cer', http_get=http.get) == issuer

    def test_accepts_a_raw_der_response(self):
        issuer = build_cert(cn='Issuer')
        http = FakeHttp({'http://ca/issuer.cer': issuer})
        assert chain_fetch.fetch_issuer_cert('http://ca/issuer.cer', http_get=http.get) == issuer

    def test_non_certificate_body_is_rejected(self):
        http = FakeHttp({'http://ca/x': b'<html>not a cert</html>'})
        assert chain_fetch.fetch_issuer_cert('http://ca/x', http_get=http.get) is None

    def test_unreachable_returns_none(self):
        http = FakeHttp({'http://ca/x': None})
        assert chain_fetch.fetch_issuer_cert('http://ca/x', http_get=http.get) is None

    def test_non_http_scheme_is_refused_without_touching_the_network(self):
        # ldap:// / file:// must be rejected by the real _http_get, no fake needed
        assert chain_fetch.fetch_issuer_cert('ldap://ca/x', timeout=0.001) is None
        assert chain_fetch.fetch_issuer_cert('file:///etc/passwd', timeout=0.001) is None


# --- the resolver (fetch-once + cache) ------------------------------------

class TestAiaResolver(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = self.tmp.name
        self.issuer = build_cert(cn='Issuer')
        self.leaf = build_cert(cn='Leaf', raw_exts=[aia_extension('http://ca/issuer.cer')])

    def tearDown(self):
        self.tmp.cleanup()

    def _resolver(self, http):
        return chain_fetch.make_aia_resolver(
            self.cache, fetcher=lambda url: chain_fetch.fetch_issuer_cert(url, http_get=http.get))

    def test_fetches_the_issuer_named_by_aia(self):
        http = FakeHttp({'http://ca/issuer.cer': pem(self.issuer)})
        assert self._resolver(http)(self.leaf) == self.issuer
        assert http.calls == ['http://ca/issuer.cer']

    def test_second_call_is_served_from_cache_no_refetch(self):
        http = FakeHttp({'http://ca/issuer.cer': pem(self.issuer)})
        resolver = self._resolver(http)
        resolver(self.leaf)
        resolver(self.leaf)                       # a fresh resolver would refetch; cache must not
        assert http.calls == ['http://ca/issuer.cer']

    def test_a_new_resolver_reuses_the_on_disk_cache(self):
        http1 = FakeHttp({'http://ca/issuer.cer': pem(self.issuer)})
        self._resolver(http1)(self.leaf)
        http2 = FakeHttp({})                      # empty: any fetch would fail
        assert self._resolver(http2)(self.leaf) == self.issuer
        assert http2.calls == []
        assert any(Path(self.cache).iterdir())

    def test_no_aia_returns_none(self):
        http = FakeHttp({})
        assert self._resolver(http)(build_cert(cn='Bare')) is None

    def test_unreachable_issuer_returns_none(self):
        http = FakeHttp({'http://ca/issuer.cer': None})
        assert self._resolver(http)(self.leaf) is None


# --- the completion loop in build_certificate_chain -----------------------

class TestChainCompletion(unittest.TestCase):

    def setUp(self):
        # root (self-signed) <- inter <- leaf, linked by AKI->SKI, each carrying
        # an AIA pointing at the next issuer up.
        self.root = build_cert(cn='Root', ski='03' * 20)
        self.inter = build_cert(cn='Inter', ski='02' * 20, aki='03' * 20,
                                raw_exts=[aia_extension('http://ca/root.cer')])
        self.leaf = build_cert(cn='Leaf', ski='01' * 20, aki='02' * 20,
                               raw_exts=[aia_extension('http://ca/inter.cer')])

    def _names(self, chain):
        return [get_x509_subject(d) for d in chain]

    def test_without_resolver_only_the_leaf_comes_back(self):
        chain = service.build_certificate_chain(self.leaf, [self.leaf])
        assert self._names(chain) == ['Leaf']

    def test_resolver_completes_leaf_to_root(self):
        tmp = tempfile.TemporaryDirectory()
        http = FakeHttp({'http://ca/inter.cer': pem(self.inter),
                         'http://ca/root.cer': pem(self.root)})
        resolver = chain_fetch.make_aia_resolver(
            tmp.name, fetcher=lambda url: chain_fetch.fetch_issuer_cert(url, http_get=http.get))
        chain = service.build_certificate_chain(self.leaf, [self.leaf], resolver=resolver)
        assert self._names(chain) == ['Leaf', 'Inter', 'Root']
        tmp.cleanup()

    def test_already_complete_chain_never_calls_the_resolver(self):
        calls = []
        def resolver(der):
            calls.append(der)
            return None
        chain = service.build_certificate_chain(
            self.leaf, [self.leaf, self.inter, self.root], resolver=resolver)
        assert self._names(chain) == ['Leaf', 'Inter', 'Root']
        assert calls == []

    def test_resolver_returning_none_stops_cleanly(self):
        chain = service.build_certificate_chain(self.leaf, [self.leaf], resolver=lambda d: None)
        assert self._names(chain) == ['Leaf']

    def test_a_non_extending_resolver_cannot_loop_forever(self):
        # Resolver keeps handing back an unrelated cert that never links in.
        junk = build_cert(cn='Junk', ski='ff' * 20)
        chain = service.build_certificate_chain(self.leaf, [self.leaf], resolver=lambda d: junk)
        assert self._names(chain) == ['Leaf']


if __name__ == '__main__':
    unittest.main()
