import asyncio, os, socket, ssl, sys, tempfile, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import transport
from src.cert_parser import parse_certificate, pem_to_der


class TestRsaKeyGen(unittest.TestCase):

    def test_generated_key_is_mathematically_consistent(self):
        k = transport.generate_rsa_key(bits=1024)
        assert k['n'] == k['p'] * k['q']
        assert k['n'].bit_length() == 1024
        # e·d ≡ 1 (mod λ) -> sign/verify round-trips any message
        m = 0x1234567890ABCDEF
        assert pow(pow(m, k['d'], k['n']), k['e'], k['n']) == m

    def test_crt_parameters_correct(self):
        k = transport.generate_rsa_key(bits=1024)
        assert k['dp'] == k['d'] % (k['p'] - 1)
        assert k['dq'] == k['d'] % (k['q'] - 1)
        assert (k['qinv'] * k['q']) % k['p'] == 1


class TestSelfSignedCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = transport.generate_rsa_key(bits=1024)
        cls.cert_pem = transport.build_self_signed_cert(cls.key, cn='localhost')

    def test_cert_parses_with_our_own_parser(self):
        der = pem_to_der(self.cert_pem)[0]
        meta = parse_certificate(der)
        assert 'CN=localhost' in meta['subject']
        assert 'CN=localhost' in meta['issuer']
        assert meta['key_type'] == 'RSA'
        # SubjectAltName present (browsers require it)
        assert '2.5.29.17' in meta['extensions']

    def test_self_signature_verifies(self):
        ''' The cert is signed by its own key: verify with our RSA verifier '''
        import hashlib
        from src.cert_parser import DerReader
        der = pem_to_der(self.cert_pem)[0]
        outer = DerReader(der).read_seq()
        tbs_tag_len_value = outer.read_tlv()          # TBSCertificate (tag, value)
        # Re-serialize the exact TBS bytes that were signed
        tbs = bytes([0x30]) + _der_len(len(tbs_tag_len_value[1])) + tbs_tag_len_value[1]
        outer.read_tlv()                              # signatureAlgorithm
        _, sig_bitstring = outer.read_tlv()           # signatureValue BIT STRING
        signature = sig_bitstring[1:]                 # drop unused-bits byte

        n, e = self.key['n'], self.key['e']
        recovered = pow(int.from_bytes(signature, 'big'), e, n)
        em = recovered.to_bytes((n.bit_length() + 7) // 8, 'big')
        expected = transport.pad_pkcs1_v15_sha256(hashlib.sha256(tbs).digest(), n.bit_length())
        assert em == expected


class TestTlsHandshake(unittest.IsolatedAsyncioTestCase):
    ''' a real TLS handshake against the minted cert '''

    async def test_generated_cert_serves_real_tls(self):
        with tempfile.TemporaryDirectory() as d:
            cert_path, key_path = transport.ensure_localhost_cert(d, bits=1024, announce=False)

            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # SECLEVEL=1 permits the fast 1024-bit test key; production uses 2048
            server_ctx.set_ciphers('DEFAULT@SECLEVEL=1')
            server_ctx.load_cert_chain(cert_path, key_path)

            async def handle(reader, writer):
                writer.write(b'hello-tls')
                await writer.drain()
                writer.close()

            server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=server_ctx)
            port = server.sockets[0].getsockname()[1]

            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.set_ciphers('DEFAULT@SECLEVEL=1')
            client_ctx.load_verify_locations(cert_path)  # trust our own cert
            client_ctx.check_hostname = True

            async with server:
                reader, writer = await asyncio.open_connection(
                    '127.0.0.1', port, ssl=client_ctx, server_hostname='localhost')
                data = await reader.read(100)
                writer.close()

            assert data == b'hello-tls'


class TestEnsureCert(unittest.TestCase):

    def test_reuses_existing_cert(self):
        with tempfile.TemporaryDirectory() as d:
            c1, k1 = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            mtime = os.path.getmtime(c1)
            c2, k2 = transport.ensure_localhost_cert(d, bits=1024, announce=False)  # must not regenerate
            assert (c1, k1) == (c2, k2)
            assert os.path.getmtime(c2) == mtime

    def test_regenerates_cert_without_san(self):
        """ A pre-upgrade CN-only cert (no subjectAltName) must be re-minted:
            Chromium ignores CN and rejects SAN-less certs outright. """

        with tempfile.TemporaryDirectory() as d:
            c1, k1 = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            assert transport._cert_has_san(c1)

            # forge the stale state: a cert whose DER carries no SAN OID
            key = transport.generate_rsa_key(1024)
            import base64
            der = transport._seq(b'')  # any SAN-less DER stands in for an old cert
            with open(c1, 'wb') as f:
                f.write(transport._pem('CERTIFICATE', der))
            assert not transport._cert_has_san(c1)

            c2, k2 = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            assert (c1, k1) == (c2, k2)
            assert transport._cert_has_san(c2)

    def test_key_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            _, key_path = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            if os.name != 'nt':
                assert os.stat(key_path).st_mode & 0o777 == 0o600


class TestPickFreePort(unittest.TestCase):

    @staticmethod
    def _find_free_port():
        ''' Bind port 0 to learn a currently-free port, then release it '''
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', 0))
            return probe.getsockname()[1]

    def test_skips_occupied_port(self):
        # Genuinely occupy one port; offer a genuinely-free one second
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            taken = occupied.getsockname()[1]
            free = self._find_free_port()  # released, so pickable
            if free == taken:
                self.skipTest('port collision, rerun')
            assert transport.pick_free_port([taken, free]) == free

    def test_raises_when_none_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            taken = occupied.getsockname()[1]
            _raised = False
            try:
                transport.pick_free_port([taken])
            except OSError:
                _raised = True
            assert _raised, 'OSError not raised'


class TestTrustInstructions(unittest.TestCase):

    def test_returns_platform_commands(self):
        cmds = transport.trust_instructions('/tmp/localhost.pem')
        assert cmds and all(isinstance(c, list) for c in cmds)
        assert any('/tmp/localhost.pem' in ' '.join(c) for c in cmds)


    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux distro routing')
    def test_linux_dir_and_command_match_same_distro(self):
        ''' The anchor directory and its update command must belong to the SAME distro family '''

        orig_isdir = os.path.isdir
        # (anchor dir that "exists", expected update command, wrong command)
        cases = [
            ('/usr/local/share/ca-certificates', 'update-ca-certificates', 'update-ca-trust'),
            ('/etc/pki/ca-trust/source/anchors', 'update-ca-trust', 'update-ca-certificates'),
            ('/etc/ca-certificates/trust-source/anchors', 'extract-compat', 'update-ca-trust'),
        ]
        for present_dir, right_cmd, wrong_cmd in cases:
            os.path.isdir = lambda p, _d=present_dir: p == _d
            try:
                cmds = transport.trust_instructions('/tmp/localhost.pem')
            finally:
                os.path.isdir = orig_isdir
            flat = [' '.join(c) for c in cmds]
            assert any(present_dir in f for f in flat), present_dir
            assert any(right_cmd in f for f in flat), f'{present_dir}: expected {right_cmd}'
            assert not any(wrong_cmd in f for f in flat), f'{present_dir}: wrong {wrong_cmd}'


class TestBrowserTrustStatus(unittest.TestCase):
    '''
    browser_trust_status drives the dashboard's first-run offer: 'untrusted'
    prompts, 'trusted'/'unavailable' stay quiet. Real fakes throughout - a
    scripted run() seam and swapped module attributes, restored in tearDown.
    '''

    PEM = ('-----BEGIN CERTIFICATE-----\n'
           'AAAABBBBCCCC\nDDDD\n'
           '-----END CERTIFICATE-----\n')

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cert = os.path.join(self.tmp, 'localhost.pem')
        with open(self.cert, 'w') as fh:
            fh.write(self.PEM)

        import shutil
        self._orig_dbs = transport._nss_trust_dbs
        self._orig_which = shutil.which
        self._shutil = shutil
        transport._nss_trust_dbs = lambda: ['sql:/fake/nssdb', 'sql:/fake/firefox']
        shutil.which = lambda name: '/usr/bin/certutil' if name == 'certutil' else None

    def tearDown(self):
        transport._nss_trust_dbs = self._orig_dbs
        self._shutil.which = self._orig_which

    class _Result:
        def __init__(self, returncode, stdout=b''):
            self.returncode, self.stdout = returncode, stdout

    def _run_returning(self, per_db):
        ''' Fake subprocess.run: answers by the -d argument, records the calls '''

        calls = []

        def run(cmd, capture_output=False):
            calls.append(cmd)
            db = cmd[cmd.index('-d') + 1]
            return per_db[db]

        return run, calls

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS status is POSIX-only')
    def test_all_stores_current_is_trusted(self):
        run, calls = self._run_returning({
            'sql:/fake/nssdb': self._Result(0, self.PEM.encode()),
            'sql:/fake/firefox': self._Result(0, self.PEM.encode()),
        })
        assert transport.browser_trust_status(self.cert, run=run) == 'trusted'
        assert len(calls) == 2

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS status is POSIX-only')
    def test_missing_in_one_store_is_untrusted(self):
        run, _ = self._run_returning({
            'sql:/fake/nssdb': self._Result(0, self.PEM.encode()),
            'sql:/fake/firefox': self._Result(255),       # nickname not found
        })
        assert transport.browser_trust_status(self.cert, run=run) == 'untrusted'

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS status is POSIX-only')
    def test_stale_cert_in_store_is_untrusted(self):
        ''' A re-minted localhost cert must count as untrusted, not "present" '''

        stale = self.PEM.replace('AAAA', 'ZZZZ')
        run, _ = self._run_returning({
            'sql:/fake/nssdb': self._Result(0, stale.encode()),
            'sql:/fake/firefox': self._Result(0, stale.encode()),
        })
        assert transport.browser_trust_status(self.cert, run=run) == 'untrusted'

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS status is POSIX-only')
    def test_no_stores_is_unavailable(self):
        transport._nss_trust_dbs = lambda: []
        assert transport.browser_trust_status(self.cert) == 'unavailable'

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS status is POSIX-only')
    def test_no_certutil_is_unavailable(self):
        self._shutil.which = lambda name: None
        assert transport.browser_trust_status(self.cert) == 'unavailable'

    def test_pem_body_normalises_whitespace_and_ignores_trailers(self):
        wrapped = ('junk header\n-----BEGIN CERTIFICATE-----\n  AAAABBBBCCCC  \nDDDD\n'
                   '-----END CERTIFICATE-----\ntrailing noise\n')
        assert transport._pem_body(wrapped) == transport._pem_body(self.PEM)
        assert transport._pem_body('no pem here') == ''


class TestInstallBrowserTrust(unittest.TestCase):
    '''
    The self-signed localhost LEAF (basicConstraints CA:FALSE) must be trusted
    as an SSL PEER (certutil 'P,,'), never a CA ('C,,'): Chromium rejects a
    CA:FALSE cert trusted as a CA with ERR_CERT_INVALID. Real certutil roundtrip
    into a throwaway NSS DB - the exact store the dashboard button writes.
    '''

    @unittest.skipIf(sys.platform in ('darwin', 'win32'), 'NSS/certutil path is POSIX-only')
    def test_installs_as_ssl_peer_not_ca(self):
        import shutil, subprocess
        if not shutil.which('certutil'):
            self.skipTest('certutil (nss tools) not installed')

        tmp = tempfile.mkdtemp()
        try:
            cert, _ = transport.ensure_localhost_cert(tmp, bits=1024, announce=False)
            nssdb = os.path.join(tmp, 'nssdb')
            os.makedirs(nssdb)
            subprocess.run(['certutil', '-N', '--empty-password', '-d', f'sql:{nssdb}'],
                           check=True, capture_output=True)

            orig = transport._nss_trust_dbs
            transport._nss_trust_dbs = lambda: [f'sql:{nssdb}']
            try:
                ok, msg = transport.install_browser_trust(cert)
            finally:
                transport._nss_trust_dbs = orig
            assert ok, msg

            listing = subprocess.run(['certutil', '-L', '-d', f'sql:{nssdb}'],
                                     capture_output=True, text=True).stdout
            line = next((l for l in listing.splitlines()
                         if transport._TRUST_NICK in l), '')
            assert line, f'nickname not listed:\n{listing}'
            assert 'P,,' in line, f'expected SSL peer trust, got: {line!r}'
            assert 'C,,' not in line
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestCertFingerprint(unittest.TestCase):
    ''' The fingerprint identifies THIS cert - stable, and changes on regen,
        which is what drives the dashboard's trust re-offer. '''

    def test_stable_and_distinct(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            a, _ = transport.ensure_localhost_cert(d1, bits=1024, announce=False)
            b, _ = transport.ensure_localhost_cert(d2, bits=1024, announce=False)
            fp_a = transport.cert_fingerprint(a)
            assert len(fp_a) == 64                      # sha256 hex
            assert transport.cert_fingerprint(a) == fp_a          # stable
            assert transport.cert_fingerprint(b) != fp_a          # a different cert differs

    def test_missing_cert_is_empty(self):
        assert transport.cert_fingerprint('/no/such/cert.pem') == ''


# Local copy of the DER length helper for the signature test above
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


if __name__ == '__main__':
    unittest.main()
