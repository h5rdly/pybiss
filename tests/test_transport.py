import asyncio, os, socket, ssl, sys, tempfile, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import transport
from src.cert_parser import parse_certificate, pem_to_der


class TestRsaKeyGen(unittest.TestCase):

    def test_generated_key_is_mathematically_consistent(self):
        k = transport.generate_rsa_key(bits=1024)
        self.assertEqual(k['n'], k['p'] * k['q'])
        self.assertEqual(k['n'].bit_length(), 1024)
        # e·d ≡ 1 (mod λ) -> sign/verify round-trips any message
        m = 0x1234567890ABCDEF
        self.assertEqual(pow(pow(m, k['d'], k['n']), k['e'], k['n']), m)

    def test_crt_parameters_correct(self):
        k = transport.generate_rsa_key(bits=1024)
        self.assertEqual(k['dp'], k['d'] % (k['p'] - 1))
        self.assertEqual(k['dq'], k['d'] % (k['q'] - 1))
        self.assertEqual((k['qinv'] * k['q']) % k['p'], 1)


class TestSelfSignedCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = transport.generate_rsa_key(bits=1024)
        cls.cert_pem = transport.build_self_signed_cert(cls.key, cn='localhost')

    def test_cert_parses_with_our_own_parser(self):
        der = pem_to_der(self.cert_pem)[0]
        meta = parse_certificate(der)
        self.assertIn('CN=localhost', meta['subject'])
        self.assertIn('CN=localhost', meta['issuer'])
        self.assertEqual(meta['key_type'], 'RSA')
        # SubjectAltName present (browsers require it)
        self.assertIn('2.5.29.17', meta['extensions'])

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
        self.assertEqual(em, expected)


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

            self.assertEqual(data, b'hello-tls')


class TestEnsureCert(unittest.TestCase):

    def test_reuses_existing_cert(self):
        with tempfile.TemporaryDirectory() as d:
            c1, k1 = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            mtime = os.path.getmtime(c1)
            c2, k2 = transport.ensure_localhost_cert(d, bits=1024, announce=False)  # must not regenerate
            self.assertEqual((c1, k1), (c2, k2))
            self.assertEqual(os.path.getmtime(c2), mtime)

    def test_key_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            _, key_path = transport.ensure_localhost_cert(d, bits=1024, announce=False)
            if os.name != 'nt':
                self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)


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
            self.assertEqual(transport.pick_free_port([taken, free]), free)

    def test_raises_when_none_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            taken = occupied.getsockname()[1]
            with self.assertRaises(OSError):
                transport.pick_free_port([taken])


class TestTrustInstructions(unittest.TestCase):

    def test_returns_platform_commands(self):
        cmds = transport.trust_instructions('/tmp/localhost.pem')
        self.assertTrue(cmds and all(isinstance(c, list) for c in cmds))
        self.assertTrue(any('/tmp/localhost.pem' in ' '.join(c) for c in cmds))


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
            self.assertTrue(any(present_dir in f for f in flat), present_dir)
            self.assertTrue(any(right_cmd in f for f in flat), f'{present_dir}: expected {right_cmd}')
            self.assertFalse(any(wrong_cmd in f for f in flat), f'{present_dir}: wrong {wrong_cmd}')


# Local copy of the DER length helper for the signature test above
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


if __name__ == '__main__':
    unittest.main()
