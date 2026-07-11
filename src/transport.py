import os, sys, socket, secrets, hashlib, shutil, subprocess, time

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from sc_apdu import pad_pkcs1_v15_sha256


# The official BISS daemon listens HTTPS-only on the first free of these ports.
BISS_PORTS = [53952, 53953, 53954, 53955]


# --- Minimal DER encoding (enough to build a self-signed X.509 v3 cert) ---

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _int(i: int) -> bytes:
    body = i.to_bytes((i.bit_length() + 8) // 8 or 1, 'big')  # +8 forces a leading 0 when top bit set
    return _tlv(0x02, body)


def _seq(*parts: bytes) -> bytes: return _tlv(0x30, b''.join(parts))
def _set(*parts: bytes) -> bytes: return _tlv(0x31, b''.join(parts))
def _bitstring(b: bytes) -> bytes: return _tlv(0x03, b'\x00' + b)
def _octet(b: bytes) -> bytes: return _tlv(0x04, b)
def _explicit(tag_num: int, content: bytes) -> bytes: return _tlv(0xA0 | tag_num, content)


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append((p & 0x7F) | 0x80)
            p >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _utctime(t: time.struct_time) -> bytes:
    return _tlv(0x17, time.strftime('%y%m%d%H%M%SZ', t).encode('ascii'))


def _cn(name: str) -> bytes:
    # Name ::= SEQUENCE OF RelativeDistinguishedName; here just CN
    return _seq(_set(_seq(_oid('2.5.4.3'), _tlv(0x0C, name.encode('utf-8')))))


# --- Pure-Python RSA key generation ---

_SMALL_PRIMES = [p for p in range(3, 1000, 2)
                 if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, *_SMALL_PRIMES):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # top + bottom bit set
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_key(bits: int = 2048, e: int = 65537) -> dict:
    ''' Generate an RSA private key. stdlib - no OpenSSL, no dependencies '''

    half = bits // 2
    while True:
        p, q = _gen_prime(half), _gen_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue  # e must be coprime with phi
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(e, -1, phi)
        return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q,
                'dp': d % (p - 1), 'dq': d % (q - 1), 'qinv': pow(q, -1, p)}


def _rsa_private_key_pem(k: dict) -> bytes:
    ''' PKCS#1 RSAPrivateKey, PEM-wrapped ("RSA PRIVATE KEY") '''

    der = _seq(
        _int(0), _int(k['n']), _int(k['e']), _int(k['d']),
        _int(k['p']), _int(k['q']), _int(k['dp']), _int(k['dq']), _int(k['qinv']),
    )
    return _pem('RSA PRIVATE KEY', der)


def _spki(k: dict) -> bytes:
    ''' SubjectPublicKeyInfo for an RSA key '''

    rsa_pub = _seq(_int(k['n']), _int(k['e']))
    alg = _seq(_oid('1.2.840.113549.1.1.1'), _tlv(0x05, b''))  # rsaEncryption, NULL params
    return _seq(alg, _bitstring(rsa_pub))


def _pem(label: str, der: bytes) -> bytes:
    import base64
    b64 = base64.encodebytes(der)
    return f'-----BEGIN {label}-----\n'.encode() + b64 + f'-----END {label}-----\n'.encode()


# --- Self-signed localhost certificate ---

def _san_extension() -> bytes:
    # subjectAltName: DNS:localhost, IP:127.0.0.1
    dns = _tlv(0x82, b'localhost')          # [2] dNSName IA5String
    ip = _tlv(0x87, bytes([127, 0, 0, 1]))  # [7] iPAddress OCTET STRING
    san = _seq(dns, ip)
    return _seq(_oid('2.5.29.17'), _octet(san))


def _extensions() -> bytes:
    basic_constraints = _seq(_oid('2.5.29.19'), _tlv(0x01, b'\xff'), _octet(_seq()))  # critical CA:FALSE
    key_usage = _seq(_oid('2.5.29.15'), _tlv(0x01, b'\xff'),
                     _octet(_bitstring(bytes([0xA0]))))  # digitalSignature + keyEncipherment
    ext_key_usage = _seq(_oid('2.5.29.37'), _octet(_seq(_oid('1.3.6.1.5.5.7.3.1'))))  # serverAuth
    return _explicit(3, _seq(basic_constraints, key_usage, ext_key_usage, _san_extension()))


def build_self_signed_cert(k: dict, cn: str = 'localhost', days: int = 3650) -> bytes:
    ''' Builds and self-signs an X.509 v3 certificate for `cn`. Returns PEM. '''

    now = time.gmtime()
    not_after = time.gmtime(time.time() + days * 86400)
    sig_alg = _seq(_oid('1.2.840.113549.1.1.11'), _tlv(0x05, b''))  # sha256WithRSAEncryption

    tbs = _seq(
        _explicit(0, _int(2)),                         # version v3
        _int(secrets.randbits(64) | 1),                # positive serial
        sig_alg,
        _cn(cn),                                       # issuer
        _seq(_utctime(now), _utctime(not_after)),      # validity
        _cn(cn),                                       # subject
        _spki(k),
        _extensions(),
    )

    signature = pow(int.from_bytes(pad_pkcs1_v15_sha256(hashlib.sha256(tbs).digest(),
                                                        k['n'].bit_length()), 'big'),
                    k['d'], k['n'])
    sig_bytes = signature.to_bytes((k['n'].bit_length() + 7) // 8, 'big')

    cert_der = _seq(tbs, sig_alg, _bitstring(sig_bytes))
    return _pem('CERTIFICATE', cert_der)


def ensure_localhost_cert(cert_dir: str, bits: int = 2048, announce: bool = True) -> tuple[str, str]:
    ''' Generates a self-signed localhost cert on first use if one is not already present '''

    cert_path = os.path.join(cert_dir, 'localhost.pem')
    key_path = os.path.join(cert_dir, 'localhost.key')

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    os.makedirs(cert_dir, exist_ok=True)
    if announce:
        print(f'[*] First run: generating a self-signed {bits}-bit localhost certificate '
              '(pure-Python RSA keygen, this can take a few seconds)...', flush=True)
    t0 = time.time()
    key = generate_rsa_key(bits)
    with open(key_path, 'wb') as f:
        f.write(_rsa_private_key_pem(key))
    os.chmod(key_path, 0o600)
    with open(cert_path, 'wb') as f:
        f.write(build_self_signed_cert(key))
    if announce:
        print(f'[+] Certificate ready in {time.time() - t0:.1f}s: {cert_path}', flush=True)
    
    return cert_path, key_path


# --- Port selection ---

def pick_free_port(ports: list = None, host: str = '127.0.0.1') -> int:
    ''' Return the first bindable port from the list (BISS ports by default) '''

    for port in (ports or BISS_PORTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue

    raise OSError(f'No free port among {ports or BISS_PORTS}')


# --- Trust-store integration (consent-gated) ---

def trust_instructions(cert_path: str) -> list:
    '''
    Per-OS command(s) that add our localhost cert to the system trust store so
    browsers accept the HTTPS daemon
    '''

    if sys.platform == 'win32':
        return [['certutil', '-addstore', '-user', 'Root', cert_path]]
    elif sys.platform == 'darwin':
        return [['security', 'add-trusted-cert', '-d', '-r', 'trustRoot',
                 '-k', os.path.expanduser('~/Library/Keychains/login.keychain-db'), cert_path]]

    linux_stores = [
        ('/usr/local/share/ca-certificates', ['update-ca-certificates']),        # Debian / Ubuntu
        ('/etc/pki/ca-trust/source/anchors', ['update-ca-trust']),               # RHEL / Fedora
        ('/etc/ca-certificates/trust-source/anchors', ['trust', 'extract-compat']),  # Arch
    ]
    for anchor_dir, update_cmd in linux_stores:
        if os.path.isdir(anchor_dir):
            dest = os.path.join(anchor_dir, 'pybiss-localhost.crt')
            return [['sudo', 'cp', cert_path, dest], ['sudo', *update_cmd]]

    # Fallback: p11-kit's one-shot anchor (no manual dir needed)
    if shutil.which('trust'):
        return [['sudo', 'trust', 'anchor', '--store', cert_path]]

    raise OSError('Unsupported Linux trust store: no known anchor directory or `trust` tool found. '
                  'Note: Firefox keeps its own NSS store and must be trusted separately '
                  '(certutil -d sql:~/.mozilla/firefox/<profile> -A ...).')


def install_trust_anchor(cert_path: str, assume_yes: bool = False) -> bool:
    ''' Install the localhost cert into the OS trust store after the user consents '''

    commands = trust_instructions(cert_path)
    print('The following command(s) will add the pybiss localhost certificate '
          'to your trust store so the browser accepts the local HTTPS service:')
    for cmd in commands:
        print('   ', ' '.join(cmd))

    if not assume_yes:
        try:
            answer = input('Proceed? [y/N] ').strip().lower()
        except EOFError:
            answer = 'n'
        if answer not in ('y', 'yes'):
            print('Trust-store install skipped.')
            return False

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            print(f'[!] Command failed ({" ".join(cmd)}): {e}')
            return False
    return True
