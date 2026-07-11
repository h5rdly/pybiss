'''
Minimal DER / X.509 synthesizer for tests.

Builds just enough of a certificate for src.cert_parser.parse_certificate:
serial, issuer/subject names, validity, RSA SPKI, and extensions
(AKI, SKI, and arbitrary OID -> text extensions).
'''

import base64, hashlib, json, sys

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.sc_apdu import pad_pkcs1_v15_sha256


# Throwaway 2048-bit RSA key, generated for tests only
TEST_N = 0x9f21b0bebdc48d1dc890f01279f44f8d23dea3f862df25c5707cc5200f4063505e9c14ee3eecf1abb293540b6af2d9d0f7c48a172e9a0cc9aa8e78997e7cd4285ea1dc5e902457242f26a56ebf17fd478c904bd1da8a13b35cd64059ef438884fb607b12eff6d00f9fa94dfffa327b2ad6de491b0dc7b13d0ddbc8d0bc7fd47c7f7e4cfde9edf5b2e9e1842f54deb23227ba181c9deadc44d7db2be2c96cde5370be45a18951e1658a10bb739c109ca3bc331630c32d5eb55b33e4e52d1074ec55ec20043598a6857be8f705d15f79a8e8dcf8737cd7fa1168dd2a9928539f2b8b5728846d9b1c6c6ab09aabf825c72f148cc3dca7faa93adfab547434c57f5f
TEST_E = 65537
TEST_D = 0x1142a1bda6aebd91b7f204a0346b2bffc69ebd1151841bc03529cb65e5519a141b16f9ec379612c689599299a4718fefab183dd432e151b6c411ad021526ac0a6eed468e593b1fda9464b037f9713c2f390f63b1f0eede212bd62f67b1dc94dfbbb664d31285265f3375b538a9263596d97485e071d7b1a14a32072fa0ea8a9d048b85ea69573469050c0e570555763a1d5544fa2ea5cae29f2c913f489bb6e5dd6f7ffee8c53ccc2be0fd014291eb08461a62b431f4a6e87009e666f3c90cc1c6490c99f2b9fa3a7ccfabd221e54ddde6eda1b2c3fe2e257c201e04e7c5b1eff47c40171e5efd1ca09dfff3c46424a559742c8ef0ef4b80d4d27b7cd2ed92f5


# --- DER primitives ---

def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFF:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82]) + n.to_bytes(2, 'big')
    return bytes([tag]) + length + content


def seq(*parts: bytes) -> bytes: return tlv(0x30, b''.join(parts))
def octet(b: bytes) -> bytes: return tlv(0x04, b)
def utf8(s: str) -> bytes: return tlv(0x0C, s.encode('utf-8'))
def utctime(s: str) -> bytes: return tlv(0x17, s.encode('ascii'))
def bitstring(b: bytes) -> bytes: return tlv(0x03, b'\x00' + b)


def integer(i: int) -> bytes:
    # +8 bits guarantees a leading zero byte when the high bit is set
    return tlv(0x02, i.to_bytes((i.bit_length() + 8) // 8 or 1, 'big'))


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append((p & 0x7F) | 0x80)
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def name(cn: str) -> bytes:
    return seq(tlv(0x31, seq(oid('2.5.4.3'), utf8(cn))))


# --- Certificate builder ---

def build_cert(n: int = TEST_N, e: int = TEST_E, cn: str = 'Test', aki: str = None,
               ski: str = None, ext_texts: dict = None,
               not_before: str = '250101000000Z', not_after: str = '400101000000Z') -> bytes:
    '''
    Returns a DER certificate. aki/ski are hex key identifiers;
    ext_texts maps dotted OIDs to UTF8String extension payloads.
    '''

    exts = []
    if aki:
        exts.append(seq(oid('2.5.29.35'), octet(seq(tlv(0x80, bytes.fromhex(aki))))))
    if ski:
        exts.append(seq(oid('2.5.29.14'), octet(octet(bytes.fromhex(ski)))))
    for o, text in (ext_texts or {}).items():
        exts.append(seq(oid(o), octet(utf8(text))))

    rsa_alg = seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, b''))
    spki = seq(
        seq(oid('1.2.840.113549.1.1.1'), tlv(0x05, b'')),
        bitstring(seq(integer(n), integer(e))),
    )

    tbs = seq(
        integer(1),                                    # serial
        rsa_alg,                                       # signature algorithm
        name(cn + ' Issuer'),
        seq(utctime(not_before), utctime(not_after)),  # validity
        name(cn),
        spki,
        tlv(0xA3, seq(*exts)) if exts else b'',
    )
    # Signature value is a placeholder - pybiss pins issuers by key identifier
    return seq(tbs, rsa_alg, bitstring(b'\x00'))


# --- JWS crafting ---

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def make_jws(payload: dict, cert_der: bytes, alg: str = 'RS256',
             d: int = TEST_D, n: int = TEST_N, tamper: bool = False) -> str:
    ''' Builds a compact JWS signed with the test RSA key (RS256 semantics) '''

    header = {'alg': alg, 'x5c': [base64.b64encode(cert_der).decode('ascii')]}
    h64 = b64url(json.dumps(header).encode('utf-8'))
    p64 = b64url(json.dumps(payload).encode('utf-8'))

    digest = hashlib.sha256(f'{h64}.{p64}'.encode('ascii')).digest()
    block = pad_pkcs1_v15_sha256(digest, 2048)
    signature = pow(int.from_bytes(block, 'big'), d, n).to_bytes(256, 'big')

    if tamper:
        p64 = b64url(json.dumps(payload | {'evil': True}).encode('utf-8'))

    return f'{h64}.{p64}.{b64url(signature)}'
