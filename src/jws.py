import base64, json, sys, time


from .cert_parser import DerReader, parse_certificate
from .verifier import verify_rsa_pkcs1_v1_5


# B-Trust operational CA (ACA) subject key identifiers. The certificate
# carried in the JWS x5c header must be issued by one of these CAs.
ACA_KEY_IDENTIFIERS = {
    '07DCAA307698B7854B6D0318C8E3CDA77B3682EF',   # production ACA
    'F527CCF7DB9B28942B9B66F029720E8A3D62DC98',   # test ACA
}

# Borica private certificate extensions carrying the authorization strings
OID_RENEW_FUNCTIONS = '1.3.6.1.4.1.15862.100'
OID_ADMIN_FUNCTIONS = '1.3.6.1.4.1.15862.200'
RENEW_MARKER = 'BISS ENABLE RENEW FUNCTIONS'
ADMIN_MARKER = 'BISS ENABLE ADMINISTRATIVE FUNCTIONS'

# RSASSA-PKCS1-v1_5 only. 'none' and the HS* (HMAC) family are rejected
# outright - accepting them enables classic JWS forgery attacks.
ALLOWED_ALGS = {'RS256': 'SHA256', 'RS384': 'SHA384', 'RS512': 'SHA512'}


class JwsError(Exception):
    pass


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


def parse_compact(jws: str):
    '''
    Splits a compact JWS into (header dict, payload bytes, signing input, signature).
    The signing input is the raw base64url segments as received - the signature
    covers those bytes, never a re-serialization.
    '''

    try:
        head_b64, payload_b64, sig_b64 = jws.split('.')
        header = json.loads(_b64url_decode(head_b64))
        payload = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except Exception:
        raise JwsError('Malformed JWS: expected header.payload.signature (base64url)')

    signing_input = f'{head_b64}.{payload_b64}'.encode('ascii')
    return header, payload, signing_input, signature


def _extension_text(cert: dict, oid: str) -> str:
    ''' Decodes a certificate extension value that wraps a DER string '''

    raw = cert.get('extensions', {}).get(oid)
    if not raw:
        return ''
    try:
        return DerReader(raw).read_tlv()[1].decode('utf-8', errors='ignore')
    except Exception:
        return raw.decode('utf-8', errors='ignore')


def verify(jws_data: str, admin_required: bool = False) -> dict:
    '''
    Verifies a BISS jwsData request and returns its decoded JSON payload.

    Checks, in order: pinned algorithm, RSASSA signature against the x5c
    certificate, certificate validity window, issuing CA (pinned B-Trust
    ACA key identifiers), and the Borica authorization extensions
    (admin always passes; renew passes unless admin_required).
    '''

    header, payload, signing_input, signature = parse_compact(jws_data)

    alg = header.get('alg')
    if alg not in ALLOWED_ALGS:
        raise JwsError(f'Disallowed JWS algorithm: {alg}')

    x5c = header.get('x5c') or []
    if not x5c:
        raise JwsError('JWS header carries no x5c certificate')
    try:
        # x5c entries are standard base64 (not base64url) DER
        cert = parse_certificate(base64.b64decode(x5c[0]))
    except Exception:
        raise JwsError('JWS x5c certificate could not be parsed')

    if cert.get('key_type') != 'RSA':
        raise JwsError('JWS certificate does not carry an RSA key')

    if not verify_rsa_pkcs1_v1_5(signing_input, signature, cert['n'], cert['e'], ALLOWED_ALGS[alg]):
        raise JwsError('JWS signature verification failed')

    now = int(time.time())
    if not cert.get('not_before', 0) <= now <= cert.get('not_after', 0):
        raise JwsError('JWS certificate is expired or not yet valid')

    if cert.get('aki', '').upper() not in ACA_KEY_IDENTIFIERS:
        raise JwsError('JWS certificate is not issued by a known B-Trust CA')

    is_admin = ADMIN_MARKER in _extension_text(cert, OID_ADMIN_FUNCTIONS)
    is_renew = RENEW_MARKER in _extension_text(cert, OID_RENEW_FUNCTIONS)
    if not (is_admin or (is_renew and not admin_required)):
        raise JwsError('JWS certificate lacks the required BISS authorization')

    try:
        return json.loads(payload)
    except Exception:
        raise JwsError('JWS payload is not valid JSON')
