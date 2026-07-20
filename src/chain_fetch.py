import hashlib, urllib.request, urllib.error
from pathlib import Path

from .cert_parser import DerReader, get_x509_metadata, pem_to_der


_AIA_EXT_OID = '1.3.6.1.5.5.7.1.1'                 # authorityInfoAccess extension
_CA_ISSUERS_METHOD = bytes.fromhex('2b06010505073002')  # OID body 1.3.6.1.5.5.7.48.2
_URI_TAG = 0x86                                    # GeneralName [6] IA5String


def ca_issuer_urls(cert_der: bytes) -> list[str]:
    ''' Every AIA caIssuers URI in a certificate, in order '''

    try:
        ext = get_x509_metadata(cert_der).get('extensions', {}).get(_AIA_EXT_OID)
    except Exception:
        return []
    if not ext:
        return []

    urls = []
    try:
        descriptions = DerReader(ext).read_seq()   # SEQUENCE OF AccessDescription
        while not descriptions.is_empty():
            ad = DerReader(descriptions.read_tlv()[1])
            method = ad.read_tlv()[1]               # accessMethod OID body
            tag, location = ad.read_tlv()           # accessLocation GeneralName
            if method == _CA_ISSUERS_METHOD and tag == _URI_TAG:
                urls.append(location.decode('latin1'))
    except (ValueError, IndexError):
        pass
    return urls


def _http_get(url: str, timeout: float) -> bytes | None:
    ''' GET with TLS validated (urllib default). None on any failure '''

    if not url.lower().startswith(('http://', 'https://')):
        return None                                 # no ldap://, no file://
    req = urllib.request.Request(url, headers={'User-Agent': 'pybiss'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(1 << 20)               # a CA cert is a few KB; cap at 1 MiB
    except (urllib.error.URLError, OSError, ValueError):
        return None


def fetch_issuer_cert(url: str, timeout: float = 10, *, http_get=None) -> bytes | None:
    ''' Fetch and return one issuer certificate as DER '''

    body = (http_get or _http_get)(url, timeout)
    if not body:
        return None
    for der in pem_to_der(body):                    # PEM -> DER, or [body] if already DER
        if der[:1] == b'\x30':                      # a DER SEQUENCE, i.e. a real cert
            return der
    return None


def make_aia_resolver(cache_dir, timeout: float = 10, *, fetcher=None):
    ''' Build resolver(cert_der). Tests inject a fake to exercise the cache logic without a socket '''

    cache = Path(cache_dir)
    fetch = fetcher or (lambda url: fetch_issuer_cert(url, timeout))

    def resolver(cert_der: bytes) -> bytes | None:
        for url in ca_issuer_urls(cert_der):
            path = cache / (hashlib.sha256(url.encode()).hexdigest()[:24] + '.der')
            if path.exists():
                try:
                    der = path.read_bytes()
                    if der[:1] == b'\x30':
                        return der
                except OSError:
                    pass
            der = fetch(url)
            if der:
                try:
                    cache.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(der)
                except OSError:
                    pass                            # cache is best-effort
                return der
        return None

    return resolver
