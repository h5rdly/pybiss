import struct, zlib

from x509_helpers import build_cert, full_name, TEST_N, TEST_E, TEST_D
from src.sc_apdu import pad_pkcs1_v15_sha256


# A B-Trust-style ATR (any IDPrime ATR routes to IDPrimeDriver)
DEFAULT_ATR = bytes.fromhex('3B7F96000080318065B085050039120FFE829000')


# --- MiniDriver byte-structure builders ------------------------------------

def _index_record(file_id: bytes, length: int, name: str) -> bytes:
    return file_id + struct.pack('<H', length) + name.encode('ascii').ljust(17, b'\x00')


def _index_blob(records) -> bytes:
    return bytes([len(records)]) + b''.join(records)


def minidriver_cert(der: bytes) -> bytes:
    ''' Wrap a DER cert the way an IDPrime file stores it: 01 00 <u16 len> zlib '''

    return b'\x01\x00' + struct.pack('<H', len(der)) + zlib.compress(der)


def keyref_record(index: int, key_ref: int, pin_index: int = 1) -> bytes:
    ''' One 8-byte EF 0005 record: [flag][key_ref][index]..[pin_index@7] '''

    rec = bytearray(8)
    rec[0] = 0x01           # occupied slot
    rec[1] = key_ref
    rec[2] = index
    rec[7] = pin_index
    return bytes(rec)


# --- identity certificate ---------------------------------------------------

def make_identity_cert(name: str = 'Test User', *, email: str = None,
                       personal_id: str = None, country: str = 'BG',
                       given_name: str = None, surname: str = None,
                       serial: int = 1, not_after: str = '400101000000Z',
                       n: int = TEST_N, e: int = TEST_E) -> bytes:
    '''
    A DER certificate with a realistic multi-field subject built from fake
    identity data (no PII). The public key is the throwaway test key so the
    synthetic card can produce verifiable signatures.
    '''

    subject = full_name(country=country, common_name=name,
                        serial_number=personal_id, given_name=given_name,
                        surname=surname, email=email)
    return build_cert(cn=name, subject=subject, serial=serial,
                      not_after=not_after, n=n, e=e)


# --- the card ---------------------------------------------------------------

class SyntheticIDPrimeCard:
    '''
    Serves the IDPrime MiniDriver structure for one certificate and signs for
    real with its key. Doubles as its own context manager + card lock, so it is
    a drop-in for SmartCardConnection (app._open_card can return it directly).
    '''

    def __init__(self, cert_der: bytes, *, key=(TEST_N, TEST_E, TEST_D),
                 key_ref: int = 0x54, pin_index: int = 1, container: int = 0,
                 atr: bytes = DEFAULT_ATR):
        self._n, self._e, self._d = key
        self.cert_der = cert_der
        self.key_ref = key_ref
        self.atr = atr
        self._sel = None
        self._pending_hash = b''

        cert_fid = bytes([0x02, 0x08 + container])
        self.files = {
            b'\x01\x01': _index_blob([
                _index_record(bytes([0x02, 0x07 + container]), 7426, f'priprk{container:02d}p11'),
                _index_record(cert_fid, len(cert_der), f'kxc{container:02d}mscp'),
                _index_record(bytes([0x02, 0x09 + container]), 514, f'pubkxc{container:02d}p11'),
            ]),
            cert_fid: minidriver_cert(cert_der),
            b'\x00\x05': keyref_record(container, key_ref, pin_index),
        }

    # SmartCardConnection surface
    def __enter__(self): return self
    def __exit__(self, *exc): return False
    def transaction(self): return self
    def get_atr(self): return self.atr

    def transmit(self, apdu):
        apdu = bytes(apdu)
        if apdu[:2] == b'\x00\xa4':                       # SELECT
            self._sel = apdu[5:5+apdu[4]] if apdu[2] == 0x00 else None
            return b'\x90\x00'
        if apdu[:2] == b'\x00\xb0':                       # READ BINARY
            content = self.files.get(self._sel, b'')
            off = (apdu[2] << 8) | apdu[3]
            return content[off:off+255] + b'\x90\x00' if off < len(content) else b'\x62\x82'
        if apdu[1] == 0x20:                               # VERIFY
            return b'\x90\x00'
        if apdu[:2] == b'\x00\x22':                       # MSE
            return b'\x90\x00'
        if apdu[:4] == b'\x00\x2a\x90\xa0':               # hash input -> echo
            self._pending_hash = apdu[7:7+apdu[6]]
            return self._pending_hash + b'\x90\x00'
        if apdu[:4] == b'\x00\x2a\x9e\x9a':               # compute -> real RSA sig
            block = pad_pkcs1_v15_sha256(self._pending_hash, self._n.bit_length())
            k = (self._n.bit_length() + 7) // 8
            sig = pow(int.from_bytes(block, 'big'), self._d, self._n).to_bytes(k, 'big')
            return sig + b'\x90\x00'
        return b'\x90\x00'


def synthetic_idprime_card(name: str = 'Test User', **identity) -> SyntheticIDPrimeCard:
    '''
    One call to a ready synthetic card. Identity kwargs (email, personal_id,
    country, given_name, surname, serial) flow into the certificate; card kwargs
    (key_ref, pin_index, container, atr) tune the MiniDriver layout.
    '''

    card_keys = ('key', 'key_ref', 'pin_index', 'container', 'atr')
    card_opts = {k: identity.pop(k) for k in card_keys if k in identity}
    key = card_opts.get('key', (TEST_N, TEST_E, TEST_D))
    cert = make_identity_cert(name, n=key[0], e=key[1], **identity)
    return SyntheticIDPrimeCard(cert, **card_opts)
