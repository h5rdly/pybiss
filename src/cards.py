import sys, zlib

from .sc_types import SCARDHANDLE
from .sc_ffi import SmartCardConnection
from .sc_apdu import pad_pkcs1_v15_sha256, read_binary_file, build_apdu, decode_ecdsa_signature, ber_tlv
from .pkcs15 import parse_pkcs15_filesystem, encode_pkcs15_pin


# --- Known ATRs for the card families B-Trust issues ---
IDPRIME_ATRS = [
    '3B7F96000080318065B0850300EF120FFE829000', # IDPrime 840
    '3B7F96000080318065B0855956FB120FFE829000', # IDPrime 940
    '3BFF9600008131FE4380318065B0855956FB120FFE82900000', # IDPrime MD 940
    '3B7F96000080318065B085050039120FFE829000', # IDPrime (B-Trust QES, MiniDriver)
]


# --- IDPrime MiniDriver object model (pure helpers, hardware-free) ---
'''
IDPrime cards store objects in a Microsoft MiniDriver container model. 
Under the applet, EF 0101 is an index: one length byte giving the entry count, 
then fixed 21-byte records of [fileID:2][length:2 LE][name: printable ASCII, 
NUL-padded]. Certificates live in the 'kxc##mscp' (key-exchange) and 'ksc##mscp' 
(signing) files; the 'pub*p11' entries are PKCS#11 helper blobs, not certs.
'''

_MINIDRIVER_INDEX_EF = b'\x01\x01'


def parse_minidriver_index(raw: bytes) -> list[dict]:
    ''' Parse EF 0101 into [{'file_id': b'..', 'length': int, 'name': str}] '''

    if not raw:
        return []
    count = raw[0]
    entries = []
    for i in range(count):
        rec = raw[1 + i * 21 : 1 + (i + 1) * 21]
        if len(rec) < 21:
            break
        name = bytes(c for c in rec[4:] if 32 <= c < 127).decode('ascii', 'replace').strip()
        entries.append({
            'file_id': bytes(rec[0:2]),
            'length': int.from_bytes(rec[2:4], 'little'),
            'name': name,
        })
    return entries


def is_certificate_entry(name: str) -> bool:
    ''' A MiniDriver index name that holds an actual X.509 (kxc/ksc, not pub*) '''

    return name.startswith(('kxc', 'ksc')) and 'mscp' in name


def decompress_minidriver_cert(raw: bytes) -> bytes:
    '''
    Unwrap a MiniDriver certificate file to raw DER. The stored form is
    01 00 <uncompressed_len: u16 LE> <zlib stream>; anything already starting
    with a DER SEQUENCE (0x30) is returned as-is.
    '''

    if len(raw) >= 4 and raw[0] == 0x01 and raw[1] == 0x00:
        der = zlib.decompress(raw[4:])
        expected = int.from_bytes(raw[2:4], 'little')
        if expected and len(der) != expected:
            raise ValueError(f'MiniDriver cert length mismatch: '
                             f'header {expected}, got {len(der)}')
        return der
    return raw

CARDOS_ATRS = [
    '3BD218008131FE58C90114', # CardOS V5.0
    '3BD218008131FE58C90217', # CardOS V5.3
    '3BD218008131FE58C90316', # CardOS V5.3
    '3BF81300008131FE454A434F5076323431B7', # Cryptovision
]

ASEPCOS_ATRS = [
    '3BFF1800008131FE55006B02090603010101434E5310318067',
    '3BD6180081B1FE7D1F0341534537353501',
]

IASECC_ATRS = [
    '3BDD96008131FE4580F9A00000007701080007900070',
    '3B7F9600000031B8644070141073940180829000',
]

SCHSM_ATRS = [
    '3BFE1800008131FE458031815448534D31738021408107FA',
    '3BF81300008131FE454A434F5076323431B7', # Cryptovision
]


class BaseCardDriver:
    ''' Abstract base class for B-Trust smart cards '''

    def __init__(self, connection: SmartCardConnection):
        self.conn = connection

    def verify_pin(self, pin: str, pin_ref: int = 0x81, pin_info: dict = None):
        ''' Standard ISO 7816-4 PIN Verification '''

        if pin_info and pin_info.get('pin_ref') is not None:
            pin_ref = pin_info['pin_ref']
        pin_bytes = encode_pkcs15_pin(pin, pin_info)
        # CLA=00, INS=20 (Verify), P1=00, P2=pin_ref, Lc=len(padded PIN)
        apdu = bytes([0x00, 0x20, 0x00, pin_ref, len(pin_bytes)]) + pin_bytes
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] == b'\x90\x00':
            return True
        elif resp[-2] == 0x63:
            retries = resp[-1] & 0x0F
            raise Exception(f'Incorrect PIN. {retries} retries remaining.')
        elif resp[-2:] == b'\x69\x83':
            raise Exception('Smart card is blocked!')
        else:
            raise Exception(f'PIN Verification failed: {resp[-2:].hex().upper()}')


    def change_pin(self, old_pin: str, new_pin: str, pin_ref: int = 0x81, pin_info: dict = None):
        ''' Standard ISO 7816-4 Change Reference Data (Change PIN) '''

        if pin_info and pin_info.get('pin_ref') is not None:
            pin_ref = pin_info['pin_ref']
        # Old and new PINs encoded per the card's PinAttributes, concatenated
        payload = encode_pkcs15_pin(old_pin, pin_info) + encode_pkcs15_pin(new_pin, pin_info)
        
        # CLA=00, INS=24 (Change), P1=00, P2=pin_ref, Data=payload
        apdu = build_apdu(0x00, 0x24, 0x00, pin_ref, data=payload)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'PIN Change failed: {resp[-2:].hex().upper()}')
        return True


    def unblock_pin(self, puk: str, new_pin: str, pin_ref: int = 0x81, pin_info: dict = None):
        ''' Standard ISO 7816-4 Reset Retry Counter (Unblock with PUK) '''

        if pin_info and pin_info.get('pin_ref') is not None:
            pin_ref = pin_info['pin_ref']
        # PUK and New PIN encoded per the card's PinAttributes, concatenated
        payload = encode_pkcs15_pin(puk, pin_info) + encode_pkcs15_pin(new_pin, pin_info)
        
        # CLA=00, INS=2C (Reset Retry Counter), P1=00, P2=pin_ref, Data=payload
        apdu = build_apdu(0x00, 0x2C, 0x00, pin_ref, data=payload)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'PIN Unblock failed: {resp[-2:].hex().upper()}')
        return True


    def discover_certificates(self) -> list[dict]:
        '''
        Dynamically traverses the PKCS#15 file structure natively 
        to find all certificates without relying on PKCS#11.
        '''
        
        # Ensure we are inside the PKCS#15 directory structure
        self.select_applet()
        
        # Let the ASN.1 explorer crawl the card
        fs_map = parse_pkcs15_filesystem(self.conn)
        
        return fs_map.get('certificates', [])


    def set_security_environment(self, key_id: int, is_ecdsa: bool = False):
        raise NotImplementedError

    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        raise NotImplementedError


class BTrustDriver:
    ''' Factory class to instantiate the correct hardware driver '''

    @staticmethod
    def create(connection: SmartCardConnection) -> BaseCardDriver:
        atr = connection.get_atr().hex().upper()

        families = [
            (IDPRIME_ATRS, IDPrimeDriver),
            (CARDOS_ATRS, CardOSDriver),
            (ASEPCOS_ATRS, AsepcosDriver),
            (IASECC_ATRS, IasEccDriver),
            (SCHSM_ATRS, ScHsmDriver),
        ]
        candidates = [cls for atrs, cls in families if any(a in atr for a in atrs)]

        if not candidates:
            raise Exception(f'Unsupported Smart Card ATR: {atr}')
        if len(candidates) == 1:
            return candidates[0](connection)

        # Ambiguous ATR (the Cryptovision JCOP chip carries either a CardOS-style
        # or an SC-HSM profile): probe by applet selection, most specific first.
        # CardOS goes last - selecting the Master File succeeds on almost any card.
        probe_order = [ScHsmDriver, AsepcosDriver, IDPrimeDriver, IasEccDriver, CardOSDriver]
        for cls in sorted(candidates, key=probe_order.index):
            driver = cls(connection)
            try:
                driver.select_applet()
                return driver
            except Exception:
                continue

        raise Exception(f'No driver could select its applet for ATR: {atr}')


class IDPrimeDriver(BaseCardDriver):
    ''' Gemalto IDPrime Implementation '''

    def __init__(self, connection: SmartCardConnection):
        self.conn = connection

    def select_applet(self):

        # Gemalto IDPrime applet AID
        aid = bytes.fromhex('A000000018800000000662')
        apdu = b'\x00\xA4\x04\x00' + bytes([len(aid)]) + aid
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception('Failed to select IDPrime Applet')


    # IDPrime PIN references: 0x11 user, 0x83 signature. The user PIN is padded  16 
    # btoytes with 0x00 - an unpadded PIN is rejected 6700 (wrong length) BEFORE the 
    # counter is touched. Validated live on a B-Trust QES token.
    PIN_REF_USER = 0x11
    PIN_REF_SIGNATURE = 0x83
    _PIN_STORED_LENGTH = 16
    _PIN_PAD_CHAR = 0x00

    def get_pin_tries(self, pin_ref: int = PIN_REF_USER) -> int:
        '''
        Remaining attempts for a PIN, queried WITHOUT spending one: a case-1
        VERIFY (no data) returns ISO 63 CX where X is the counter, and the card
        does not decrement. Returns -1 if the PIN reports already-verified.
        '''

        self.select_applet()
        sw = self.conn.transmit(bytes([0x00, 0x20, 0x00, pin_ref]))[-2:]
        if sw[0] == 0x63 and (sw[1] & 0xF0) == 0xC0:
            return sw[1] & 0x0F
        if sw == b'\x90\x00':
            return -1
        raise Exception(f'PIN tries query failed for ref 0x{pin_ref:02X}: {sw.hex()}')

    def verify_pin(self, pin: str, pin_ref: int = PIN_REF_USER, pin_info: dict = None):
        ''' IDPrime user-PIN verify: reference 0x11, PIN padded to 16 bytes with
            0x00 (the documented MiniDriver encoding). '''

        if pin_info and pin_info.get('pin_ref') is not None:
            pin_ref = pin_info['pin_ref']
        self.select_applet()

        pin_bytes = pin.encode('ascii')
        if len(pin_bytes) > self._PIN_STORED_LENGTH:
            raise ValueError(f'IDPrime PIN longer than {self._PIN_STORED_LENGTH} bytes')
        padded = pin_bytes + bytes([self._PIN_PAD_CHAR]) * (self._PIN_STORED_LENGTH - len(pin_bytes))

        sw = self.conn.transmit(bytes([0x00, 0x20, 0x00, pin_ref, len(padded)]) + padded)[-2:]
        if sw == b'\x90\x00':
            return True
        if sw[0] == 0x63 and (sw[1] & 0xF0) == 0xC0:
            raise Exception(f'Incorrect PIN. {sw[1] & 0x0F} tries remaining.')
        if sw == b'\x69\x83':
            raise Exception('Smart card is blocked!')
        raise Exception(f'PIN verification failed: {sw.hex().upper()}')

    def _select_ef(self, file_id: bytes):
        ''' SELECT an EF by file-id under the applet. Accepts 9000 and 61xx
            (T=0 "FCI available"); READ BINARY works from either. '''

        resp = self.conn.transmit(b'\x00\xA4\x00\x00\x02' + file_id)
        if resp[-2] not in (0x90, 0x61):
            raise Exception(f'select EF {file_id.hex()} failed: {resp[-2:].hex()}')


    def _read_ef(self, file_id: bytes) -> bytes:
        ''' Select an EF and READ BINARY it fully (multi-block, T=0 6Cxx aware) '''

        self._select_ef(file_id)
        data = bytearray()
        offset = 0
        while offset < 0x10000:
            p1, p2 = (offset >> 8) & 0xFF, offset & 0xFF
            resp = self.conn.transmit(bytes([0x00, 0xB0, p1, p2, 0x00]))
            sw, chunk = resp[-2:], resp[:-2]
            if sw == b'\x90\x00':
                if not chunk:
                    break
                data += chunk
                offset += len(chunk)
            elif sw[0] == 0x6C:                       # exact length in sw[1]
                resp = self.conn.transmit(bytes([0x00, 0xB0, p1, p2, sw[1]]))
                data += resp[:-2]
                break
            else:                                     # 6B00 / 6282 = end of file
                data += chunk
                break
        return bytes(data)


    def _transmit_chained(self, apdu: bytes) -> bytes:
        ''' transmit resolving T=0 61xx (GET RESPONSE) and 6Cxx (retry Le), so
            large signatures come back whole over PC/SC as well as direct CCID '''

        resp = self.conn.transmit(apdu)
        data = b''
        while len(resp) >= 2 and resp[-2] in (0x61, 0x6C):
            if resp[-2] == 0x61:
                data += resp[:-2]
                resp = self.conn.transmit(bytes([0x00, 0xC0, 0x00, 0x00, resp[-1]]))
            else:
                resp = self.conn.transmit(bytes(apdu[:4]) + bytes([resp[-1]]))
        return data + resp


    def read_keyref_map(self) -> dict:
        '''
        Map container index -> {'key_ref', 'pin_index'} from the IDPrime key
        reference file (EF 0005; 8-byte records [flag][key_ref][index]..[pin]).
        Empty on cards that lack the file (the key ref is then formula-derived).
        Validated live: container 0 -> key_ref 0x54, pin_index 1 (user PIN).
        '''

        try:
            raw = self._read_ef(b'\x00\x05')
        except Exception:
            return {}
        out = {}
        for i in range(0, (len(raw) // 8) * 8, 8):
            rec = raw[i:i+8]
            if rec[0] == 0:                    # empty slot
                continue
            out[rec[2]] = {'key_ref': rec[1], 'pin_index': rec[7]}
        return out


    def discover_certificates(self) -> list[dict]:
        '''
        Enumerate certificates via the IDPrime MiniDriver index (EF 0101) - these
        cards have no PKCS#15 filesystem. Reads each kxc/ksc container, decompresses
        it to DER, and attaches the signing key reference + PIN index from the key
        reference file. Read-only; no PIN.
        '''

        self.select_applet()
        keyrefs = self.read_keyref_map()
        certs = []
        for entry in parse_minidriver_index(self._read_ef(_MINIDRIVER_INDEX_EF)):
            if not is_certificate_entry(entry['name']):
                continue
            try:
                der = decompress_minidriver_cert(self._read_ef(entry['file_id']))
            except Exception:
                continue
            if der[:1] != b'\x30':          # not a DER SEQUENCE - skip
                continue
            digits = ''.join(c for c in entry['name'][3:5] if c.isdigit())
            container = int(digits) if digits else None
            kr = keyrefs.get(container, {})
            certs.append({
                'label': entry['name'],
                'id': entry['file_id'],
                'der': der,
                'container': container,
                'key_ref': kr.get('key_ref'),
                'pin_index': kr.get('pin_index'),
            })
        return certs


    # IDPrime algorithm references: 0x42 = RSA-PKCS1 over a SHA-256 hash 
    # (the card builds DigestInfo + pads), 0x44 = ECDSA.
    ALG_RSA_SHA256 = 0x42
    ALG_ECDSA = 0x44

    def set_security_environment(self, key_ref: int, algo_ref: int = ALG_RSA_SHA256):
        ''' MSE SET for signing: 00 22 41 B6  80 01 <algo> 84 01 <key_ref> '''

        data = bytes([0x80, 0x01, algo_ref, 0x84, 0x01, key_ref])
        resp = self.conn.transmit(b'\x00\x22\x41\xB6' + bytes([len(data)]) + data)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'IDPrime MSE failed: {resp[-2:].hex().upper()}')


    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        '''
        Sign a RAW hash (the card applies DigestInfo + PKCS#1 padding itself - do
        NOT pre-pad). set_security_environment must have run first. Two PSO steps:
        hash-input (case 4; the card echoes the hash) then compute.
        '''

        # Hash input: 00 2A 90 A0  90 <len> <hash>  (Le = len, card echoes it back)
        hlen = len(raw_hash)
        hin = bytes([0x00, 0x2A, 0x90, 0xA0, 2 + hlen, 0x90, hlen]) + raw_hash + bytes([hlen])
        resp1 = self._transmit_chained(hin)
        if resp1[-2:] != b'\x90\x00':
            raise Exception(f'IDPrime hash input failed: {resp1[-2:].hex().upper()}')

        # Compute: 00 2A 9E 9A 00  -> signature (via 61xx for RSA-3072's 384 bytes)
        resp2 = self._transmit_chained(bytes([0x00, 0x2A, 0x9E, 0x9A, 0x00]))
        if resp2[-2:] != b'\x90\x00':
            raise Exception(f'IDPrime signature computation failed: {resp2[-2:].hex().upper()}')

        sig = resp2[:-2]
        return decode_ecdsa_signature(sig) if is_ecdsa else sig


    def sign(self, pin: str, raw_hash: bytes, key_ref: int, pin_ref: int = None) -> bytes:
        '''
        High-level: verify PIN, set the security environment, and sign a raw hash.
        pin_ref defaults to the user PIN (0x11); a key whose pin_index selects the
        signature PIN needs pin_ref=0x83. Returns the raw signature bytes.
        '''

        self.select_applet()
        self.verify_pin(pin, pin_ref=pin_ref if pin_ref is not None else self.PIN_REF_USER)
        self.set_security_environment(key_ref)
        return self.compute_signature(raw_hash)


class CardOSDriver(BaseCardDriver):
    ''' Siemens / Cryptovision Implementation '''

    def __init__(self, connection: SmartCardConnection):
        self.conn = connection
        
    def select_applet(self):
        # CardOS uses a standard Master File structure. 
        # Usually, selecting 3F00 (MF) is enough, followed by the specific DF.
        apdu = b'\x00\xA4\x00\x00\x02\x3F\x00'
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00' and resp[-2:] != b'\x9F\x22':
            raise Exception('Failed to select CardOS Master File')

    def set_security_environment(self, key_id: int, is_ecdsa: bool = False):
        # CardOS V5.3+ supports ECDSA natively. The usage qualifier is the same.
        data = bytes([0x84, 0x01, key_id, 0x95, 0x01, 0x40])
        apdu = b'\x00\x22\x41\xB6' + bytes([len(data)]) + data
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'CardOS MSE failed: {resp[-2:].hex().upper()}')

    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        # ECDSA passes the raw hash directly to the card.
        payload = raw_hash if is_ecdsa else pad_pkcs1_v15_sha256(raw_hash, key_size_bits)

        # One-step computation (triggers Extended APDU for both Lc and Le)
        apdu = build_apdu(0x00, 0x2A, 0x9E, 0x9A, data=payload, le=256 if is_ecdsa else key_size_bits // 8)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'CardOS signature computation failed: {resp[-2:].hex().upper()}')
            
        raw_signature = resp[:-2]
        return decode_ecdsa_signature(raw_signature) if is_ecdsa else raw_signature


class AsepcosDriver(BaseCardDriver):
    ''' Athena ASEPCOS Implementation (Bit4ID) '''

    def select_applet(self):
        # A0 00 00 01 64 41 53 45 50 43 4F 53 00
        aid = bytes.fromhex('A00000016441534550434F5300')
        apdu = b'\x00\xA4\x04\x00' + bytes([len(aid)]) + aid
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception('Failed to select ASEPCOS Applet')

    def set_security_environment(self, key_id: int, is_ecdsa: bool = False):
        # ASEPCOS doesn't use MSE for standard signing!
        # It passes the key reference implicitly or during file selection.
        pass

    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        payload = raw_hash if is_ecdsa else pad_pkcs1_v15_sha256(raw_hash, key_size_bits)

        # CLA=80, INS=14, P1=01, P2=00, Data=payload, Le=key size
        apdu = build_apdu(0x80, 0x14, 0x01, 0x00, data=payload, le=256 if is_ecdsa else key_size_bits // 8)
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'ASEPCOS signature failed: {resp[-2:].hex().upper()}')
            
        raw_signature = resp[:-2]
        return decode_ecdsa_signature(raw_signature) if is_ecdsa else raw_signature


class IasEccDriver(BaseCardDriver):
    ''' IAS-ECC Implementation (Idemia / Oberthur) '''

    def select_applet(self):
        # Oberthur IAS/ECC AID
        aid = bytes.fromhex('A000000077010800070000FE00000100')
        apdu = b'\x00\xA4\x04\x00' + bytes([len(aid)]) + aid
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception('Failed to select IAS-ECC Applet')

    def set_security_environment(self, key_id: int, is_ecdsa: bool = False):
        # CLA=00, INS=22, P1=41, P2=B6
        # Data: 84 01 [key_id] 80 01 [algo_ref]
        # IASECC uses 0x02 for RSA-PKCS, 0x13 for ECDSA (secp256r1)
        algo_ref = 0x13 if is_ecdsa else 0x02
        data = bytes([0x84, 0x01, key_id, 0x80, 0x01, algo_ref])
        
        apdu = b'\x00\x22\x41\xB6' + bytes([len(data)]) + data
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'IAS-ECC MSE failed: {resp[-2:].hex().upper()}')

    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        payload = raw_hash if is_ecdsa else pad_pkcs1_v15_sha256(raw_hash, key_size_bits)

        # Step 1: Send the hash (BER length handles the >255 byte RSA payloads)
        step1_data = ber_tlv(0x90, payload)
        apdu1 = build_apdu(0x00, 0x2A, 0x90, 0xA0, data=step1_data)

        resp1 = self.conn.transmit(apdu1)
        if resp1[-2:] != b'\x90\x00':
            raise Exception('IAS-ECC signature preparation failed')

        # Step 2: Compute
        apdu2 = build_apdu(0x00, 0x2A, 0x9E, 0x9A, le=256 if is_ecdsa else key_size_bits // 8)
        resp2 = self.conn.transmit(apdu2)
        if resp2[-2:] != b'\x90\x00':
            raise Exception(f'IAS-ECC computation failed: {resp2[-2:].hex().upper()}')
            
        raw_signature = resp2[:-2]
        return decode_ecdsa_signature(raw_signature) if is_ecdsa else raw_signature


class ScHsmDriver(BaseCardDriver):
    ''' SmartCard-HSM Implementation (Cryptovision) '''

    def select_applet(self):
        aid = bytes.fromhex('E82B0601040181C31F0201')
        apdu = b'\x00\xA4\x04\x00' + bytes([len(aid)]) + aid
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception('Failed to select SC-HSM Applet')

    def set_security_environment(self, key_id: int, is_ecdsa: bool = False):
        # Handled dynamically inside compute_signature
        self.active_key_id = key_id

    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:
        payload = raw_hash if is_ecdsa else pad_pkcs1_v15_sha256(raw_hash, key_size_bits)

        # CLA=80, INS=68, P1=key_id, P2=algorithm, Data=payload, Le=key size
        key_id = getattr(self, 'active_key_id', 0x01)

        # SC-HSM uses P2 as the algorithm descriptor.
        # 0x01 for RSA PKCS#1.5. For ECDSA, it uses 0x08.
        algo_id = 0x08 if is_ecdsa else 0x01

        apdu = build_apdu(0x80, 0x68, key_id, algo_id, data=payload, le=256 if is_ecdsa else key_size_bits // 8)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'SC-HSM signature failed: {resp[-2:].hex().upper()}')
            
        raw_signature = resp[:-2]
        return decode_ecdsa_signature(raw_signature) if is_ecdsa else raw_signature

