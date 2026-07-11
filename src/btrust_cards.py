import sys

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from sc_types import SCARDHANDLE
from sc_ffi import SmartCardConnection
from sc_apdu import pad_pkcs1_v15_sha256, read_binary_file, build_apdu, decode_ecdsa_signature, ber_tlv
from pkcs15 import parse_pkcs15_filesystem


# --- Known ATRs for the card families B-Trust issues ---
IDPRIME_ATRS = [
    '3B7F96000080318065B0850300EF120FFE829000', # IDPrime 840
    '3B7F96000080318065B0855956FB120FFE829000', # IDPrime 940
    '3BFF9600008131FE4380318065B0855956FB120FFE82900000', # IDPrime MD 940
]

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



def _encode_pin(pin: str) -> bytes:
    '''
    ASCII PIN padded with 0xFF to 8 bytes. Length is validated strictly:
    an over-long PIN would produce a malformed APDU, and the card treats
    any malformed VERIFY the same as a wrong PIN - it burns a retry.
    '''

    if not 4 <= len(pin) <= 8:
        raise ValueError('PIN/PUK must be 4 to 8 characters long.')
    return pin.encode('ascii').ljust(8, b'\xFF')


class BaseCardDriver:
    ''' Abstract base class for B-Trust smart cards '''

    def __init__(self, connection: SmartCardConnection):
        self.conn = connection

    def verify_pin(self, pin: str, pin_ref: int = 0x81):
        ''' Standard ISO 7816-4 PIN Verification '''

        pin_bytes = _encode_pin(pin)
        # CLA=00, INS=20 (Verify), P1=00, P2=pin_ref, Lc=08
        apdu = bytes([0x00, 0x20, 0x00, pin_ref, 0x08]) + pin_bytes
        
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


    def change_pin(self, old_pin: str, new_pin: str, pin_ref: int = 0x81):
        ''' Standard ISO 7816-4 Change Reference Data (Change PIN) '''
        
        # PINs are ASCII, padded with 0xFF to 8 bytes, concatenated
        payload = _encode_pin(old_pin) + _encode_pin(new_pin)
        
        # CLA=00, INS=24 (Change), P1=00, P2=pin_ref, Data=payload
        apdu = build_apdu(0x00, 0x24, 0x00, pin_ref, data=payload)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'PIN Change failed: {resp[-2:].hex().upper()}')
        return True


    def unblock_pin(self, puk: str, new_pin: str, pin_ref: int = 0x81):
        ''' Standard ISO 7816-4 Reset Retry Counter (Unblock with PUK) '''
        
        # PUK and New PIN are ASCII, padded with 0xFF to 8 bytes, concatenated
        payload = _encode_pin(puk) + _encode_pin(new_pin)
        
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


    def set_security_environment(self, key_id: int):

        # CLA=00, INS=22 (MSE), P1=41 (Set for computation), P2=B6 (Digital Signature)
        # Data: 83 01 <key_id>
        data = bytes([0x83, 0x01, key_id])
        apdu = b'\x00\x22\x41\xB6' + bytes([len(data)]) + data
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'MSE failed: {resp[-2:].hex().upper()}')


    def compute_signature(self, raw_hash: bytes, is_ecdsa: bool = False, key_size_bits: int = 2048) -> bytes:

        # ECDSA uses the raw 32-byte hash. RSA requires PKCS#1 v1.5 padding to the key size.
        payload = raw_hash if is_ecdsa else pad_pkcs1_v15_sha256(raw_hash, key_size_bits)

        # Send the data (BER length handles the >255 byte RSA payloads)
        step1_data = ber_tlv(0x90, payload)
        apdu1 = build_apdu(0x00, 0x2A, 0x90, 0xA0, data=step1_data)

        resp1 = self.conn.transmit(apdu1)
        if resp1[-2:] != b'\x90\x00':
            raise Exception('IDPrime signature preparation failed')

        # Ask for the cryptographic result
        # ECDSA returns ~70 bytes (ASN.1); RSA returns exactly the key size in bytes.
        apdu2 = build_apdu(0x00, 0x2A, 0x9E, 0x9A, le=256 if is_ecdsa else key_size_bits // 8)
        resp2 = self.conn.transmit(apdu2)
        if resp2[-2:] != b'\x90\x00':
            raise Exception(f'IDPrime signature computation failed: {resp2[-2:].hex().upper()}')
            
        raw_signature = resp2[:-2]
        
        # Unwrap the ASN.1 sequence if it's an ECDSA signature
        if is_ecdsa:
            return decode_ecdsa_signature(raw_signature)
            
        return raw_signature


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

