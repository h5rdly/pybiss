import sys

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from sc_types import SCARDHANDLE
from sc_ffi import SmartCardConnection
from sc_apdu import pad_pkcs1_v15_sha256, read_binary_file, build_apdu


# --- ATR Signatures from OpenSC ---
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

class BaseCardDriver:
    ''' Abstract base class for B-Trust smart cards '''
    
    def __init__(self, connection: SmartCardConnection):
        self.conn = connection

    def verify_pin(self, pin: str, pin_ref: int = 0x81):
        ''' Standard ISO 7816-4 PIN Verification '''

        # PIN is ASCII, padded with 0xFF to 8 bytes
        pin_bytes = pin.encode('ascii').ljust(8, b'\xFF')
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

    def set_security_environment(self, key_id: int):
        raise NotImplementedError


    def compute_signature(self, padded_hash: bytes) -> bytes:
        raise NotImplementedError


class IDPrimeDriver(BaseCardDriver):
    ''' Gemalto IDPrime Implementation '''

    def __init__(self, connection: SmartCardConnection):
        self.conn = connection

    def select_applet(self):

        # From idprime_path: A0 00 00 00 18 80 00 00 00 06 62
        aid = bytes.fromhex('A000000018800000000662')
        apdu = b'\x00\xA4\x04\x00' + bytes([len(aid)]) + aid
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception('Failed to select IDPrime Applet')


    def set_security_environment(self, key_id: int):

        # Translated from idprime_set_security_env()
        # CLA=00, INS=22 (MSE), P1=41 (Set for computation), P2=B6 (Digital Signature)
        # Data: 83 01 <key_id>
        data = bytes([0x83, 0x01, key_id])
        apdu = b'\x00\x22\x41\xB6' + bytes([len(data)]) + data
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'MSE failed: {resp[-2:].hex().upper()}')


    def compute_signature(self, padded_hash: bytes) -> bytes:

        # Step 1: Send the hash (triggers Extended APDU because len > 255)
        step1_data = bytes([0x90, len(padded_hash) & 0xFF]) + padded_hash
        apdu1 = build_apdu(0x00, 0x2A, 0x90, 0xA0, data=step1_data)
        
        resp1 = self.conn.transmit(apdu1)
        if resp1[-2:] != b'\x90\x00':
            raise Exception('IDPrime signature preparation failed')

        # Step 2: Ask for the cryptographic result (triggers Short APDU, Le=0x00 means 256)
        apdu2 = build_apdu(0x00, 0x2A, 0x9E, 0x9A, le=256)
        resp2 = self.conn.transmit(apdu2)
        if resp2[-2:] != b'\x90\x00':
            raise Exception(f'IDPrime signature computation failed: {resp2[-2:].hex().upper()}')
            
        return resp2[:-2]


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


    def set_security_environment(self, key_id: int):

        # Translated from cardos_set_security_env() for V5 cards
        # CLA=00, INS=22 (MSE), P1=41, P2=B6 (Signature)
        # Data: 84 01 <key_id> 95 01 40 (Private key ref + Usage qualifier)
        data = bytes([0x84, 0x01, key_id, 0x95, 0x01, 0x40])
        apdu = b'\x00\x22\x41\xB6' + bytes([len(data)]) + data
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'CardOS MSE failed: {resp[-2:].hex().upper()}')


    def compute_signature(self, padded_hash: bytes) -> bytes:

        # One-step computation (triggers Extended APDU for both Lc and Le)
        apdu = build_apdu(0x00, 0x2A, 0x9E, 0x9A, data=padded_hash, le=256)
        
        resp = self.conn.transmit(apdu)
        if resp[-2:] != b'\x90\x00':
            raise Exception(f'CardOS signature computation failed: {resp[-2:].hex().upper()}')
            
        return resp[:-2]


class BTrustDriver:
    ''' Factory class to instantiate the correct hardware driver '''
    
    @staticmethod
    def create(connection: SmartCardConnection) -> BaseCardDriver:
        atr = connection.get_atr().hex().upper()
        
        if any(a in atr for a in IDPRIME_ATRS):
            return IDPrimeDriver(connection)
        elif any(a in atr for a in CARDOS_ATRS):
            return CardOSDriver(connection)
        else:
            raise Exception(f'Unsupported Smart Card ATR: {atr}')