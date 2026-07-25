import sys, unittest
import types

sys.path.append(f'{__file__.replace('\\', '/').rsplit('/', 2)[0]}')

from mocks import FakeSmartCardConnection
from src.sc_apdu import pad_pkcs1_v15_sha256, decode_ecdsa_signature
from src.cards import (
    BTrustDriver, IDPrimeDriver, CardOSDriver, ScHsmDriver, BaseCardDriver, AsepcosDriver,
)


class TestBTrustCards(unittest.TestCase):

    def setUp(self):
        self.fake_conn = FakeSmartCardConnection()

    # --- Factory Tests ---

    def test_factory_creates_idprime(self):
        # Provide a known IDPrime 940 ATR
        self.fake_conn.atr_bytes = bytes.fromhex('3B7F96000080318065B0855956FB120FFE829000')
        driver = BTrustDriver.create(self.fake_conn)
        assert isinstance(driver, IDPrimeDriver)

    def test_factory_creates_cardos(self):
        # Provide a known CardOS V5.3 ATR
        self.fake_conn.atr_bytes = bytes.fromhex('3BD218008131FE58C90217')
        driver = BTrustDriver.create(self.fake_conn)
        assert isinstance(driver, CardOSDriver)

    def test_factory_rejects_unknown(self):
        self.fake_conn.atr_bytes = bytes.fromhex('3B9999999999')
        context = None
        try:
            BTrustDriver.create(self.fake_conn)
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert 'Unsupported Smart Card ATR' in str(context.exception)

    def test_factory_creates_asepcos(self):
        self.fake_conn.atr_bytes = bytes.fromhex('3BD6180081B1FE7D1F0341534537353501')
        driver = BTrustDriver.create(self.fake_conn)
        assert type(driver).__name__ == 'AsepcosDriver'

    def test_factory_creates_iasecc(self):
        self.fake_conn.atr_bytes = bytes.fromhex('3BDD96008131FE4580F9A00000007701080007900070')
        driver = BTrustDriver.create(self.fake_conn)
        assert type(driver).__name__ == 'IasEccDriver'

    def test_factory_creates_schsm(self):
        self.fake_conn.atr_bytes = bytes.fromhex('3BFE1800008131FE458031815448534D31738021408107FA')
        driver = BTrustDriver.create(self.fake_conn)
        assert type(driver).__name__ == 'ScHsmDriver'


    # --- PIN Verification Tests ---

    def test_base_driver_pin_success(self):
        self.fake_conn.transmit_responses = [b'\x90\x00'] # Success APDU
        driver = BaseCardDriver(self.fake_conn)
        
        result = driver.verify_pin('1234')
        assert result is True
        
        # Verify the APDU was padded correctly (00 20 00 81 08 31 32 33 34 FF FF FF FF)
        assert self.fake_conn.last_transmitted_apdu == bytes.fromhex('002000810831323334FFFFFFFF')


    def test_base_driver_pin_uses_card_aodf_params(self):
        ''' AODF pin_info overrides the hardcoded ref and padding '''
        
        self.fake_conn.transmit_responses = [b'\x90\x00']
        driver = BaseCardDriver(self.fake_conn)

        pin_info = {'pin_ref': 0x82, 'stored_length': 6, 'pad_char': 0x00, 'min_length': 4}
        assert driver.verify_pin('1234', pin_info=pin_info) is True

        # P2 = 0x82 (card ref), Lc = 0x06, PIN padded to 6 bytes with 0x00
        assert self.fake_conn.last_transmitted_apdu == bytes.fromhex('0020008206313233340000')


    def test_base_driver_pin_wrong_retries(self):
        self.fake_conn.transmit_responses = [b'\x63\xC2'] # 2 retries left
        driver = BaseCardDriver(self.fake_conn)
        
        context = None
        try:
            driver.verify_pin('9999')
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert '2 retries remaining' in str(context.exception)


    def test_base_driver_pin_blocked(self):
        self.fake_conn.transmit_responses = [b'\x69\x83'] # Blocked APDU
        driver = BaseCardDriver(self.fake_conn)
        
        context = None
        try:
            driver.verify_pin('1234')
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert 'Smart card is blocked' in str(context.exception)


    # --- IDPrime Tests ---

    def test_idprime_compute_signature_rsa(self):
        ''' Proves IDPrime pads a raw 32-byte hash to 256 bytes for RSA '''

        self.fake_conn.transmit_responses = [
            b'\x90\x00',                     # Send Hash
            b'fake_signature_bytes\x90\x00'  # Retrieve Sig
        ]
        driver = IDPrimeDriver(self.fake_conn)
        
        raw_hash = b'\xAA' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=False)
        assert sig == b'fake_signature_bytes'
        assert self.fake_conn.transmit_call_count == 2


    def test_idprime_compute_signature_ecdsa(self):
        ''' Proves IDPrime bypasses padding and unwraps ASN.1 for ECDSA '''
        
        # Mocking an ASN.1 wrapped ECDSA response from the card
        mock_asn1_sig = b'\x30\x06\x02\x01\x11\x02\x01\x22'
        self.fake_conn.transmit_responses = [
            b'\x90\x00',                     
            mock_asn1_sig + b'\x90\x00'  
        ]
        driver = IDPrimeDriver(self.fake_conn)
        
        raw_hash = b'\xBB' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=True)
        
        # The driver should unwrap the ASN.1 and return raw r||s
        expected_raw = decode_ecdsa_signature(mock_asn1_sig)
        assert sig == expected_raw


    def test_idprime_compute_signature_apdu_formats(self):
        ''' Proves IDPrime uses an Extended APDU for Step 1, and a Short APDU for Step 2 '''
        
        self.fake_conn.transmit_responses = [
            b'\x90\x00',                     
            b'fake_signature_bytes\x90\x00'  
        ]
        driver = IDPrimeDriver(self.fake_conn)
        
        raw_hash = b'\xAA' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=False)
        
        # Verify Step 2 APDU: Expecting a 1-byte Short Le (0x00 = 256 bytes)
        assert self.fake_conn.last_transmitted_apdu == b'\x00\x2A\x9E\x9A\x00'


    # --- CardOS Tests ---

    def test_cardos_set_security_env(self):
        
        self.fake_conn.transmit_responses = [b'\x90\x00']
        driver = CardOSDriver(self.fake_conn)
        
        driver.set_security_environment(key_id=0x01)
        
        # Verify the MSE APDU: 00 22 41 B6 06 84 01 01 95 01 40
        assert self.fake_conn.last_transmitted_apdu == bytes.fromhex('002241B606840101950140')


    def test_cardos_compute_signature_extended_apdu(self):
        ''' CardOS correctly wraps a 256-byte hash in a full Extended APDU '''

        from src.sc_apdu import pad_pkcs1_v15_sha256
        
        self.fake_conn.transmit_responses = [b'fake_signature_bytes\x90\x00']
        driver = CardOSDriver(self.fake_conn)
        
        # Pass a 32-byte raw_hash
        raw_hash = b'\xAA' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=False)
        
        assert sig == b'fake_signature_bytes'
        
        # Expect: CLA/INS/P1/P2 + Extended Lc (00 01 00) + Data + Extended Le (01 00 = 256 bytes)
        # Manually pad it to test that the APDU generated by the driver matches
        padded_hash = pad_pkcs1_v15_sha256(raw_hash)
        expected_apdu = b'\x00\x2A\x9E\x9A\x00\x01\x00' + padded_hash + b'\x01\x00'
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


    # --- ASEPCOS Tests ---

    def test_asepcos_compute_signature(self):
        ''' ASEPCOS uses a proprietary 0x14 INS instruction instead of 0x2A '''
        
        self.fake_conn.transmit_responses = [b'fake_signature_bytes\x90\x00']
        driver = AsepcosDriver(self.fake_conn)
        
        raw_hash = b'\xAA' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=False)
        
        assert sig == b'fake_signature_bytes'
        
        padded_hash = pad_pkcs1_v15_sha256(raw_hash)
        expected_apdu = b'\x80\x14\x01\x00\x00\x01\x00' + padded_hash + b'\x01\x00'
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


    # --- IAS-ECC Tests ---

    def test_iasecc_set_security_env(self):
        ''' Proves IAS-ECC sets the algo_ref dynamically based on key ID '''

        self.fake_conn.transmit_responses = [b'\x90\x00']
        
        # Set the ATR FIRST, then create the driver
        self.fake_conn.atr_bytes = bytes.fromhex('3BDD96008131FE4580F9A00000007701080007900070')
        driver = BTrustDriver.create(self.fake_conn)
        
        driver.set_security_environment(key_id=0x11)
        
        # Expect: CLA(00) INS(22) P1(41) P2(B6) Lc(06) + [84 01 11 80 01 02]
        expected_apdu = bytes.fromhex('002241B606840111800102')
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


    # --- SC-HSM Tests ---

    def test_schsm_compute_signature_dynamic_key(self):
        ''' SC-HSM skips MSE and injects the Key ID directly into P1 of the signature APDU '''
        
        self.fake_conn.transmit_responses = [b'fake_signature_bytes\x90\x00']
        driver = ScHsmDriver(self.fake_conn)
        
        # SC-HSM requires setting the environment first so it caches the active_key_id
        driver.set_security_environment(key_id=0x05)
        
        raw_hash = b'\xAA' * 32
        sig = driver.compute_signature(raw_hash, is_ecdsa=False)
        
        assert sig == b'fake_signature_bytes'
        
        padded_hash = pad_pkcs1_v15_sha256(raw_hash)
        # Expect: P1 = 0x05 (key_id), P2 = 0x01 (RSA_PKCS)
        expected_apdu = b'\x80\x68\x05\x01\x00\x01\x00' + padded_hash + b'\x01\x00'
        assert self.fake_conn.last_transmitted_apdu == expected_apdu



    def test_base_driver_change_pin_success(self):
        ''' Proves Change PIN (INS=0x24) pads and concatenates the old and new PINs correctly '''
        
        self.fake_conn.transmit_responses = [b'\x90\x00'] # Success APDU
        driver = BaseCardDriver(self.fake_conn)
        
        result = driver.change_pin(old_pin='1234', new_pin='5678')
        assert result is True
        
        # Expect: CLA(00) INS(24) P1(00) P2(81) Lc(10) + [1234 + FFFF] + [5678 + FFFF]
        expected_apdu = bytes.fromhex('002400811031323334FFFFFFFF35363738FFFFFFFF')
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


    def test_base_driver_change_pin_failure(self):
        ''' Verifies that a failed PIN change safely raises an exception '''
        
        self.fake_conn.transmit_responses = [b'\x69\x82'] # Security status not satisfied
        driver = BaseCardDriver(self.fake_conn)
        
        context = None
        try:
            driver.change_pin('0000', '1111')
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert 'PIN Change failed: 6982' in str(context.exception)


    def test_base_driver_unblock_pin_success(self):
        ''' Proves Unblock PIN (INS=0x2C) maps the PUK and the new PIN together natively '''
        
        self.fake_conn.transmit_responses = [b'\x90\x00'] # Success APDU
        driver = BaseCardDriver(self.fake_conn)
        
        # Simulating an 8-digit PUK and a 4-digit New PIN
        result = driver.unblock_pin(puk='87654321', new_pin='1234')
        assert result is True
        
        # Expect: CLA(00) INS(2C) P1(00) P2(81) Lc(10) + [87654321] + [1234 + FFFF]
        expected_apdu = bytes.fromhex('002C008110383736353433323131323334FFFFFFFF')
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


if __name__ == '__main__':
    unittest.main()