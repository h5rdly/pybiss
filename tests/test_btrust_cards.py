import sys, unittest

sys.path.append(f'{__file__.replace('\\', '/').rsplit('/', 2)[0]}')

from mocks import FakeSmartCardConnection
from src.btrust_cards import BTrustDriver, IDPrimeDriver, CardOSDriver, BaseCardDriver


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
        with self.assertRaises(Exception) as context:
            BTrustDriver.create(self.fake_conn)
        assert 'Unsupported Smart Card ATR' in str(context.exception)

    # --- PIN Verification Tests ---

    def test_base_driver_pin_success(self):
        self.fake_conn.transmit_responses = [b'\x90\x00'] # Success APDU
        driver = BaseCardDriver(self.fake_conn)
        
        result = driver.verify_pin('1234')
        assert result is True
        
        # Verify the APDU was padded correctly (00 20 00 81 08 31 32 33 34 FF FF FF FF)
        assert self.fake_conn.last_transmitted_apdu == bytes.fromhex('002000810831323334FFFFFFFF')

    def test_base_driver_pin_wrong_retries(self):
        self.fake_conn.transmit_responses = [b'\x63\xC2'] # 2 retries left
        driver = BaseCardDriver(self.fake_conn)
        
        with self.assertRaises(Exception) as context:
            driver.verify_pin('9999')
        assert '2 retries remaining' in str(context.exception)

    def test_base_driver_pin_blocked(self):
        self.fake_conn.transmit_responses = [b'\x69\x83'] # Blocked APDU
        driver = BaseCardDriver(self.fake_conn)
        
        with self.assertRaises(Exception) as context:
            driver.verify_pin('1234')
        assert 'Smart card is blocked' in str(context.exception)

    # --- IDPrime Tests ---

    def test_idprime_compute_signature(self):
        # IDPrime uses a 2-step process. We mock both success responses.
        self.fake_conn.transmit_responses = [
            b'\x90\x00',                     # Step 1 (Send Hash)
            b'fake_signature_bytes\x90\x00'  # Step 2 (Retrieve Sig)
        ]
        driver = IDPrimeDriver(self.fake_conn)
        
        sig = driver.compute_signature(b'dummy_padded_hash')
        assert sig == b'fake_signature_bytes'
        assert self.fake_conn.transmit_call_count == 2

    # --- CardOS Tests ---

    def test_cardos_set_security_env(self):
        self.fake_conn.transmit_responses = [b'\x90\x00']
        driver = CardOSDriver(self.fake_conn)
        
        driver.set_security_environment(key_id=0x01)
        
        # Verify the MSE APDU: 00 22 41 B6 06 84 01 01 95 01 40
        assert self.fake_conn.last_transmitted_apdu == bytes.fromhex('002241B606840101950140')


    def test_cardos_compute_signature_extended_apdu(self):
        ''' Proves CardOS correctly wraps a 256-byte hash in an Extended APDU '''
        self.fake_conn.transmit_responses = [b'fake_signature_bytes\x90\x00']
        driver = CardOSDriver(self.fake_conn)
        
        padded_hash = b'\xAA' * 256
        sig = driver.compute_signature(padded_hash)
        
        assert sig == b'fake_signature_bytes'
        
        # Expect: Extended Lc (00 01 00) + Data + Extended Le (00 00)
        expected_apdu = b'\x00\x2A\x9E\x9A\x00\x01\x00' + padded_hash + b'\x00\x00'
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


    def test_idprime_compute_signature_apdu_formats(self):
        '''  IDPrime uses an Extended APDU for Step 1, and a Short APDU for Step 2 '''
        
        self.fake_conn.transmit_responses = [
            b'\x90\x00',                     # Step 1: Buffer acceptance
            b'fake_signature_bytes\x90\x00'  # Step 2: Computation return
        ]
        driver = IDPrimeDriver(self.fake_conn)
        
        padded_hash = b'\xBB' * 256
        sig = driver.compute_signature(padded_hash)
        
        assert sig == b'fake_signature_bytes'
        assert self.fake_conn.transmit_call_count == 2
        
        # Verify Step 2 APDU: Expecting a 1-byte Short Le (0x00 = 256 bytes)
        assert self.fake_conn.last_transmitted_apdu == b'\x00\x2A\x9E\x9A\x00'


    def test_cardos_compute_signature_extended_apdu(self):
        ''' CardOS correctly wraps a 256-byte hash in a full Extended APDU '''

        self.fake_conn.transmit_responses = [b'fake_signature_bytes\x90\x00']
        driver = CardOSDriver(self.fake_conn)
        
        padded_hash = b'\xAA' * 256
        sig = driver.compute_signature(padded_hash)
        
        assert sig == b'fake_signature_bytes'
        
        # Expect: CLA/INS/P1/P2 + Extended Lc (00 01 00) + Data + Extended Le (01 00 = 256 bytes)
        expected_apdu = b'\x00\x2A\x9E\x9A\x00\x01\x00' + padded_hash + b'\x01\x00'
        assert self.fake_conn.last_transmitted_apdu == expected_apdu


if __name__ == '__main__':
    unittest.main()