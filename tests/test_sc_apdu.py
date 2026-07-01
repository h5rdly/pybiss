import sys, unittest

sys.path.append(f'{__file__.replace('\\', '/').rsplit('/', 2)[0]}')

from src.sc_apdu import pad_pkcs1_v15_sha256, read_binary_file, build_apdu
from mocks import FakeSmartCardConnection


class TestSCAPDU(unittest.TestCase):

    def test_pad_pkcs1_v15_sha256(self):
        ''' Raw byte-level PKCS#1 v1.5 padding test '''

        dummy_hash = b'\xAA' * 32
        padded = pad_pkcs1_v15_sha256(dummy_hash, key_size_bits=2048)
        
        # 2048 bits = 256 bytes
        assert len(padded) == 256
        assert padded.startswith(b'\x00\x01')
        
        # Must end with the exact ASN.1 SHA256 OID and the hash
        asn1_oid = bytes.fromhex('3031300d060960864801650304020105000420')
        assert padded.endswith(asn1_oid + dummy_hash)
        

    def test_pad_pkcs1_bad_hash_length(self):
        ''' 32-byte limit for SHA256 '''

        with self.assertRaises(ValueError):
            pad_pkcs1_v15_sha256(b'\xAA' * 31)


    def test_read_binary_file_success(self):
        ''' Reading a 266-byte file over chunked ISO-7816 APDUs '''

        fake_conn = FakeSmartCardConnection()
        
        # We simulate the sequential APDU responses the card would send us back:
        fake_conn.transmit_responses = [
            b'\x90\x00',                   # Select File: Success
            (b'\xAA' * 256) + b'\x90\x00', # Read chunk 1: 256 bytes + Success
            (b'\xBB' * 10) + b'\x62\x82'   # Read chunk 2: 10 bytes + EOF Reached
        ]
        
        cert_data = read_binary_file(fake_conn, file_id=b'\x43\x01')
        
        assert len(cert_data) == 266
        assert cert_data.startswith(b'\xAA' * 256)
        assert cert_data.endswith(b'\xBB' * 10)
        assert fake_conn.transmit_call_count == 3


    def test_build_apdu_short(self):
        ''' Standard APDUs (< 256 bytes) use a 1-byte Lc '''

        data = b'\xAA' * 10
        apdu = build_apdu(0x00, 0xA4, 0x04, 0x00, data)
        
        # Expect: CLA INS P1 P2 Lc Data
        assert apdu == b'\x00\xA4\x04\x00\x0A' + data
        

    def test_build_apdu_short_with_le(self):
        ''' Short APDUs handle the expected length (Le) byte correctly '''

        apdu = build_apdu(0x00, 0xB0, 0x00, 0x00, le=256)
        
        # Expect: CLA INS P1 P2 Le
        assert apdu == b'\x00\xB0\x00\x00\x00'


    def test_build_apdu_extended(self):
        ''' Extended APDUs (>= 256 bytes) trigger the 3-byte Lc format '''

        data = b'\xBB' * 256
        apdu = build_apdu(0x00, 0x2A, 0x9E, 0x9A, data)
        
        # Expect: CLA INS P1 P2 [00 HighByte LowByte] Data
        # 256 bytes = 0x0100 -> Lc should be 00 01 00
        assert apdu == b'\x00\x2A\x9E\x9A\x00\x01\x00' + data


    def test_build_apdu_extended_with_le(self):
        ''' Extended APDUs format the 2-byte Le correctly at the tail '''

        data = b'\xCC' * 256
        apdu = build_apdu(0x00, 0x2A, 0x9E, 0x9A, data, le=256)
        
        # Expect: Lc is 00 01 00, Data, Le is 00 00 (0 means expect up to 65536 bytes back)
        assert apdu == b'\x00\x2A\x9E\x9A\x00\x01\x00' + data + b'\x01\x00'


if __name__ == '__main__':
    unittest.main()