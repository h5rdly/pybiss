import sys, unittest

sys.path.append(f'{__file__.replace("\\", "/").rsplit("/", 2)[0]}')

from src.pkcs15 import (
    parse_cdf, parse_prkdf, parse_pkcs15_filesystem, parse_aodf, _extract_path,
    encode_pkcs15_pin,
)


class TestPKCS15Explorer(unittest.TestCase):

    def test_extract_path_from_implicit_sequence(self):
        ''' Proves we can dig into an ASN.1 block to find an OCTET STRING path '''

        # A mocked PKCS#15 sequence containing a path (0x04 0x02 0x50 0x33)
        mock_val = b'\x30\x04\x04\x02\x50\x33'
        
        path = _extract_path(mock_val)
        assert path == b'\x50\x33'


    def test_parse_cdf_success(self):
        ''' Proves the Certificate Directory File parsing flawlessly maps ID to Path '''
        
        # Mocked ASN.1 structure representing a single Certificate Record
        # CommonObjectAttributes: Label="TestCert", AuthId=b"\x01"
        # ClassAttributes: Id=b"\x12\x34"
        # TypeAttributes: Path=b"\x43\x01"
        mock_cdf = (
            b'\x30\x22' # Sequence (Record)
            b'\x30\x0E' # CommonObjectAttributes Sequence
                b'\x0C\x08TestCert' # Label
                b'\x04\x02\x00\x01' # AuthID
            b'\x30\x04' # ClassAttributes Sequence
                b'\x04\x02\x12\x34' # Cert ID
            b'\xA1\x0A' # TypeAttributes [1]
                b'\x30\x08' # Sequence
                    b'\x30\x06' # Path Sequence
                        b'\x04\x02\x43\x01' # OCTET STRING Path
                        b'\x02\x00' # End
        )
        
        certs = parse_cdf(mock_cdf)
        
        assert len(certs) == 1
        assert certs[0]['id'] == b'\x12\x34'
        assert certs[0]['label'] == 'TestCert'
        assert certs[0]['path'] == b'\x43\x01'
        assert certs[0]['auth_id'] == b'\x00\x01'


    def test_parse_prkdf_success(self):
        ''' Proves Private Key Directory mapping correctly extracts Key ID and Auth PIN '''
        
        # CommonObjectAttributes: AuthId=b"\x05"
        # ClassAttributes: Id=b"\x99\x99"
        mock_prkdf = (
            b'\x30\x0E' # Sequence (Record - 14 bytes)
            b'\x30\x04' # COA Sequence <--- FIX: 0x04 (4 bytes) instead of 0x06
                b'\x04\x02\x00\x05' # AuthID (PIN ref)
            b'\x30\x04' # ClassAttributes Sequence
                b'\x04\x02\x99\x99' # Key ID
            b'\xA1\x00' # TypeAttributes (Empty for mock)
        )
        
        keys = parse_prkdf(mock_prkdf)
        
        assert len(keys) == 1
        assert keys[0]['id'] == b'\x99\x99'
        assert keys[0]['auth_id'] == b'\x00\x05'


    def test_parse_cdf_multiple_records(self):
        ''' Proves the parser correctly loops through multiple certificates in a single file '''
        
        # Record 1 (ID: 1111, Path: 4311)
        rec1 = (
            b'\x30\x1A' # 26 bytes
            b'\x30\x0C' # COA (12 bytes)
                b'\x0C\x06Cert_1' # Label
                b'\x04\x02\x00\x01' # AuthID
            b'\x30\x04' # CA
                b'\x04\x02\x11\x11' # ID
            b'\xA1\x04' # TA
                b'\x04\x02\x43\x11' # Path
        )
        # Record 2 (ID: 2222, Path: 4322)
        rec2 = (
            b'\x30\x1A' # 26 bytes
            b'\x30\x0C' # COA
                b'\x0C\x06Cert_2' 
                b'\x04\x02\x00\x02' 
            b'\x30\x04' # CA
                b'\x04\x02\x22\x22' 
            b'\xA1\x04' # TA
                b'\x04\x02\x43\x22' 
        )
        
        certs = parse_cdf(rec1 + rec2)
        
        assert len(certs) == 2
        assert certs[0]['label'] == 'Cert_1'
        assert certs[0]['path'] == b'\x43\x11'
        assert certs[1]['label'] == 'Cert_2'
        assert certs[1]['id'] == b'\x22\x22'


    def test_parse_prkdf_missing_optionals(self):
        ''' Proves the parser doesn't crash if the card vendor omitted Labels or AuthIDs '''
        
        mock_prkdf = (
            b'\x30\x08' # Seq (8 bytes)
            b'\x30\x00' # COA is Empty! (0 bytes)
            b'\x30\x04' # CA
                b'\x04\x02\x33\x33' # Key ID
        )
        
        keys = parse_prkdf(mock_prkdf)
        
        assert len(keys) == 1
        assert keys[0]['id'] == b'\x33\x33'
        assert keys[0]['label'] == ""        # Degrades gracefully
        assert keys[0]['auth_id'] is None    # Degrades gracefully


    def test_parse_pkcs15_filesystem_orchestration(self):
        ''' 
        Proves the master function correctly issues APDUs to read the ODF, 
        resolves the paths, and extracts the physical DER bytes from the card natively.
        '''

        from mocks import FakeSmartCardConnection
        fake_conn = FakeSmartCardConnection()
        
        # ODF -> Points to CDF (50 33) and PrKDF (50 32)
        odf_data = (
            b'\x30\x06\xA4\x04\x04\x02\x50\x33' 
            b'\x30\x06\xA0\x04\x04\x02\x50\x32' 
        )
        
        # CDF -> Points to Cert DER at Path 43 01
        cdf_data = (
            b'\x30\x12' 
            b'\x30\x04\x04\x02\x00\x01' # COA (Auth 01)
            b'\x30\x04\x04\x02\x11\x11' # CA (ID 1111)
            b'\xA1\x04\x04\x02\x43\x01' # TA (Path 43 01)
        )
        
        # PrKDF -> Key ID 1111 mapped to PIN Ref 01
        prkdf_data = (
            b'\x30\x0E' 
            b'\x30\x04\x04\x02\x00\x01' 
            b'\x30\x04\x04\x02\x11\x11' 
            b'\xA1\x00' 
        )

        cert_der_data = b'MOCK_DER_BYTES'

        # We program the Fake token to respond to our APDUs in the exact order 
        # the PKCS#15 explorer requests them. Each file takes 3 APDUs to read 
        # (Select -> Read -> Read EOF)
        fake_conn.transmit_responses = [
            b'\x90\x00', odf_data + b'\x90\x00', b'\x62\x82',       # 1. Read ODF
            b'\x90\x00', cdf_data + b'\x90\x00', b'\x62\x82',       # 2. Read CDF
            b'\x90\x00', cert_der_data + b'\x90\x00', b'\x62\x82',  # 3. Read Physical Cert DER
            b'\x90\x00', prkdf_data + b'\x90\x00', b'\x62\x82'      # 4. Read PrKDF
        ]
        
        # Execute the explorer
        fs = parse_pkcs15_filesystem(fake_conn)
        
        # Assert the filesystem mapped perfectly
        assert len(fs['certificates']) == 1
        assert len(fs['private_keys']) == 1
        
        # Assert it actually fetched the physical DER bytes from Path 43 01
        assert fs['certificates'][0]['der'] == b'MOCK_DER_BYTES'


    def test_parse_aodf_success(self):
        ''' Proves the AODF parser successfully maps an AuthID to a Hardware PIN Reference '''
        
        # Mocked AODF Record:
        # CommonObjectAttributes: Empty
        # CommonAuthenticationObjectAttributes: AuthID = b"\x01"
        # PinAttributes: ... MinLen=4, MaxLen=8, PinRef=0x81
        mock_aodf = (
            b'\x30\x1A' # Sequence (Record)
            b'\x30\x00' # COA (Empty)
            b'\x30\x04' # CAOA Sequence
                b'\x04\x02\x00\x01' # AuthID
            b'\x30\x10' # PinAttributes Sequence
                b'\x03\x02\x00\x00' # PinFlags (BIT STRING)
                b'\x0A\x01\x01'     # PinType (ENUM)
                b'\x02\x01\x04'     # MinLength = 4
                b'\x02\x01\x08'     # MaxLength = 8
                b'\x02\x01\x81'     # PinReference = 0x81
        )
        
        pin_map = parse_aodf(mock_aodf)

        assert len(pin_map) == 1
        assert b'\x00\x01' in pin_map
        # pinReference encoded as a plain trailing INTEGER -> fallback path
        assert pin_map[b'\x00\x01']['pin_ref'] == 0x81
        assert pin_map[b'\x00\x01']['pin_type'] == 1
        assert pin_map[b'\x00\x01']['min_length'] == 4

    def test_parse_aodf_spec_context_tagged_pin_ref(self):
        ''' Spec-correct cards tag pinReference as [0] and carry storedLength + padChar '''

        # PinAttributes: flags, type=ascii(1), minLen=4, storedLen=6,
        #                pinRef [0]=0x82, padChar=0x00
        mock_aodf = (
            b'\x30\x1D'
            b'\x30\x00'                       # COA empty
            b'\x30\x04\x04\x02\x00\x02'       # CAOA: AuthID = 00 02
            b'\x30\x13'                       # PinAttributes (19 bytes)
                b'\x03\x02\x00\xC0'           # PinFlags
                b'\x0A\x01\x01'               # PinType = ascii-numeric
                b'\x02\x01\x04'               # minLength = 4
                b'\x02\x01\x06'               # storedLength = 6
                b'\x80\x01\x82'               # [0] pinReference = 0x82
                b'\x04\x01\x00'               # padChar = 0x00
        )

        info = parse_aodf(mock_aodf)[b'\x00\x02']
        assert info['pin_ref'] == 0x82
        assert info['stored_length'] == 6
        assert info['pad_char'] == 0x00
        assert info['min_length'] == 4


class TestEncodePin(unittest.TestCase):

    def test_default_encoding_matches_btrust_convention(self):
        ''' No card info -> ASCII, padded to 8 bytes with 0xFF '''
        self.assertEqual(encode_pkcs15_pin('1234'), bytes.fromhex('31323334FFFFFFFF'))

    def test_card_derived_stored_length_and_pad_char(self):
        info = {'pin_ref': 0x82, 'stored_length': 6, 'pad_char': 0x00, 'min_length': 4}
        self.assertEqual(encode_pkcs15_pin('1234', info), bytes.fromhex('313233340000'))

    def test_rejects_pin_longer_than_stored_length(self):
        info = {'stored_length': 6, 'min_length': 4}
        with self.assertRaises(ValueError):
            encode_pkcs15_pin('1234567', info)

    def test_rejects_pin_shorter_than_min_length(self):
        with self.assertRaises(ValueError):
            encode_pkcs15_pin('12')  # default min 4

    def test_default_rejects_over_eight(self):
        with self.assertRaises(ValueError):
            encode_pkcs15_pin('123456789')


if __name__ == '__main__':
    unittest.main()