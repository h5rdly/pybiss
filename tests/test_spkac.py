import base64
import sys
import unittest

sys.path.append(f'{__file__.replace("\\", "/").rsplit("/", 2)[0]}')

from src.spkac import (
    _encode_der_len, _encode_der_int, _encode_der_sequence, 
    build_spkac_payload, assemble_final_spkac
)


class TestSpkacEncoding(unittest.TestCase):

    def test_encode_der_len_short(self):
        ''' Lengths less than 128 bytes occupy a single byte '''
        
        assert _encode_der_len(0) == b'\x00'
        assert _encode_der_len(127) == b'\x7f'


    def test_encode_der_len_long(self):
        ''' Lengths greater than or equal to 128 use multibyte format '''

        # 128 -> 0x80 | 1 length byte -> followed by 0x80
        assert _encode_der_len(128) == b'\x81\x80'
        # 256 -> 0x81 \x01\x00
        assert _encode_der_len(256) == b'\x82\x01\x00'


    def test_encode_der_int_positive(self):
        ''' Simple integers get wrapped in tag 0x02 '''

        raw_int = b'\x01\x02\x03'
        encoded = _encode_der_int(raw_int)
        assert encoded == b'\x02\x03\x01\x02\x03'


    def test_encode_der_int_leading_zeros(self):
        ''' Padding bytes from hardware are stripped safely '''

        padded_int = b'\x00\x00\x05\xaa'
        encoded = _encode_der_int(padded_int)
        assert encoded == b'\x02\x02\x05\xaa'


    def test_encode_der_int_sign_extension(self):
        ''' Prepend 0x00 if highest bit is set to preserve positive integer rule '''

        negative_looking_int = b'\x80\x11\x22'
        encoded = _encode_der_int(negative_looking_int)
        # Length becomes 4 instead of 3 due to added null byte boundary
        assert encoded == b'\x02\x04\x00\x80\x11\x22'


    def test_build_spkac_payload_structure(self):
        ''' Validates payload returns valid sequence wrapper '''

        modulus = b'\x00\xaa\xbb\xcc'
        exponent = b'\x01\x00\x01'
        challenge = "test-challenge"
        
        tbs_bytes = build_spkac_payload(modulus, exponent, challenge)
        
        # Structure must always start with an ASN.1 SEQUENCE tag
        assert tbs_bytes.startswith(b'\x30')
        assert challenge.encode('ascii') in tbs_bytes


    def test_assemble_final_spkac_base64(self):
        ''' Assembled outputs must be clear raw Base64 without newlines '''

        tbs_dummy = b'\x30\x05\x16\x03foo'
        sig_dummy = b'\xdd\xee\xff'
        
        spkac_b64 = assemble_final_spkac(tbs_dummy, sig_dummy)
        
        # Decode validation
        decoded_bytes = base64.b64decode(spkac_b64)
        assert decoded_bytes.startswith(b'\x30')
        assert b'foo' in decoded_bytes
        assert sig_dummy in decoded_bytes


if __name__ == '__main__':
    unittest.main()