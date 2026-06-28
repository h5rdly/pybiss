import base64,sys, unittest
from datetime import datetime, timezone

sys.path.append(f'{__file__.replace("\\", "/").rsplit("/", 2)[0]}')

from src.cert_parser import (
    DerReader, _decode_string, _parse_time, _parse_name, 
    get_x509_subject, get_x509_metadata, get_rsa_public_key
)

# Real-world certificate (Subject: CN=Testing)
REAL_CERT_B64 = (
    'MIICnTCCAYUCBgGAUN03JTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4X'
    'DTIyMDQyMjEwNDAxNloXDTMyMDQyMjEwNDE1NlowEjEQMA4GA1UEAwwHVGVzdGluZzCCASIw'
    'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJnn9zZF3+PvugbVDyo4ZVe6X+lb+xzIPlS'
    '/iE1/CkGUw+C081jt8fUT8FXqSo4H7yXvyImRWiV+/Pmu86XBvZqWRvHM6dwvJ2UrwCSqYb2'
    'C3fbPamKxjBVvbdXh8hsJiEDdNlV8B3mdCQ3eV+Iu7DuFz5DcnH80qMWkG7+8ADWAU3L3FnI'
    '2FcSI+GaWJErEKq6zk5uvRuxcrq7XxMRnO45UkXL/hrm6vytyECxxh05YpdtMKmZorNXSycK'
    'QI4E8WO7kEsBHaiRwiUd6u+m7A3pSAWaW0dO5KiDl6mLudsNMJAv9Vu/x3FTyzaek/zC9PT/'
    'IxrDlnzDvef83IZLHkMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi7ZppYbkpt0ALn5NXIIP'
    'gA04svRwAmsUJWKLBS5iKVXq6HOJPsz0GAB9oKpjar83rUomwK2UE0XFJLMDvrB0nTZJBjm2'
    'DCANLL1GtTKUd+mdvhyHCIMrUApkhAYzv2Rk1c4+Jt7f5/h8FnM8jdl9FGc5TBy5ixS0Oxny'
    'W1JOakClYQz8vNS7LrC4hmLWwy7GAmUdemNLEefQcECaNzaLN5gGk1ht5lJyNCsHu9STZeYM'
    '2UXdDAtMtu9HAepfzh2CAOscSDtZr89SmFSwxKaOfbJyXH4PivMgWK4zO0P6ofuv8d8gRbUA'
    'UgnysKHQc0isTVWOxgmzI69EUe/iVXJHig=='
)
CERT_BYTES = base64.b64decode(REAL_CERT_B64)


class TestCertParser(unittest.TestCase):

    def test_der_reader_basic_tlv(self):
        reader = DerReader(b'\x02\x03\x01\x02\x03')
        tag, val = reader.read_tlv()
        assert tag == 0x02
        assert val == b'\x01\x02\x03'


    def test_der_reader_multibyte_length(self):
        ''' Proves the reader correctly parses lengths >= 128 bytes '''

        payload = b'\x04\x81\x80' + (b'A' * 128)
        reader = DerReader(payload)
        tag, val = reader.read_tlv()
        assert tag == 0x04
        assert len(val) == 128


    def test_der_reader_eof_protection(self):
        ''' Prevents memory/out-of-bounds panics on truncated payloads '''

        reader = DerReader(b'\x02\x05\x00') # Claims 5 bytes, only has 1
        exception_raised = False
        try:
            reader.read_tlv()
        except ValueError:
            exception_raised = True
        assert exception_raised


    def test_decode_string_bmp(self):
        ''' Enterprise AD CS certs often use BMPString (UTF-16 BE) '''

        utf16_bytes = 'Enterprise User'.encode('utf-16-be')
        decoded = _decode_string(0x1E, utf16_bytes)
        assert decoded == 'Enterprise User'


    def test_decode_string_utf8(self):
        ''' Standard UTF8 String (Cyrillic support test) '''

        utf8_bytes = 'Иван Иванов'.encode('utf-8')
        decoded = _decode_string(0x0C, utf8_bytes)
        assert decoded == 'Иван Иванов'


    def test_parse_time_utc(self):
        ''' Parses UTCTime (2-digit year) '''

        ts = _parse_time(0x17, b'220422104016Z')
        expected = int(datetime(2022, 4, 22, 10, 40, 16, tzinfo=timezone.utc).timestamp())
        assert ts == expected


    def test_parse_time_generalized(self):
        ''' Parses GeneralizedTime (4-digit year) '''

        ts = _parse_time(0x18, b'20320422104016Z')
        expected = int(datetime(2032, 4, 22, 10, 40, 16, tzinfo=timezone.utc).timestamp())
        assert ts == expected

    def test_get_x509_subject(self):
        ''' Extracts the exact Common Name string natively '''
        subject = get_x509_subject(CERT_BYTES)
        assert subject == 'Testing'


    def test_get_x509_metadata(self):
        ''' Ensures complete, accurate extraction of all required routing data '''

        meta = get_x509_metadata(CERT_BYTES)
        
        assert isinstance(meta, dict)
        assert meta['issuer'] == 'CN=Testing'
        assert meta['subject'] == 'CN=Testing'
        assert isinstance(meta['not_before'], int)
        assert isinstance(meta['not_after'], int)
        assert meta['not_after'] > meta['not_before']
        
        # Verify Key Usage extraction works (this cert has no usages, but the structure parses)
        assert isinstance(meta['key_usages'], list)
        
        # Verify RSA public key integers were extracted safely
        assert isinstance(meta['n'], int)
        assert isinstance(meta['e'], int)
        assert meta['e'] == 65537


    def test_get_rsa_public_key(self):
        ''' Extracts just the n and e values for the Verifier '''

        n, e = get_rsa_public_key(CERT_BYTES)
        assert isinstance(n, int)
        assert e == 65537


if __name__ == '__main__':
    unittest.main()