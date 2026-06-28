import base64, sys, hashlib, unittest 
from unittest.mock import patch

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import src.service as service

# --- Test Vectors  ---

# X.509 Certificate (Contains N and E)
# Subject: CN=Test Certificate, OU=Test Certificate, O=PyJWT, L=Austin, ST=Texas, C=US
# Valid from: 2015-03-18 to 2018-03-17
TEST_CERT_B64 = (
    "MIIDhTCCAm2gAwIBAgIJANE4sir3EkX8MA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV"
    "BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEPMA0GA1UEBwwGQXVzdGluMQ4wDAYDVQQK"
    "DAVQeUpXVDEZMBcGA1UECwwQVGVzdCBDZXJ0aWZpY2F0ZTAeFw0xNTAzMTgwMTE2"
    "MTRaFw0xODAzMTcwMTE2MTRaMFkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh"
    "czEPMA0GA1UEBwwGQXVzdGluMQ4wDAYDVQQKDAVQeUpXVDEZMBcGA1UECwwQVGVz"
    "dCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANR4"
    "MwXyb9nDo0K8gsHvDRHpa4jkzRVimVIr3r1K0YZanJmSXQr7giUa/sQjfjpjvKsI"
    "CSUffH3jbo8VYPifS7N/1DgOB3BfZ2B+mqlVxCwBPB5PwC78YveprNQw7gL0BmmG"
    "fpQDcZb8XkBTmUm45M//ZofGi3hisKiS6d6fjoVAUKcLwFAD4PNvjlLYE1t50pY4"
    "3ha9eAfKgJ3hknP8JdJ4vvtUkWVFxUqL83KkDpJWt1tu66y36w+i14I/07A7OLw9"
    "T5yJtc3FXpyk+032CNe27Bvzv1nnMM9jZdfaS+4A6LDa7hd6ICVjatS8p/4oz0J5"
    "Dy6WR8ob7osnGHCNw4kCAwEAAaNQME4wHQYDVR0OBBYEFDR6fVdFxZED6YMmD62W"
    "LlBW+qEBMB8GA1UdIwQYMBaAFDR6fVdFxZED6YMmD62WLlBW+qEBMAwGA1UdEwQF"
    "MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFwDNwm+lU/kGfWwiWM0Lv2aosXotoiG"
    "TsBSWIn2iYphq0vzlgChcNocN9zkaOz3zc9pcREP6lyqHpE0OEbNucHHDdU1L2he"
    "lLFOLOmkpP5fyPDXs9nKYhO8ygMByEonHm3K/VvCgrsSgJ3JuxMLUxnE55jQXGWV"
    "OqYQNo2J5h93Zd2HTTe19jCz+bbWnRBP5VvLAAAo5YSmk3iroWSPWAKkWOOecJ2Q"
    "/xnRyuWERsfvZiF/m9q7yDJ55LXVVm3Rufmy76SoTnJ2acap+XQNXBH/AxayeLUS"
    "OYmHWH61dUcsQtwXYHYRB8TTtMIwUCXGmthXkDJydEfrGcD0y6APIh8="
)
CERT_BYTES = base64.b64decode(TEST_CERT_B64)


def _b64_to_int(b64_str: str) -> int:
    ''' The matching private Modulus (N) and Exponent (D) to sign test data '''

    padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), 'big')


TEST_N = _b64_to_int("1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27rrLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDosNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ")
TEST_D = _b64_to_int("rfbs8AWdB1RkLJRlC51LukrAvYl5UfU1TE6XRa4o-DTg2-03OXLNEMyVpMra47weEnu14StypzC8qXL7vxXOyd30SSFTffLfleaTg-qxgMZSDw-Fb_M-pUHMPMEDYG-lgGma4l4fd1yTX2ATtoUo9BVOQgWS1LMZqi0ASEOkUfzlBgL04UoaLhPSuDdLygdlDzgruVPnec0t1uOEObmrcWIkhwU2CGQzeLtuzX6OVgPhk7xcnjbDurTTVpWH0R0gbZ5ukmQ2P-YuCX8T9iWNMGjPNSkb7h02s2Oe9ZRzP007xQ0VF-Z7xyLuxk6ASmoX1S39ujSbk2WF0eXNPRgFwQ")


def sign_rsa_pkcs1_v1_5(payload: bytes, n: int, d: int) -> bytes:
    ''' Native RSA Signer. Applies PKCS#1 v1.5 padding and mathematically signs using d. '''
    
    h = hashlib.sha256(payload).digest()
    prefix = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    t = prefix + h
    
    k = (n.bit_length() + 7) // 8
    ps_len = k - len(t) - 3
    em = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + t
    
    m = int.from_bytes(em, 'big')
    s = pow(m, d, n)

    return s.to_bytes(k, 'big')


class TestService(unittest.TestCase):

    # -- Certificate Filtering Tests 

    def test_filter_certificates_by_issuer_real(self):
        ''' Extracting and filtering by Issuer DN '''

        certs = [{'id': b'1', 'der': CERT_BYTES}]
        
        filtered = service.filter_certificates(certs, selector={'issuers': ['Test Certificate']}, show_valid_certs=False)
        assert len(filtered) == 1
        assert 'PyJWT' in filtered[0]['issuer']
        
        filtered_bad = service.filter_certificates(certs, selector={'issuers': ['Hacker CA']}, show_valid_certs=False)
        assert len(filtered_bad) == 0


    @patch('time.time')
    def test_filter_certificates_validity_dates_real(self, mock_time):
        ''' Freezes time to test real certificate expiration boundaries natively '''

        certs = [{'id': b'1', 'der': CERT_BYTES}]
        
        # Freeze time to 2016 (Inside the 2015-2018 validity window)
        mock_time.return_value = 1451606400
        valid_certs = service.filter_certificates(certs, selector=None, show_valid_certs=True)
        assert len(valid_certs) == 1

        # Freeze time to 2020 (Expired)
        mock_time.return_value = 1577836800 
        expired_certs = service.filter_certificates(certs, selector=None, show_valid_certs=True)
        assert len(expired_certs) == 0


    # -- Signature Verification Tests

    def test_verify_server_signature_scheme_a_success(self):
        ''' Service flawlessly identifies and authenticates Scheme A (Hash + Payload) natively '''
        
        payload = b"financial-transaction-data"
        
        # Manually construct Scheme A's expected hash buffer and sign it
        payload_hash = hashlib.sha256(payload).digest()
        combined_data = payload_hash + payload
        signature = sign_rsa_pkcs1_v1_5(combined_data, TEST_N, TEST_D)
        
        # Service parses CERT_BYTES for N/E, hashes the payload, and validates
        verified = service.verify_server_signature(
            payload=payload, 
            signature=signature, 
            server_cert_der=CERT_BYTES, 
            hash_alg='SHA256'
        )
        
        assert verified is True


    def test_verify_server_signature_scheme_b_fallback(self):
        ''' Service automatically falls back to Scheme B (Payload Only) and authenticates natively '''
        
        payload = b"financial-transaction-data"
        
        # Sign ONLY the payload
        signature = sign_rsa_pkcs1_v1_5(payload, TEST_N, TEST_D)
        
        verified = service.verify_server_signature(
            payload=payload, 
            signature=signature, 
            server_cert_der=CERT_BYTES, 
            hash_alg='SHA256'
        )
        
        assert verified is True


    def test_verify_server_signature_tampered_fails(self):
        ''' Altered payloads securely fail mathematical validation '''
        
        payload = b"financial-transaction-data"
        signature = sign_rsa_pkcs1_v1_5(payload, TEST_N, TEST_D)
        
        tampered_payload = payload + b"hacked"
        verified = service.verify_server_signature(
            payload=tampered_payload, 
            signature=signature, 
            server_cert_der=CERT_BYTES, 
            hash_alg='SHA256'
        )
        
        assert verified is False


if __name__ == '__main__':
    unittest.main()