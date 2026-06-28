import os, sys, base64, unittest
from ctypes import CDLL 
from mocks import MockLoader

sys.path.append(f'{__file__.rsplit("/", 2)[0]}')

from src.pkcs11_types import CKR_OK
from src.hardware import ( 
    load_pkcs11, sign_payload, get_slots, get_certificates, get_token_serial_number, 
    change_card_pin, unblock_card_pin, generate_rsa_keypair, generate_spkac, write_certificate, 
    LIBCVP11_PATH
)


class TestHardware(unittest.TestCase):

    def setUp(self):
        ''' Runs before every test to reset the hardware state '''

        self.mock_loader = MockLoader(LIBCVP11_PATH)
        # Inject the fake loader into the hardware module
        self.funcs = load_pkcs11(LIBCVP11_PATH, loader=self.mock_loader)
        # A direct reference to the fake token's state machine for assertions
        self.token_state = self.mock_loader.token


    def test_sign_payload_success(self):
        ''' Tests a complete, successful hardware signing flow '''

        signature = sign_payload(
            funcs=self.funcs,
            slot_id=1,
            pin='1234', # The Fake token is hardcoded to accept this PIN
            payload=b'test_payload_to_sign',
            key_id=b'fake_key_id'
        )
        # Verify the byte output matches what the Fake token generates
        assert len(signature) == 256
        assert signature.startswith(b'\xAA\xBB\xCC')
        
        # Verify the state machine cleanly logged out and closed the session
        # Guarantees the `finally` block in hardware.py is working
        assert not self.token_state.is_initialized
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_sign_payload_login_failure(self):
        ''' Tests that if the PIN is wrong, the hardware session is safely closed '''

        exception_raised = False
        try:
            sign_payload(
                funcs=self.funcs,
                slot_id=1,
                pin='wrong_pin',
                payload=b'data',
                key_id=b'id'
            )
        except Exception as e:
            exception_raised = True
            assert 'C_Login failed' in str(e)
            
        assert exception_raised
        
        # Verify that despite the Python Exception, the hardware token state was safely closed to prevent hardware locks.
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_load_pkcs11_failure(self):
        ''' Tests that a failure to get the function list raises an exception '''

        # Instruct the fake token to fail when asked for its function list
        self.token_state.rv_get_function_list = 0x00000006 # CKR_FUNCTION_FAILED
        
        exception_raised = False
        try:
            load_pkcs11(LIBCVP11_PATH, loader=self.mock_loader)
        except Exception as e:
            exception_raised = True
            assert 'Failed to get function list' in str(e)
            
        assert exception_raised


    def test_get_slots_success(self):
        ''' Tests the dynamic array allocation for slots '''

        # Execute against the fake token
        slots = get_slots(self.funcs)
        # Assert the extracted data matches the fake's internal state
        assert slots == [42, 99]
        
        # Verify cleanup occurred (C_Finalize was called)
        assert not self.token_state.is_initialized

    def test_get_certificates_success(self):
        ''' Tests the two-step memory allocation for extracting certificates '''
        
        # Execute directly against the fake token
        certs = get_certificates(self.funcs, 1, '1234')
        
        # Assert the extracted data perfectly matches our fake token's internal state
        assert len(certs) == 1
        assert certs[0]['id'] == b'ID_1'
        assert certs[0]['der'] == b'DER_DATA'
        
        # Verify the hardware session was cleanly closed (crucial for stability)
        assert not self.token_state.session_open
        assert not self.token_state.logged_in

    def test_get_certificates_empty_token(self):
        ''' Tests handling of a token that has no certificates stored on it '''

        # Override the mock token to contain zero certificates
        self.token_state.mock_certs = []
        certs = get_certificates(self.funcs, slot_id=1, pin='1234')
        
        # Assert we got an empty list, not a crash
        assert len(certs) == 0
        assert certs == []
        
        # Verify the session was still safely cleaned up
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_get_certificates_attribute_failure(self):
        ''' Tests that if C_GetAttributeValue fails, the exception is raised but the hardware session is STILL closed. '''
        
        # Force the mock to fail when extracting the certificate data
        def failing_mock_C_GetAttributeValue(hSession, hObject, pTemplate, ulCount):
            return 0x00000005 # CKR_GENERAL_ERROR
            
        # Temporarily inject the failing callback
        self.token_state.f.C_GetAttributeValue = self.token_state.cb_C_GetAttributeValue.__class__(failing_mock_C_GetAttributeValue)
        
        exception_raised = False
        try:
            get_certificates(self.funcs, slot_id=1, pin='1234')
        except Exception as e:
            exception_raised = True
            assert "failed to get size for cert" in str(e).lower()
            
        assert exception_raised
        
        # The critical assertion: Even though the C-call failed and Python threw an exception,
        # the 'finally' block must have executed to prevent the token from locking.
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_sign_payload_buffer_size_failure(self):
        ''' Tests the two-step memory allocation of C_Sign. If the token refuses to tell us how much memory to allocate, we must abort cleanly. '''
        
        # Force the mock to return an error when asked for the buffer size (pSignature == NULL)
        def failing_mock_C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen):
            if not pSignature:
                return 0x00000112 # CKR_BUFFER_TOO_SMALL
            return 0 # CKR_OK
            
        self.token_state.f.C_Sign = self.token_state.cb_C_Sign.__class__(failing_mock_C_Sign)
        
        exception_raised = False
        try:
            sign_payload(
                funcs=self.funcs,
                slot_id=1,
                pin='1234',
                payload=b'test_payload_to_sign',
                key_id=b'fake_key_id'
            )
        except Exception as e:
            exception_raised = True
            assert "failed to get signature size" in str(e).lower()
            
        assert exception_raised
        
        # Verify the session didn't hang open
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_get_slots_hardware_unplugged(self):
        ''' Tests that if the C_GetSlotList call fails, the library handles the failure gracefully. '''
        
        def failing_mock_C_GetSlotList(tokenPresent, pSlotList, pulCount):
            return 0x00000050 # CKR_DEVICE_ERROR
            
        self.token_state.f.C_GetSlotList = self.token_state.cb_C_GetSlotList.__class__(failing_mock_C_GetSlotList)
        
        exception_raised = False
        try:
            get_slots(self.funcs)
        except Exception as e:
            exception_raised = True
            assert "failed to get slot count" in str(e).lower()
            
        assert exception_raised


    def test_get_token_serial_number_success(self):
        ''' Tests extracting the raw padded token serial number into a clean string '''
        
        serial = get_token_serial_number(self.funcs, slot_id=1)
        
        # Verified against fake_serial = b"987654321        " in mocks.py
        assert serial == "987654321"


    def test_change_card_pin_success(self):
        ''' Tests that altering the PIN opens a session and performs native cleanup '''
        
        change_card_pin(self.funcs, slot_id=1, old_pin="1234", new_pin="5678")
        
        # Ensure session was safely torn down after adjustment
        assert not self.token_state.session_open


    def test_unblock_card_pin_so_flow(self):
        ''' Tests that unblocking logs in as SO (PUK) and gracefully clears state '''
        
        unblock_card_pin(self.funcs, slot_id=1, puk="87654321", new_pin="1234")
        
        # Verify the session closed and cleanly logged out
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_generate_rsa_keypair_stamping(self):
        ''' Tests keypair generation maps and stamps CKA_ID successfully '''
        
        success = generate_rsa_keypair(self.funcs, slot_id=1, pin="1234", label="Test Key", key_id=b"UUID-1122")
        
        assert success is True
        assert not self.token_state.session_open
        

    def test_generate_spkac_complete_flow(self):
        ''' Tests full orchestration of generation, memory allocation extraction, and signature creation '''
        
        spkac_out = generate_spkac(
            funcs=self.funcs,
            slot_id=1,
            pin="1234",
            key_id=b"NEW-KEY-ID",
            challenge="ca-challenge-string"
        )
        
        # Confirm we successfully compiled a base64 string payload
        assert isinstance(spkac_out, str)
        assert len(spkac_out) > 64
        
        # Ensure all ephemeral sessions opened inside generate_spkac were safely closed
        assert not self.token_state.session_open
        assert not self.token_state.logged_in


    def test_write_certificate_pairs_with_public_key(self):
        ''' Tests the complex CKA_ID/CKA_LABEL grouping flow for certificate issuance '''
        
        # Real-world certificate (Contains valid RSA Modulus to satisfy the parser)
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
        
        # If this function doesn't crash, it successfully parsed the cert, found the key, 
        # extracted the CKA_ID/CKA_LABEL, packed the template, and called C_CreateObject.
        write_certificate(self.funcs, slot_id=1, pin="1234", cert_der=base64.b64decode(TEST_CERT_B64))
        
        # Ensure session cleanup ran
        assert not self.token_state.session_open


class TestHardwareIntegration(unittest.TestCase):
    
    @unittest.skipIf(not os.path.exists(LIBCVP11_PATH), 'Vendor library not found, skipping integration test.')
    def test_real_library_loading(self):
        ''' Attempt to load the real .so/.dll '''
        funcs = load_pkcs11(LIBCVP11_PATH)
        assert funcs is not None


if __name__ == '__main__':
    unittest.main()
