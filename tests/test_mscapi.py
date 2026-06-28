import sys, unittest
from unittest.mock import patch

from mocks import FakeMSCAPI, DummyWindowsLibrary

sys.path.append(f'{__file__.replace("\\", "/").rsplit("/", 2)[0]}')

import src.mscapi as mscapi


class TestMSCAPI(unittest.TestCase):

    def setUp(self):

        # Force the module to believe it's running on Windows
        self.is_windows_patcher = patch('src.mscapi.IS_WINDOWS', True)
        self.is_windows_patcher.start()

        self.state = FakeMSCAPI()
        
        # Build the fake crypt32.dll
        self.mock_crypt32 = DummyWindowsLibrary()
        self.mock_crypt32.CertOpenStore = self.state.cb_CertOpenStore
        self.mock_crypt32.CertEnumCertificatesInStore = self.state.cb_CertEnumCertificatesInStore
        self.mock_crypt32.CertDuplicateCertificateContext = self.state.cb_CertDuplicateCertificateContext
        self.mock_crypt32.CertFreeCertificateContext = self.state.cb_CertFreeCertificateContext
        self.mock_crypt32.CertCloseStore = self.state.cb_CertCloseStore
        self.mock_crypt32.CryptAcquireCertificatePrivateKey = self.state.cb_CryptAcquireCertificatePrivateKey
        self.mock_crypt32.CryptReleaseContext = self.state.cb_CryptReleaseContext
        
        # Build the fake ncrypt.dll
        self.mock_ncrypt = DummyWindowsLibrary()
        self.mock_ncrypt.NCryptSetProperty = self.state.cb_NCryptSetProperty
        self.mock_ncrypt.NCryptSignHash = self.state.cb_NCryptSignHash
        self.mock_ncrypt.NCryptFreeObject = self.state.cb_NCryptFreeObject

        # Inject them into mscapi
        self.crypt32_patcher = patch('src.mscapi.crypt32', self.mock_crypt32, create=True)
        self.ncrypt_patcher = patch('src.mscapi.ncrypt', self.mock_ncrypt, create=True)

        self.crypt32_patcher.start()
        self.ncrypt_patcher.start()

    def tearDown(self):
        self.is_windows_patcher.stop()
        self.crypt32_patcher.stop()
        self.ncrypt_patcher.stop()


    def test_get_windows_certificates_success(self):
        ''' PROVES: Retrieves, duplicates, and securely un-pointers Windows certificates '''
        
        certs = mscapi.get_windows_certificates()
        assert len(certs) == 1
        assert certs[0]['der'] == b'der_certificate_data' 
        assert certs[0]['windows_ctx'] == 99999


    @patch('src.mscapi.CERT_STORE_PROV_SYSTEM', 0)
    def test_get_windows_certificates_store_fail(self):
        ''' Gracefully raises if the System Store cannot be opened '''

        with self.assertRaises(Exception) as context:
            mscapi.get_windows_certificates()
        assert "Failed to open Windows Certificate Store" in str(context.exception)


    def test_free_windows_certificate(self):
        ''' Securely frees duplicated memory contexts '''

        mscapi.free_windows_certificate(99999)
        assert self.state.contexts_freed == 1
        mscapi.free_windows_certificate(None)


    def test_sign_payload_windows_success(self):
        ''' End-to-end CNG signing passes PIN, sizes buffer, and signs payload natively '''

        signature = mscapi.sign_payload_windows(
            cert_ctx_pointer=123, 
            payload=b'transaction_data', 
            pin='1234', 
            hash_alg='SHA256'
        )
        assert self.state.last_pin_bytes == b'1\x002\x003\x004\x00\x00\x00' 
        assert len(signature) == 256


    def test_sign_payload_windows_legacy_csp_rejected(self):
        ''' Legacy CSP hardware providers are securely rejected '''

        self.state.is_legacy_csp = True
        with self.assertRaises(Exception) as context:
            mscapi.sign_payload_windows(cert_ctx_pointer=123, payload=b'data')
        assert "Legacy CSP keys are not supported" in str(context.exception)


    @patch('src.mscapi.GetLastError', return_value=5, create=True)
    def test_sign_payload_windows_acquire_fails(self, mock_get_last_error):
        ''' Windows crypto failures bubble up natively '''

        self.state.acquire_should_fail = True
        with self.assertRaises(Exception) as context:
            mscapi.sign_payload_windows(cert_ctx_pointer=123, payload=b'data')
        assert "Failed to acquire private key" in str(context.exception)


    def test_non_windows_os_blocks_execution(self):
        ''' Running the module on Linux/Mac fails safely without crashing '''

        with patch('src.mscapi.IS_WINDOWS', False):
            certs = mscapi.get_windows_certificates()
            assert certs == []
            
            with self.assertRaises(Exception) as ctx:
                mscapi.sign_payload_windows(123, b'payload')
            assert "Windows native signing is not supported on this OS" in str(ctx.exception)
            
            mscapi.free_windows_certificate(123)


if __name__ == '__main__':
    unittest.main()