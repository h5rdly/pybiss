import sys, unittest
import types

from mocks import FakeMSCAPI, DummyWindowsLibrary

sys.path.append(f'{__file__.replace("\\", "/").rsplit("/", 2)[0]}')

import src.mscapi as mscapi


class TestMSCAPI(unittest.TestCase):

    def setUp(self):

        self.state = FakeMSCAPI()

        # Build the fake crypt32.dll
        self.mock_crypt32 = DummyWindowsLibrary()
        self.mock_crypt32.CertOpenStore = self.state.cb_CertOpenStore
        self.mock_crypt32.CertEnumCertificatesInStore = self.state.cb_CertEnumCertificatesInStore
        self.mock_crypt32.CertDuplicateCertificateContext = self.state.cb_CertDuplicateCertificateContext
        self.mock_crypt32.CertFreeCertificateContext = self.state.cb_CertFreeCertificateContext
        self.mock_crypt32.CertCloseStore = self.state.cb_CertCloseStore
        self.mock_crypt32.CryptAcquireCertificatePrivateKey = self.state.cb_CryptAcquireCertificatePrivateKey

        # Build the fake advapi32.dll (CryptReleaseContext lives here, not in crypt32)
        self.mock_advapi32 = DummyWindowsLibrary()
        self.mock_advapi32.CryptReleaseContext = self.state.cb_CryptReleaseContext

        # Build the fake ncrypt.dll
        self.mock_ncrypt = DummyWindowsLibrary()
        self.mock_ncrypt.NCryptSetProperty = self.state.cb_NCryptSetProperty
        self.mock_ncrypt.NCryptSignHash = self.state.cb_NCryptSignHash
        self.mock_ncrypt.NCryptFreeObject = self.state.cb_NCryptFreeObject

        # Inject them the same way hardware tests inject a loader: as a parameter
        self.libs = mscapi.NativeLibs(
            self.mock_crypt32, self.mock_ncrypt, self.mock_advapi32,
            get_last_error=lambda: 0,
        )


    def test_get_windows_certificates_success(self):
        ''' PROVES: Retrieves, duplicates, and securely un-pointers Windows certificates '''

        certs = mscapi.get_windows_certificates(libs=self.libs)
        assert len(certs) == 1
        assert certs[0]['der'] == b'der_certificate_data'
        assert certs[0]['windows_ctx'] == 99999


    def test_get_windows_certificates_store_fail(self):
        ''' Gracefully raises if the System Store cannot be opened '''

        self.libs.crypt32.CertOpenStore = lambda *args: None
        context = None
        try:
            mscapi.get_windows_certificates(libs=self.libs)
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert "Failed to open Windows Certificate Store" in str(context.exception)


    def test_free_windows_certificate(self):
        ''' Securely frees duplicated memory contexts '''

        mscapi.free_windows_certificate(99999, libs=self.libs)
        assert self.state.contexts_freed == 1
        mscapi.free_windows_certificate(None, libs=self.libs)


    def test_sign_payload_windows_success(self):
        ''' End-to-end CNG signing passes PIN, sizes buffer, and signs payload natively '''

        signature = mscapi.sign_payload_windows(
            cert_ctx_pointer=123,
            payload=b'transaction_data',
            pin='1234',
            hash_alg='SHA256',
            libs=self.libs,
        )
        assert self.state.last_pin_bytes == b'1\x002\x003\x004\x00\x00\x00'
        assert len(signature) == 256


    def test_sign_payload_windows_legacy_csp_rejected(self):
        ''' Legacy CSP hardware providers are securely rejected '''

        self.state.is_legacy_csp = True
        context = None
        try:
            mscapi.sign_payload_windows(cert_ctx_pointer=123, payload=b'data', libs=self.libs)
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert "Legacy CSP keys are not supported" in str(context.exception)


    def test_sign_payload_windows_acquire_fails(self):
        ''' Windows crypto failures bubble up natively '''

        self.state.acquire_should_fail = True
        self.libs.get_last_error = lambda: 5
        context = None
        try:
            mscapi.sign_payload_windows(cert_ctx_pointer=123, payload=b'data', libs=self.libs)
        except Exception as _e:
            context = types.SimpleNamespace(exception=_e)
        assert context is not None, 'Exception not raised'
        assert "Failed to acquire private key" in str(context.exception)
        assert "5" in str(context.exception)


    @unittest.skipIf(sys.platform == 'win32', 'Real DLLs would be bound on Windows')
    def test_non_windows_os_blocks_execution(self):
        ''' Running the module on Linux/Mac fails safely without crashing '''

        certs = mscapi.get_windows_certificates()
        assert certs == []

        ctx = None
        try:
            mscapi.sign_payload_windows(123, b'payload')
        except Exception as _e:
            ctx = types.SimpleNamespace(exception=_e)
        assert ctx is not None, 'Exception not raised'
        assert "Windows native signing is not supported on this OS" in str(ctx.exception)

        mscapi.free_windows_certificate(123)


if __name__ == '__main__':
    unittest.main()
