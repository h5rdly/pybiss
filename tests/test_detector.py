import os, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])
from src import detector


class FakeEnv:
    ''' 
    Context manager to fake OS and FileSystem behavior natively, 
    avoiding the need for unittest.mock.
    '''

    def __init__(self, platform='linux', existing_paths=None, connected_atrs=None, pcsc_bindings=None):
        
        self.platform = platform
        self.existing_paths = existing_paths or []
        self.connected_atrs = connected_atrs
        self.pcsc_bindings = pcsc_bindings


    def __enter__(self):

        # Save original functions and state
        self.orig_platform = sys.platform
        self.orig_exists = os.path.exists
        self.orig_get_atrs = detector.get_connected_atrs
        self.orig_get_pcsc = detector._get_pcsc_bindings
        
        # Inject fakes
        sys.platform = self.platform
        
        # A simple fake filesystem check: if the path we injected is in the requested path, it "exists"
        os.path.exists = lambda path: any(fake_path in path for fake_path in self.existing_paths)
        
        if self.connected_atrs is not None:
            detector.get_connected_atrs = lambda: self.connected_atrs
            
        if self.pcsc_bindings is not None:
            detector._get_pcsc_bindings = lambda: self.pcsc_bindings


    def __exit__(self, exc_type, exc_val, exc_tb):
        
        # Restore everything so tests don't pollute each other
        sys.platform = self.orig_platform
        os.path.exists = self.orig_exists
        detector.get_connected_atrs = self.orig_get_atrs
        detector._get_pcsc_bindings = self.orig_get_pcsc


class TestDetector(unittest.TestCase):

    def test_identify_provider_known_atr(self):
        ''' Tests that known B-Trust ATRs correctly map to their vendors '''

        # Test Gemalto
        self.assertEqual(detector.identify_provider('3B7F96000080318065B0850300EF120FFE829000'), 'GEMALTO')
        # Test lowercase handling
        self.assertEqual(detector.identify_provider('3bf81300008131fe454a434f5076323431b7'), 'CRYPTOVISION')
        # Test Bit4ID
        self.assertEqual(detector.identify_provider('3BFF1800008131FE55006B02090603010101434E5310318067'), 'BIT4ID')


    def test_identify_provider_unknown_atr(self):
        ''' Tests that an unrecognized smart card returns None '''

        self.assertIsNone(detector.identify_provider('3B99999999999999999999999999999999999999'))


    def test_get_library_path_windows(self):
        ''' Tests Windows library resolution logic '''

        # Scenario 1: System-level eTPKCS11.dll exists
        with FakeEnv(platform='win32', existing_paths=['C:/Windows/System32/eTPKCS11.dll']):
            self.assertEqual(detector.get_library_path('GEMALTO'), 'C:/Windows/System32/eTPKCS11.dll')

        # Scenario 2: System-level doesn't exist, fall back to assets dir
        with FakeEnv(platform='win32', existing_paths=['IDPrimePKCS11_940.dll']):
            assets_path = detector.get_library_path('GEMALTO')
            self.assertIn('IDPrimePKCS11_940.dll', assets_path)
            self.assertIn('assets', assets_path)

        # Scenario 3: Bit4ID
        with FakeEnv(platform='win32', existing_paths=['C:/WINDOWS/system32/bit4ipki.dll']):
            self.assertEqual(detector.get_library_path('BIT4ID'), 'C:/WINDOWS/system32/bit4ipki.dll')


    def test_get_library_path_linux(self):
        ''' Tests Linux library resolution logic '''

        # Scenario 1: Bit4ID installed in /usr/lib64
        with FakeEnv(platform='linux', existing_paths=['/usr/lib64/libbit4ipki.so']):
            self.assertEqual(detector.get_library_path('BIT4ID'), '/usr/lib64/libbit4ipki.so')

        # Scenario 2: Cryptovision fallback to assets dir
        with FakeEnv(platform='linux', existing_paths=['libcvP11.so']):
            assets_path = detector.get_library_path('CRYPTOVISION')
            self.assertIn('libcvP11.so', assets_path)
            self.assertIn('assets', assets_path)


    def test_get_library_path_mac(self):
        ''' Tests macOS library resolution logic '''

        with FakeEnv(platform='darwin', existing_paths=['/Library/cv cryptovision/libcvP11.dylib']):
            self.assertEqual(detector.get_library_path('SIEMENS'), '/Library/cv cryptovision/libcvP11.dylib')


    def test_auto_detect_success(self):
        ''' Tests the successful end-to-end auto-detection flow '''
        
        # Fake a scenario where a Cryptovision card is plugged in, and its library exists in /usr/lib
        with FakeEnv(
            platform='linux', 
            existing_paths=['/usr/lib/libcvP11.so'],
            connected_atrs=['3BF81300008131FE454A434F5076323431B7']
        ):
            result = detector.auto_detect_library()
            self.assertEqual(result, '/usr/lib/libcvP11.so')


    def test_auto_detect_no_card(self):
        ''' Tests auto-detect returning None if no card is plugged in '''
        
        with FakeEnv(connected_atrs=[]):
            result = detector.auto_detect_library()
            self.assertIsNone(result)


    def test_get_connected_atrs_no_pcsc(self):

        ''' Tests that get_connected_atrs fails gracefully if PC/SC isn't installed on the OS '''
        
        with FakeEnv(pcsc_bindings=(None, None, None, False)):
            atrs = detector.get_connected_atrs()
            self.assertEqual(atrs, [])


if __name__ == '__main__':
    unittest.main()