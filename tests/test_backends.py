import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.backends import apdu_whitelist, resolve, OP_READ, OP_SIGN, OP_PIN, OP_MANAGE


WHITELISTED_ATR = '3B7F96000080318065B0855956FB120FFE829000'


class FakeConfig:
    def __init__(self, **kw):
        self._d = kw
    def get(self, key, fallback=None):
        return self._d.get(key, fallback)


class TestResolveDefaults(unittest.TestCase):
    ''' Empty whitelist (today's reality): behaviour must match the old code '''

    def test_linux_default_is_pkcs11_only(self):
        for op in (OP_READ, OP_SIGN):
            self.assertEqual(resolve(op, platform='linux', config=FakeConfig()), ['pkcs11'])

    def test_macos_default_is_pkcs11_only(self):
        self.assertEqual(resolve(OP_SIGN, platform='darwin', config=FakeConfig()), ['pkcs11'])

    def test_windows_default_primary_pkcs11_then_cng(self):
        # signAPI defaults to PKCS11 -> pkcs11 primary, cng as fallback, no apdu
        self.assertEqual(resolve(OP_SIGN, platform='win32', config=FakeConfig()), ['pkcs11', 'cng'])

    def test_windows_mscapi_primary_cng_then_pkcs11(self):
        cfg = FakeConfig(signAPI='MSCAPI')
        self.assertEqual(resolve(OP_SIGN, platform='win32', config=cfg), ['cng', 'pkcs11'])

    def test_no_apdu_without_whitelist_anywhere(self):
        for plat in ('linux', 'darwin', 'win32'):
            for op in (OP_READ, OP_SIGN, OP_PIN):
                self.assertNotIn('apdu', resolve(op, platform=plat, atr=WHITELISTED_ATR, config=FakeConfig()))


class TestResolveCapabilities(unittest.TestCase):

    def test_manage_is_pkcs11_only(self):
        # CNG and APDU cannot manage on-card objects
        self.assertEqual(resolve(OP_MANAGE, platform='win32', config=FakeConfig()), ['pkcs11'])
        self.assertEqual(resolve(OP_MANAGE, platform='linux', config=FakeConfig()), ['pkcs11'])

    def test_manage_never_routes_to_apdu_even_when_whitelisted(self):
        cfg = FakeConfig(apduWhitelist=WHITELISTED_ATR)
        self.assertEqual(resolve(OP_MANAGE, platform='linux', atr=WHITELISTED_ATR, config=cfg), ['pkcs11'])

    def test_cng_absent_off_windows(self):
        for plat in ('linux', 'darwin'):
            for op in (OP_READ, OP_SIGN):
                self.assertNotIn('cng', resolve(op, platform=plat, config=FakeConfig()))


class TestResolveWhitelistedApdu(unittest.TestCase):
    ''' A validated ATR lights up the APDU path per the OS policy '''

    def setUp(self):
        self.cfg = FakeConfig(apduWhitelist=f'  {WHITELISTED_ATR} , other ')

    def test_linux_prefers_apdu_for_validated_card(self):
        self.assertEqual(resolve(OP_SIGN, platform='linux', atr=WHITELISTED_ATR, config=self.cfg),
                         ['apdu', 'pkcs11'])

    def test_linux_read_prefers_apdu_for_validated_card(self):
        self.assertEqual(resolve(OP_READ, platform='linux', atr=WHITELISTED_ATR, config=self.cfg),
                         ['apdu', 'pkcs11'])

    def test_windows_keeps_apdu_last(self):
        self.assertEqual(resolve(OP_SIGN, platform='win32', atr=WHITELISTED_ATR, config=self.cfg),
                         ['pkcs11', 'cng', 'apdu'])

    def test_pin_via_apdu_only_for_validated_card(self):
        self.assertEqual(resolve(OP_PIN, platform='linux', atr=WHITELISTED_ATR, config=self.cfg),
                         ['apdu', 'pkcs11'])
        # A different, non-whitelisted card gets no APDU
        self.assertEqual(resolve(OP_PIN, platform='linux', atr='AABBCC', config=self.cfg), ['pkcs11'])

    def test_whitelist_matching_is_case_insensitive(self):
        cfg = FakeConfig(apduWhitelist=WHITELISTED_ATR.lower())
        self.assertIn('apdu', resolve(OP_SIGN, platform='linux', atr=WHITELISTED_ATR.upper(), config=cfg))


class TestApduWhitelist(unittest.TestCase):

    def test_empty_config_gives_empty_set(self):
        self.assertEqual(apdu_whitelist(None), set())
        self.assertEqual(apdu_whitelist(FakeConfig()), set())

    def test_parses_and_normalises(self):
        cfg = FakeConfig(apduWhitelist='3b7f, ABCD ,')
        self.assertEqual(apdu_whitelist(cfg), {'3B7F', 'ABCD'})


if __name__ == '__main__':
    unittest.main()
