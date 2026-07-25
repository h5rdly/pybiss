import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.backends import apdu_whitelist, known_apdu_atrs, resolve, OP_READ, OP_SIGN, OP_PIN, OP_MANAGE


WHITELISTED_ATR = '3B7F96000080318065B0855956FB120FFE829000'   # IDPrime 940 (known family)
STRANGER_ATR = '3B99999999999999999999999999999999999999'      # no family we drive


class FakeConfig:
    def __init__(self, **kw):
        self._d = kw
    def get(self, key, fallback=None):
        return self._d.get(key, fallback)


class TestResolveDefaults(unittest.TestCase):
    ''' Empty whitelist (today's reality): behaviour must match the old code '''

    def test_linux_default_is_pkcs11_only(self):
        for op in (OP_READ, OP_SIGN):
            assert resolve(op, platform='linux', config=FakeConfig()) == ['pkcs11']

    def test_macos_default_is_pkcs11_only(self):
        assert resolve(OP_SIGN, platform='darwin', config=FakeConfig()) == ['pkcs11']

    def test_windows_default_primary_pkcs11_then_cng(self):
        # signAPI defaults to PKCS11 -> pkcs11 primary, cng as fallback, no apdu
        assert resolve(OP_SIGN, platform='win32', config=FakeConfig()) == ['pkcs11', 'cng']

    def test_windows_mscapi_primary_cng_then_pkcs11(self):
        cfg = FakeConfig(signAPI='MSCAPI')
        assert resolve(OP_SIGN, platform='win32', config=cfg) == ['cng', 'pkcs11']

    def test_no_apdu_for_unknown_card_without_whitelist(self):
        # A stranger card gets no APDU path unless the user explicitly opts in.
        # (A known IDPrime-family ATR IS auto-trusted - see TestKnownFamilyAutoTrust.)
        for plat in ('linux', 'darwin', 'win32'):
            for op in (OP_READ, OP_SIGN, OP_PIN):
                assert 'apdu' not in resolve(op, platform=plat, atr=STRANGER_ATR, config=FakeConfig())


class TestResolveCapabilities(unittest.TestCase):

    def test_manage_is_pkcs11_only(self):
        # CNG and APDU cannot manage on-card objects
        assert resolve(OP_MANAGE, platform='win32', config=FakeConfig()) == ['pkcs11']
        assert resolve(OP_MANAGE, platform='linux', config=FakeConfig()) == ['pkcs11']

    def test_manage_never_routes_to_apdu_even_when_whitelisted(self):
        cfg = FakeConfig(apduWhitelist=WHITELISTED_ATR)
        assert resolve(OP_MANAGE, platform='linux', atr=WHITELISTED_ATR, config=cfg) == ['pkcs11']

    def test_cng_absent_off_windows(self):
        for plat in ('linux', 'darwin'):
            for op in (OP_READ, OP_SIGN):
                assert 'cng' not in resolve(op, platform=plat, config=FakeConfig())


class TestResolveWhitelistedApdu(unittest.TestCase):
    ''' A validated ATR lights up the APDU path per the OS policy '''

    def setUp(self):
        self.cfg = FakeConfig(apduWhitelist=f'  {WHITELISTED_ATR} , other ')

    def test_linux_prefers_apdu_for_validated_card(self):
        assert resolve(OP_SIGN, platform='linux', atr=WHITELISTED_ATR, config=self.cfg) == ['apdu', 'pkcs11']

    def test_linux_read_prefers_apdu_for_validated_card(self):
        assert resolve(OP_READ, platform='linux', atr=WHITELISTED_ATR, config=self.cfg) == ['apdu', 'pkcs11']

    def test_windows_keeps_apdu_last(self):
        assert resolve(OP_SIGN, platform='win32', atr=WHITELISTED_ATR, config=self.cfg) == ['pkcs11', 'cng', 'apdu']

    def test_pin_via_apdu_only_for_validated_card(self):
        assert resolve(OP_PIN, platform='linux', atr=WHITELISTED_ATR, config=self.cfg) == ['apdu', 'pkcs11']
        # A different, non-whitelisted card gets no APDU
        assert resolve(OP_PIN, platform='linux', atr='AABBCC', config=self.cfg) == ['pkcs11']

    def test_whitelist_matching_is_case_insensitive(self):
        cfg = FakeConfig(apduWhitelist=WHITELISTED_ATR.lower())
        assert 'apdu' in resolve(OP_SIGN, platform='linux', atr=WHITELISTED_ATR.upper(), config=cfg)


class TestKnownFamilyAutoTrust(unittest.TestCase):
    '''
    The IDPrime families the APDU driver is written for are implicitly trusted:
    a fresh install signs driver-free with zero configuration. Only unknown
    families still need the explicit apduWhitelist opt-in.
    '''

    def test_known_atrs_come_from_the_driver(self):
        from src.cards import IDPRIME_ATRS
        assert known_apdu_atrs() == {a.upper() for a in IDPRIME_ATRS}

    def test_known_family_gets_apdu_with_no_config_at_all(self):
        assert resolve(OP_SIGN, platform='linux', atr=WHITELISTED_ATR, config=FakeConfig()) == ['apdu', 'pkcs11']

    def test_known_family_is_case_insensitive(self):
        assert 'apdu' in resolve(OP_SIGN, platform='linux',
                                      atr=WHITELISTED_ATR.lower(), config=FakeConfig())

    def test_users_real_card_is_auto_trusted(self):
        # The B-Trust QES MiniDriver card this project is validated against.
        atr = '3B7F96000080318065B085050039120FFE829000'
        assert resolve(OP_SIGN, platform='linux', atr=atr, config=FakeConfig()) == ['apdu', 'pkcs11']

    def test_stranger_still_needs_the_explicit_opt_in(self):
        assert resolve(OP_SIGN, platform='linux', atr=STRANGER_ATR, config=FakeConfig()) == ['pkcs11']
        cfg = FakeConfig(apduWhitelist=STRANGER_ATR)
        assert resolve(OP_SIGN, platform='linux', atr=STRANGER_ATR, config=cfg) == ['apdu', 'pkcs11']

    def test_windows_keeps_auto_trusted_apdu_last(self):
        assert resolve(OP_SIGN, platform='win32', atr=WHITELISTED_ATR, config=FakeConfig()) == ['pkcs11', 'cng', 'apdu']

    def test_manage_never_routes_to_apdu_even_for_known_family(self):
        assert resolve(OP_MANAGE, platform='linux', atr=WHITELISTED_ATR, config=FakeConfig()) == ['pkcs11']


class TestApduWhitelist(unittest.TestCase):

    def test_empty_config_gives_empty_set(self):
        assert apdu_whitelist(None) == set()
        assert apdu_whitelist(FakeConfig()) == set()

    def test_parses_and_normalises(self):
        cfg = FakeConfig(apduWhitelist='3b7f, ABCD ,')
        assert apdu_whitelist(cfg) == {'3B7F', 'ABCD'}


if __name__ == '__main__':
    unittest.main()
