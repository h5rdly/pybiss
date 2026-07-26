import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import card_service, backends


class TestDispatchSafety(unittest.TestCase):
    ''' The heart of the facade: engine fall-through rules, PIN-safety included. '''

    def test_falls_through_on_backend_unavailable(self):
        calls = []

        def apdu():
            calls.append('apdu')
            raise backends.BackendUnavailable('no card here')

        def pkcs11():
            calls.append('pkcs11')
            return 'ok'

        result = card_service._dispatch(['apdu', 'pkcs11'],
                                        {'apdu': apdu, 'pkcs11': pkcs11}, 'x')
        assert result == 'ok'
        assert calls == ['apdu', 'pkcs11']          # unavailable -> tried the next

    def test_operational_error_never_retries_another_engine(self):
        ''' A WRONG PIN must propagate at once - retrying would burn a 2nd attempt. '''

        calls = []

        def apdu():
            calls.append('apdu')
            raise Exception('Incorrect PIN. 2 retries remaining.')

        def pkcs11():
            calls.append('pkcs11')                  # must NEVER run
            return 'ok'

        raised = None
        try:
            card_service._dispatch(['apdu', 'pkcs11'],
                                   {'apdu': apdu, 'pkcs11': pkcs11}, 'change the PIN')
        except Exception as e:
            raised = e
        assert raised is not None and 'Incorrect PIN' in str(raised)
        assert calls == ['apdu']                    # the second engine was NOT tried

    def test_empty_order_raises_backend_unavailable(self):
        raised = None
        try:
            card_service._dispatch([], {}, 'do a thing')
        except backends.BackendUnavailable as e:
            raised = e
        assert raised is not None

    def test_skips_a_backend_without_an_impl(self):
        calls = []
        result = card_service._dispatch(
            ['cng', 'pkcs11'],                      # cng has no impl here
            {'pkcs11': lambda: (calls.append('pkcs11') or 'ok')}, 'x')
        assert result == 'ok' and calls == ['pkcs11']


class TestRouting(unittest.TestCase):
    ''' Public calls resolve the right operation and hit the resolved engine. '''

    class FakeDriver:
        def __init__(self):
            self.calls = []

        def change_pin(self, old, new):
            self.calls.append(('change_pin', old, new)); return True

        def unblock_pin(self, puk, new):
            self.calls.append(('unblock_pin', puk, new)); return True

        def discover_certificates(self):
            self.calls.append(('discover',)); return [{'der': b'x'}]

    def setUp(self):
        self._resolve = backends.resolve
        self._atr = card_service._detected_atr
        self.driver = self.FakeDriver()
        self._apdu = card_service._with_apdu_driver
        self._p11_change = card_service._pkcs11_change_pin
        self._p11_puk = card_service._pkcs11_change_puk
        self._p11_write = card_service._pkcs11_write_cert
        self.resolve_calls = []

        card_service._detected_atr = lambda: 'FAKEATR'
        card_service._with_apdu_driver = lambda fn: fn(self.driver)

    def tearDown(self):
        backends.resolve = self._resolve
        card_service._detected_atr = self._atr
        card_service._with_apdu_driver = self._apdu
        card_service._pkcs11_change_pin = self._p11_change
        card_service._pkcs11_change_puk = self._p11_puk
        card_service._pkcs11_write_cert = self._p11_write

    def _resolve_returning(self, order):
        def fake(op, atr=None, config=None):
            self.resolve_calls.append((op, atr))
            return list(order)
        backends.resolve = fake

    def test_change_pin_resolves_op_pin_with_the_detected_atr(self):
        self._resolve_returning(['apdu', 'pkcs11'])
        card_service.change_pin('old', 'new')
        assert self.resolve_calls == [(backends.OP_PIN, 'FAKEATR')]

    def test_change_pin_uses_apdu_when_resolved_first(self):
        self._resolve_returning(['apdu', 'pkcs11'])
        p11_ran = []
        card_service._pkcs11_change_pin = lambda *a, **k: p11_ran.append(1)
        card_service.change_pin('o', 'n')
        assert self.driver.calls == [('change_pin', 'o', 'n')]
        assert p11_ran == []                        # PKCS#11 not touched

    def test_change_pin_uses_pkcs11_when_apdu_absent(self):
        self._resolve_returning(['pkcs11'])
        ran = []
        card_service._pkcs11_change_pin = lambda old, new, cfg: ran.append((old, new))
        card_service.change_pin('o', 'n')
        assert ran == [('o', 'n')] and self.driver.calls == []

    def test_read_certificates_apdu_discovers(self):
        self._resolve_returning(['apdu', 'pkcs11'])
        certs = card_service.read_certificates(pin='ignored-on-apdu')
        assert certs == [{'der': b'x'}] and self.driver.calls == [('discover',)]

    def test_change_puk_is_pkcs11_only_even_on_an_apdu_card(self):
        ''' The APDU driver has no PUK-change, so even an apdu-first card routes
            PUK changes straight to PKCS#11 (no 'apdu' impl to fall into). '''

        self._resolve_returning(['apdu', 'pkcs11'])   # apdu first, but no apdu impl
        ran = []
        card_service._pkcs11_change_puk = lambda old, new, cfg: ran.append((old, new))
        try:
            card_service.change_puk('oldpuk', 'newpuk')
        finally:
            pass
        assert ran == [('oldpuk', 'newpuk')] and self.driver.calls == []

    def test_import_certificate_routes_to_pkcs11(self):
        self._resolve_returning(['pkcs11'])         # OP_MANAGE excludes apdu
        got = []
        card_service._pkcs11_write_cert = lambda der, pin, cfg: got.append((der, pin))
        card_service.import_certificate(b'DER', 'PIN')
        assert got == [(b'DER', 'PIN')]
        assert self.resolve_calls == [(backends.OP_MANAGE, 'FAKEATR')]


class TestRealResolverCapabilities(unittest.TestCase):
    ''' Tie the facade to the real resolver: OP_MANAGE is PKCS#11-only, OP_PIN
        includes APDU for a whitelisted card - so writes stay PKCS#11 while PIN
        ops follow the same engine as signing. '''

    WHITELISTED = '3B7F96000080318065B085050039120FFE829000'

    class _Cfg:
        def __init__(self, d): self._d = d
        def get(self, k, default=None): return self._d.get(k, default)

    def test_op_manage_never_offers_apdu(self):
        order = backends.resolve(backends.OP_MANAGE, atr=self.WHITELISTED,
                                 config=self._Cfg({'apduWhitelist': self.WHITELISTED}),
                                 platform='linux')
        assert 'apdu' not in order                  # apdu lacks OP_MANAGE

    def test_op_pin_offers_apdu_for_a_whitelisted_card(self):
        order = backends.resolve(backends.OP_PIN, atr=self.WHITELISTED,
                                 config=self._Cfg({'apduWhitelist': self.WHITELISTED}),
                                 platform='linux')
        assert order and order[0] == 'apdu'         # same engine signing would use


if __name__ == '__main__':
    unittest.main()
