import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import app
from synthetic_card import synthetic_idprime_card


class _Boom:
    ''' A connection whose open() fails, like a missing daemon or a busy reader '''

    def __init__(self, msg): self.msg = msg
    def __enter__(self): raise RuntimeError(self.msg)
    def __exit__(self, *e): return False


class _Card:
    ''' A connection that opens fine and tracks whether it was closed '''

    def __init__(self, card): self.card, self.closed = card, False
    def __enter__(self): return self.card
    def __exit__(self, *e):
        self.closed = True
        return False


class TestCardConnectionFallback(unittest.TestCase):

    def setUp(self):
        self.card = synthetic_idprime_card(name='Fallback Test')

    def test_pcsc_is_used_when_it_works(self):
        pcsc, ccid = _Card(self.card), _Card(self.card)
        used = []
        with app._CardConnection(pcsc_factory=lambda: (used.append('pcsc'), pcsc)[1],
                                 ccid_factory=lambda: (used.append('ccid'), ccid)[1]) as conn:
            self.assertIs(conn, self.card)
        self.assertEqual(used, ['pcsc'])          # direct CCID never even tried
        self.assertTrue(pcsc.closed)

    def test_falls_back_to_direct_ccid_when_pcsc_finds_nothing(self):
        ccid = _Card(self.card)
        with app._CardConnection(pcsc_factory=lambda: _Boom('No smart card readers detected.'),
                                 ccid_factory=lambda: ccid) as conn:
            self.assertIs(conn, self.card)
        self.assertTrue(ccid.closed)              # the fallback is the one we close

    def test_both_failing_reports_both_reasons(self):
        with self.assertRaises(app.CardUnreachable) as caught:
            with app._CardConnection(pcsc_factory=lambda: _Boom('no pcscd'),
                                     ccid_factory=lambda: _Boom('no usbfs reader')):
                pass
        text = str(caught.exception)
        self.assertIn('no pcscd', text)           # a user has to see BOTH failures
        self.assertIn('no usbfs reader', text)

    def test_exit_is_safe_when_nothing_ever_opened(self):
        cm = app._CardConnection(pcsc_factory=lambda: _Boom('x'),
                                 ccid_factory=lambda: _Boom('y'))
        self.assertFalse(cm.__exit__(None, None, None))


class TestBackendReportsTheRealReason(unittest.TestCase):
    ''' The APDU backends must surface WHY the card was unreachable, not swallow it '''

    def setUp(self):
        self._orig = app._open_card
        app._open_card = lambda: app._CardConnection(
            pcsc_factory=lambda: _Boom('pcscd is not running'),
            ccid_factory=lambda: _Boom('no direct-CCID reader found'))

    def tearDown(self):
        app._open_card = self._orig

    def test_getsigner_apdu_explains_both_transports(self):
        from src import backends
        with self.assertRaises(backends.BackendUnavailable) as caught:
            app._getsigner_apdu(selector=None, show_valid_certs=False, ui_provider=None)
        text = str(caught.exception)
        self.assertIn('pcscd is not running', text)
        self.assertIn('no direct-CCID reader found', text)


class TestProductionDefaults(unittest.TestCase):
    ''' _open_card must wire the real transports, not leave a test seam behind '''

    def test_open_card_returns_a_fallback_connection(self):
        cm = app._open_card()
        self.assertIsInstance(cm, app._CardConnection)
        self.assertIs(cm._pcsc_factory, app._pcsc_factory)
        self.assertIs(cm._ccid_factory, app._ccid_factory)

    def test_factories_build_the_real_transports(self):
        from src.sc_ffi import SmartCardConnection
        from src.ccid import CcidConnection
        self.assertIsInstance(app._pcsc_factory(), SmartCardConnection)
        self.assertIsInstance(app._ccid_factory(), CcidConnection)


if __name__ == '__main__':
    unittest.main()
