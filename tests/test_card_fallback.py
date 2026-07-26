import sys, unittest
import types

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import app, card_access
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
        with card_access._CardConnection(pcsc_factory=lambda: (used.append('pcsc'), pcsc)[1],
                                 ccid_factory=lambda: (used.append('ccid'), ccid)[1]) as conn:
            assert conn is self.card
        assert used == ['pcsc']
        assert pcsc.closed

    def test_falls_back_to_direct_ccid_when_pcsc_finds_nothing(self):
        ccid = _Card(self.card)
        with card_access._CardConnection(pcsc_factory=lambda: _Boom('No smart card readers detected.'),
                                 ccid_factory=lambda: ccid) as conn:
            assert conn is self.card
        assert ccid.closed

    def test_both_failing_reports_both_reasons(self):
        caught = None
        try:
            with card_access._CardConnection(pcsc_factory=lambda: _Boom('no pcscd'),
                                     ccid_factory=lambda: _Boom('no usbfs reader')):
                pass
        except card_access.CardUnreachable as _e:
            caught = types.SimpleNamespace(exception=_e)
        assert caught is not None, 'card_access.CardUnreachable not raised'
        text = str(caught.exception)
        assert 'no pcscd' in text
        assert 'no usbfs reader' in text

    def test_exit_is_safe_when_nothing_ever_opened(self):
        cm = card_access._CardConnection(pcsc_factory=lambda: _Boom('x'),
                                 ccid_factory=lambda: _Boom('y'))
        assert not cm.__exit__(None, None, None)


class TestBackendReportsTheRealReason(unittest.TestCase):
    ''' The APDU backends must surface WHY the card was unreachable, not swallow it '''

    def setUp(self):
        self._orig = card_access._open_card
        card_access._open_card = lambda: card_access._CardConnection(
            pcsc_factory=lambda: _Boom('pcscd is not running'),
            ccid_factory=lambda: _Boom('no direct-CCID reader found'))

    def tearDown(self):
        card_access._open_card = self._orig

    def test_getsigner_apdu_explains_both_transports(self):
        from src import backends
        caught = None
        try:
            app._getsigner_apdu(selector=None, show_valid_certs=False, ui_provider=None)
        except backends.BackendUnavailable as _e:
            caught = types.SimpleNamespace(exception=_e)
        assert caught is not None, 'backends.BackendUnavailable not raised'
        text = str(caught.exception)
        assert 'pcscd is not running' in text
        assert 'no direct-CCID reader found' in text


class TestProductionDefaults(unittest.TestCase):
    ''' _open_card must wire the real transports, not leave a test seam behind '''

    def test_open_card_returns_a_fallback_connection(self):
        cm = card_access._open_card()
        assert isinstance(cm, card_access._CardConnection)
        assert cm._pcsc_factory is card_access._pcsc_factory
        assert cm._ccid_factory is card_access._ccid_factory

    def test_factories_build_the_real_transports(self):
        from src.sc_ffi import SmartCardConnection
        from src.ccid import CcidConnection
        assert isinstance(card_access._pcsc_factory(), SmartCardConnection)
        assert isinstance(card_access._ccid_factory(), CcidConnection)


if __name__ == '__main__':
    unittest.main()
