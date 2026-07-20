import os, sys, unittest
from ctypes import byref

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import sc_ffi, sc_types


# Return codes that mean "a daemon is present but not actually serving us" - no
# reader plugged in, a VM/CI host with no USB, or polkit refusing a session-less
# caller. None of these is a ctypes marshalling bug (that surfaces as
# SCARD_E_INVALID_* or a crash), so we skip on them rather than fail.
_NO_LIVE_DAEMON = {
    sc_types.SCARD_E_NO_SERVICE,         # socket absent - pcscd never came up
    sc_types.SCARD_E_SERVICE_STOPPED,    # pcscd went away
    sc_types.SCARD_F_COMM_ERROR,         # socket there, daemon not answering (FreeBSD CI, no USB)
    sc_types.SCARD_W_SECURITY_VIOLATION, # serving but polkit denied us (headless CI, no login session)
}


@unittest.skipUnless(os.environ.get('PYBISS_REQUIRE_PCSCD') == '1',
                     'needs a running pcscd; set PYBISS_REQUIRE_PCSCD=1 to enforce')
class TestLiveDaemonHandshake(unittest.TestCase):

    def setUp(self):
        # Probe once at the low level so we can tell "no daemon serving" (skip)
        # from a real ABI failure (let the test body raise and ERROR).
        p = sc_types.pcsc()
        ctx = sc_types.SCARDCONTEXT()
        res = p.SCardEstablishContext_fn(sc_types.SCARD_SCOPE_USER, None, None, byref(ctx))
        if res == sc_types.SCARD_S_SUCCESS:
            p.SCardReleaseContext_fn(ctx)
        elif res in _NO_LIVE_DAEMON:
            raise unittest.SkipTest(
                f'pcscd present but not serving ({hex(res)}): no reader/USB in this environment')

    def test_establish_context_against_a_live_daemon(self):
        # Raises if the handshake is mis-marshalled (setUp already excused a
        # merely-absent daemon).
        hcontext = sc_ffi.establish_context()
        try:
            self.assertIsNotNone(hcontext)
        finally:
            sc_ffi.release_context(hcontext)

    def test_list_readers_round_trips(self):
        # Zero readers is a perfectly good result here - we only require that the
        # two-pass buffer-sizing call completes and hands back a list.
        hcontext = sc_ffi.establish_context()
        try:
            self.assertIsInstance(sc_ffi.list_readers(hcontext), list)
        finally:
            sc_ffi.release_context(hcontext)


if __name__ == '__main__':
    unittest.main()
