import os, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import sc_ffi


@unittest.skipUnless(os.environ.get('PYBISS_REQUIRE_PCSCD') == '1',
                     'needs a running pcscd; set PYBISS_REQUIRE_PCSCD=1 to enforce')
class TestLiveDaemonHandshake(unittest.TestCase):

    def test_establish_context_against_a_live_daemon(self):
        # Raises if the daemon is not reachable or the handshake is mis-marshalled.
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
