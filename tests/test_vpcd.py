import hashlib, socket, struct, sys, threading, unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(_ROOT), str(_ROOT / 'tests' / 'test_utils')]

from src.cards import BTrustDriver
from src.cert_parser import get_rsa_public_key
from src.verifier import verify_rsa_pkcs1_v1_5

import vpcd_card
from synthetic_card import synthetic_idprime_card


class TestFraming(unittest.TestCase):

    def test_frame_prefixes_a_big_endian_length(self):
        assert vpcd_card.frame(b'\x90\x00') == b'\x00\x02\x90\x00'
        assert vpcd_card.frame(b'') == b'\x00\x00'

    def test_recv_exact_raises_when_the_peer_hangs_up(self):
        a, b = socket.socketpair()
        b.close()
        _raised = False
        try:
            vpcd_card.recv_exact(a, 4)
        except vpcd_card.Disconnected:
            _raised = True
        assert _raised, 'vpcd_card.Disconnected not raised'
        a.close()


class TestHandleMessage(unittest.TestCase):
    ''' Only the ATR request gets a reply; control bytes are silent '''

    def setUp(self):
        self.card = synthetic_idprime_card(name='Protocol Test')

    def test_atr_request_is_answered(self):
        reply = vpcd_card.handle_message(self.card, bytes([vpcd_card.CTRL_ATR]))
        assert reply == vpcd_card.frame(self.card.get_atr())

    def test_power_and_reset_are_silent(self):
        # Replying to these would desync the length-prefixed stream.
        for cmd in (vpcd_card.CTRL_OFF, vpcd_card.CTRL_ON, vpcd_card.CTRL_RESET):
            assert vpcd_card.handle_message(self.card, bytes([cmd])) is None

    def test_apdu_goes_straight_to_the_card(self):
        reply = vpcd_card.handle_message(self.card, bytes.fromhex('00A4000C02FF00'))
        assert reply == vpcd_card.frame(b'\x90\x00')

    def test_reset_is_forwarded_to_a_card_that_wants_it(self):
        class Resettable:
            was_reset = False
            def get_atr(self): return b'\x3b\x00'
            def transmit(self, apdu): return b'\x90\x00'
            def reset(self): self.was_reset = True

        card = Resettable()
        vpcd_card.handle_message(card, bytes([vpcd_card.CTRL_RESET]))
        assert card.was_reset

    def test_empty_message_is_ignored(self):
        assert vpcd_card.handle_message(self.card, b'') is None


class TestOverARealSocket(unittest.TestCase):
    '''
    The real thing minus pcscd: we speak vpcd's wire protocol to serve_connection
    over a socketpair, and run a full cert discovery + signature across it.
    '''

    def setUp(self):
        self.card = synthetic_idprime_card(name='Socket Test', personal_id='PNOBG-7')
        self.vpcd, self.cardside = socket.socketpair()
        self.thread = threading.Thread(
            target=self._serve, args=(self.card, self.cardside), daemon=True)
        self.thread.start()

    def _serve(self, card, sock):
        try:
            vpcd_card.serve_connection(card, sock, log=None)
        except vpcd_card.Disconnected, OSError:
            pass

    def tearDown(self):
        self.vpcd.close()
        self.cardside.close()

    def _request(self, payload: bytes) -> bytes:
        ''' Send a vpcd frame, read the length-prefixed reply '''

        self.vpcd.sendall(vpcd_card.frame(payload))
        (size,) = struct.unpack('!H', vpcd_card.recv_exact(self.vpcd, 2))
        return vpcd_card.recv_exact(self.vpcd, size)

    def test_atr_over_the_wire(self):
        assert self._request(bytes([vpcd_card.CTRL_ATR])) == self.card.get_atr()

    def test_power_on_then_atr(self):
        # power-on is silent, so the next reply must be the ATR (stream in sync)
        self.vpcd.sendall(vpcd_card.frame(bytes([vpcd_card.CTRL_ON])))
        assert self._request(bytes([vpcd_card.CTRL_ATR])) == self.card.get_atr()

    def test_discover_and_sign_across_the_socket(self):
        request = self._request

        class WireConn:
            ''' A SmartCardConnection whose APDUs cross the vpcd protocol '''

            def get_atr(self): return request(bytes([vpcd_card.CTRL_ATR]))
            def transmit(self, apdu): return request(bytes(apdu))
            def transaction(self):
                class T:
                    def __enter__(s): return s
                    def __exit__(s, *e): return False
                return T()
            def __enter__(self): return self
            def __exit__(self, *e): return False

        drv = BTrustDriver.create(WireConn())
        certs = drv.discover_certificates()
        assert len(certs) == 1

        n, e = get_rsa_public_key(certs[0]['der'])
        sig = drv.sign('1234', hashlib.sha256(b'vpcd').digest(),
                       key_ref=certs[0]['key_ref'])
        assert verify_rsa_pkcs1_v1_5(b'vpcd', sig, n, e, 'SHA256')


class TestConfHelper(unittest.TestCase):

    def test_conf_snippet_carries_the_port_in_devicename(self):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpcd_card.print_conf(35963)
        text = out.getvalue()
        if sys.platform == 'darwin':
            assert 'SmartCardServices' in text
        else:
            # DEVICENAME carries the port (/dev/null:0x8C7B), not a bare /dev/null
            assert 'DEVICENAME   /dev/null:0x8C7B' in text
            assert 'CHANNELID    0x8C7B' in text


def _vpcd_reader():
    from src import detector
    return next((r for r in detector.get_readers() if 'Virtual PCD' in r), None)


@unittest.skipIf(_vpcd_reader() is None,
                 'vpcd reader not served by pcscd (see tools/vpcd_design.md)')
class TestLiveViaPcsc(unittest.TestCase):
    '''
    app -> sc_ffi (ctypes) -> libpcsclite -> pcscd -> vpcd -> vpcd_card -> card.
    Needs vpcd installed, pcscd running, and tests/test_utils/vpcd_card.py serving.
    '''

    def test_detector_sees_the_card(self):
        from src import detector
        expected = synthetic_idprime_card().get_atr().hex().upper()
        assert expected in detector.get_connected_atrs()

    def test_app_getsigner_and_sign_end_to_end(self):
        import base64
        from src import app

        class UI:
            def choose_certificate(self, certs): return 0
            def prompt_pin(self, *a, **k): return '1234'

        res = app._getsigner_apdu(selector=None, show_valid_certs=False,
                                  ui_provider=UI())
        assert res['status'] == 'ok'
        der = base64.b64decode(res['chain'][0])

        payload = b'signed through pcscd and vpcd, no USB at all'
        res = app._sign_apdu([base64.b64encode(payload).decode()], 'SHA256', der, UI())
        assert res['status'] == 'ok'

        sig = base64.b64decode(res['signatures'][0])
        n, e = get_rsa_public_key(der)
        assert verify_rsa_pkcs1_v1_5(payload, sig, n, e, 'SHA256')


if __name__ == '__main__':
    unittest.main()
