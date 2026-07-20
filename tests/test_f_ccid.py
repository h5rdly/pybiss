import hashlib, struct, sys, unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(_ROOT), str(_ROOT / 'tests' / 'test_utils')]

from src import ccid
from src.cards import BTrustDriver
from src.cert_parser import get_rsa_public_key
from src.verifier import verify_rsa_pkcs1_v1_5

import f_ccid
from synthetic_card import synthetic_idprime_card


def _virtual_reader():
    ''' The f_ccid gadget, if it is currently plugged in '''

    return next((r for r in ccid.find_ccid_readers()
                 if r['name'] == 'Virtual CCID Reader'), None)


class TestDescriptors(unittest.TestCase):
    ''' What we hand FunctionFS must parse back as a usable CCID reader '''

    def test_our_own_host_parser_accepts_the_gadget_descriptors(self):
        blob = (f_ccid.INTERFACE_DESC + f_ccid.CCID_FUNCTIONAL
                + f_ccid._ep(0x81, 0x02, 512) + f_ccid._ep(0x02, 0x02, 512)
                + f_ccid._ep(0x83, 0x03, 8, 7))
        info = ccid.parse_descriptors(blob)
        self.assertIsNotNone(info['ccid'])
        self.assertTrue(ccid.is_apdu_level(info['ccid']['dwFeatures']))
        self.assertEqual((info['ep_in'], info['ep_out']), (0x81, 0x02))

    def test_interface_declares_no_string(self):
        # FunctionFS sizes its string table from the highest referenced index;
        # a non-zero iInterface would demand a matching table (EINVAL if absent).
        self.assertEqual(f_ccid.INTERFACE_DESC[8], 0)

    def test_functionfs_descriptor_header(self):
        d = f_ccid.build_descriptors()
        magic, length, flags = struct.unpack('<III', d[:12])
        self.assertEqual(magic, 3)              # FUNCTIONFS_DESCRIPTORS_MAGIC_V2
        self.assertEqual(flags, 1 | 2)          # HAS_FS_DESC | HAS_HS_DESC
        self.assertEqual(length, len(d))        # kernel rejects a wrong length
        self.assertEqual(struct.unpack('<II', d[12:20]), (5, 5))

    def test_functionfs_strings_header(self):
        s = f_ccid.build_strings()
        magic, length, count, langs = struct.unpack('<IIII', s[:16])
        self.assertEqual(magic, 2)              # FUNCTIONFS_STRINGS_MAGIC
        self.assertEqual(length, len(s))
        self.assertEqual((count, langs), (1, 1))

    def test_vid_pid_is_one_libccid_binds(self):
        # pcsc-lite matches the CCID *class* driver by VID:PID from libccid's
        # Info.plist - USB class 0x0B alone is not enough (that only gets the
        # kernel to enumerate us). 31AA:7001 is the Circle CCR7115 we mimic.
        self.assertEqual((f_ccid.VID, f_ccid.PID), ('0x31AA', '0x7001'))


class TestDispatchEngine(unittest.TestCase):
    ''' PC_to_RDR message in -> correct RDR_to_PC message out '''

    def setUp(self):
        self.card = synthetic_idprime_card(name='Dispatch Test')

    def _reply(self, mtype, payload=b'', seq=7):
        raw = f_ccid.dispatch(self.card, mtype, payload, 0, seq)
        mt, dlen, slot, rseq, status, error, _x = struct.unpack('<BIBBBBB', raw[:10])
        self.assertEqual((slot, rseq), (0, seq))     # slot/seq must be echoed
        self.assertEqual(dlen, len(raw) - 10)        # dwLength must match payload
        return mt, status, raw[10:]

    def test_power_on_returns_the_atr(self):
        mt, status, data = self._reply(0x62)
        self.assertEqual((mt, status), (0x80, 0x00))  # DataBlock, card active
        self.assertEqual(data, self.card.get_atr())

    def test_get_slot_status_reports_card_present(self):
        mt, status, data = self._reply(0x65)
        self.assertEqual((mt, status, data), (0x81, 0x00, b''))

    def test_power_off_reports_inactive(self):
        mt, status, _ = self._reply(0x63)
        self.assertEqual((mt, status & 0x03), (0x81, 0x01))

    def test_xfr_block_reaches_the_card(self):
        mt, status, data = self._reply(0x6F, bytes.fromhex('00A4000C02FF00'))
        self.assertEqual((mt, status), (0x80, 0x00))
        self.assertEqual(data, b'\x90\x00')

    def test_get_parameters_answers_t0(self):
        mt, status, data = self._reply(0x6C)
        self.assertEqual((mt, status), (0x82, 0x00))  # RDR_to_PC_Parameters
        self.assertEqual(data, f_ccid._T0_PARAMS)

    def test_unknown_message_gets_a_status_reply(self):
        mt, status, _ = self._reply(0x99)
        self.assertEqual((mt, status), (0x81, 0x00))


class TestFullConversationOverTheWire(unittest.TestCase):
    '''
    The host side (src/ccid.py's ISO-7816 layer) talking to the device side
    (f_ccid.dispatch) - every APDU crosses the CCID message boundary, exactly
    as it does over real USB, but in-process so it runs anywhere.
    '''

    def test_discover_and_sign_across_ccid_messages(self):
        card = synthetic_idprime_card(name='Wire Test', personal_id='PNOBG-42')
        seq = [0]

        def xfr(apdu):
            seq[0] = (seq[0] + 1) & 0xFF
            raw = f_ccid.dispatch(card, 0x6F, bytes(apdu), 0, seq[0])
            dlen = struct.unpack('<I', raw[1:5])[0]
            return raw[10:10 + dlen]

        class WireConn:
            def get_atr(self): return card.get_atr()
            def transmit(self, apdu): return ccid.transmit_iso7816(xfr, bytes(apdu))
            def transaction(self): return ccid._NullTransaction()
            def __enter__(self): return self
            def __exit__(self, *e): return False

        drv = BTrustDriver.create(WireConn())
        certs = drv.discover_certificates()
        self.assertEqual(len(certs), 1)

        n, e = get_rsa_public_key(certs[0]['der'])
        sig = drv.sign('1234', hashlib.sha256(b'wire').digest(),
                       key_ref=certs[0]['key_ref'])
        self.assertTrue(verify_rsa_pkcs1_v1_5(b'wire', sig, n, e, 'SHA256'))


_GADGET_ATR = f_ccid.synthetic_idprime_card().get_atr().hex().upper()


def _pcsc_reader():
    ''' The gadget as seen through pcscd, if pcscd is up and bound to it '''

    from src import detector
    return next((r for r in detector.get_readers() if 'CCR7115' in r), None)


@unittest.skipIf(_virtual_reader() is None,
                 'f_ccid gadget not plugged in (sudo python tests/test_utils/f_ccid.py start)')
class TestLiveGadgetDirect(unittest.TestCase):
    ''' Our own usbfs CCID transport driving the gadget, bypassing pcscd '''

    def test_direct_ccid_discovers_and_signs(self):
        try:
            conn_cm = ccid.CcidConnection()
            conn = conn_cm.__enter__()
        except ccid.CcidError as e:
            if 'busy' in str(e).lower():
                # pcscd owns the interface. That IS the designed precedence
                # (PC/SC first, direct CCID only as a fallback) - see TestLiveGadgetViaPcsc.
                self.skipTest(f'pcscd holds the interface, as intended: {e}')
            raise
        try:
            self.assertEqual(conn.get_atr().hex().upper(), _GADGET_ATR)
            drv = BTrustDriver.create(conn)
            certs = drv.discover_certificates()
            self.assertEqual(len(certs), 1)
            n, e = get_rsa_public_key(certs[0]['der'])
            sig = drv.sign('1234', hashlib.sha256(b'live').digest(),
                           key_ref=certs[0]['key_ref'])
            self.assertTrue(verify_rsa_pkcs1_v1_5(b'live', sig, n, e, 'SHA256'))
        finally:
            conn_cm.__exit__(None, None, None)


@unittest.skipIf(_pcsc_reader() is None,
                 'gadget not visible through pcscd (needs the gadget + a running pcscd)')
class TestLiveGadgetViaPcsc(unittest.TestCase):
    '''
    The whole stack for real: app -> sc_ffi (ctypes) -> libpcsclite -> pcscd ->
    libccid -> USB -> dummy_hcd -> f_ccid -> synthetic card. No mocks, no seam
    override - app._open_card opens a genuine PC/SC connection.
    '''

    class _UI:
        def choose_certificate(self, certs): return 0
        def prompt_pin(self, *a, **k): return '1234'

    def test_detector_sees_the_card(self):
        from src import detector
        atrs = detector.get_connected_atrs()
        self.assertIn(_GADGET_ATR, atrs)
        self.assertEqual(detector.identify_provider(_GADGET_ATR), 'GEMALTO')

    def test_app_getsigner_and_sign_end_to_end(self):
        import base64
        from src import app

        res = app._getsigner_apdu(selector=None, show_valid_certs=False,
                                  ui_provider=self._UI())
        self.assertEqual(res['status'], 'ok')
        der = base64.b64decode(res['chain'][0])

        payload = b'signed through pcscd, libccid and a virtual USB bus'
        res = app._sign_apdu([base64.b64encode(payload).decode()], 'SHA256',
                             der, self._UI())
        self.assertEqual(res['status'], 'ok')

        sig = base64.b64decode(res['signatures'][0])
        n, e = get_rsa_public_key(der)
        self.assertTrue(verify_rsa_pkcs1_v1_5(payload, sig, n, e, 'SHA256'))


if __name__ == '__main__':
    unittest.main()
