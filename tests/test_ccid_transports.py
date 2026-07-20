import ctypes, hashlib, struct, sys, unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(_ROOT), str(_ROOT / 'tests' / 'test_utils')]

from src import ccid
from src.cards import BTrustDriver
from src.cert_parser import get_rsa_public_key
from src.verifier import verify_rsa_pkcs1_v1_5

import f_ccid                                    # the CCID *device* side
from synthetic_card import synthetic_idprime_card


def _ioc(direction, group, num, size):
    ''' sys/sys/ioccom.h: _IOC(inout,group,num,len) - the reference encoding '''

    return direction | ((size & 0x1FFF) << 16) | (ord(group) << 8) | num


_IOC_OUT, _IOC_IN = 0x40000000, 0x80000000
_IOC_INOUT = _IOC_OUT | _IOC_IN


class TestFreeBsdIoctlEncoding(unittest.TestCase):

    def test_usb_gen_descriptor_is_32_bytes(self):
        # void* (8) + 4x uint16 (8) + 6x uint8 + uint8[8], padded to 8-alignment.
        # This size goes INTO USB_GET_FULL_DESC's ioctl number.
        self.assertEqual(ctypes.sizeof(ccid._UsbGenDescriptor), 32)

    def test_ioctl_numbers_match_the_freebsd_headers(self):
        expected = {
            '_USB_GET_DEVICE_DESC':   _ioc(_IOC_OUT,   'U', 105, 18),
            '_USB_GET_FULL_DESC':     _ioc(_IOC_INOUT, 'U', 109, 32),
            '_USB_SET_RX_SHORT_XFER': _ioc(_IOC_IN,    'U', 113, 4),
            '_USB_SET_RX_TIMEOUT':    _ioc(_IOC_IN,    'U', 114, 4),
            '_USB_SET_TX_TIMEOUT':    _ioc(_IOC_IN,    'U', 137, 4),
        }
        for name, want in expected.items():
            self.assertEqual(getattr(ccid, name), want, f'{name} mis-encoded')

    def test_freebsd_encoding_is_not_linuxs(self):
        # Linux: 14-bit size at bit 16, direction at bit 30. FreeBSD: 13-bit size,
        # direction in the top 3 bits. Same request would collide if we reused one.
        self.assertNotEqual(ccid._USB_SET_RX_TIMEOUT,
                            ccid._IOC(1, 'U', 114, 4))

    def test_linux_bulk_ioctl_unchanged_by_the_refactor(self):
        self.assertEqual(ccid._USBDEVFS_BULK, 0xC0185502)   # known-good on 64-bit


class TestBackendSelection(unittest.TestCase):

    def _info(self, backend, features=0x000404BA):
        return {'backend': backend, 'iface': 0, 'node': '/dev/null',
                'ep_in': 0x81, 'ep_out': 0x02, 'name': 'Test',
                'ccid': {'dwFeatures': features, 'dwMaxCCIDMessageLength': 273}}

    def test_known_backends_are_registered(self):
        self.assertEqual(sorted(ccid._TRANSPORTS), ['ugen', 'usbfs'])

    def test_unknown_backend_is_rejected(self):
        with self.assertRaises(ccid.CcidError):
            ccid.CcidUsb(self._info('nonesuch'))

    def test_tpdu_reader_is_rejected_before_any_io(self):
        # exchange level 0x01 = TPDU: the reader would need a T=1 state machine.
        with self.assertRaises(ccid.CcidError) as caught:
            ccid.CcidUsb(self._info('usbfs', features=0x00010000))
        self.assertIn('tpdu', str(caught.exception).lower())


class _FakeTransport:
    '''
    A USB transport backed by the f_ccid device engine: whatever CcidUsb writes
    is dispatched to a synthetic card, and the reply is queued for the next read.
    Exactly what the wire does, minus the wire.
    '''

    card = None                                  # set per-test

    def __init__(self, info, timeout_ms):
        self.info, self._pending = info, b''

    def write(self, data):
        mtype, dlen, slot, seq = struct.unpack('<BIBB', bytes(data)[:7])
        payload = bytes(data)[10:10 + dlen]
        self._pending = f_ccid.dispatch(_FakeTransport.card, mtype, payload, slot, seq)

    def read(self, maxlen):
        reply, self._pending = self._pending[:maxlen], b''
        return reply

    def close(self):
        self.closed = True


class TestSharedProtocolLayerOverAFakeTransport(unittest.TestCase):
    '''
    The refactor moved raw USB behind a transport. This drives the UNCHANGED CCID
    layer (headers, bSeq, time-extension, T=0 GET RESPONSE) over a fake one and
    runs a full discover -> sign, proving the shared layer still works for both.
    '''

    def setUp(self):
        _FakeTransport.card = synthetic_idprime_card(name='Transport Test',
                                                     personal_id='PNOBG-5')
        ccid._TRANSPORTS['fake'] = _FakeTransport
        self.info = {'backend': 'fake', 'iface': 0, 'node': '/dev/null',
                     'ep_in': 0x81, 'ep_out': 0x02, 'name': 'Fake',
                     'ccid': {'dwFeatures': 0x000404BA, 'dwMaxCCIDMessageLength': 273}}

    def tearDown(self):
        ccid._TRANSPORTS.pop('fake', None)
        _FakeTransport.card = None

    def test_power_on_returns_the_atr(self):
        usb = ccid.CcidUsb(self.info)
        self.assertEqual(usb.power_on(), _FakeTransport.card.get_atr())

    def test_slot_status_reports_a_card(self):
        usb = ccid.CcidUsb(self.info)
        self.assertEqual(usb.slot_status() & 0x03, 0)      # 0 = present and active

    def test_sequence_number_increments_per_message(self):
        usb = ccid.CcidUsb(self.info)
        usb.power_on()
        first = usb.seq
        usb.slot_status()
        self.assertEqual(usb.seq, (first + 1) & 0xFF)

    def test_full_discover_and_sign_through_the_ccid_layer(self):
        usb = ccid.CcidUsb(self.info)
        usb.power_on()

        class Conn:
            def get_atr(inner): return usb.power_on()
            def transmit(inner, apdu): return ccid.transmit_iso7816(usb.xfr, bytes(apdu))
            def transaction(inner): return ccid._NullTransaction()
            def __enter__(inner): return inner
            def __exit__(inner, *e): return False

        drv = BTrustDriver.create(Conn())
        certs = drv.discover_certificates()
        self.assertEqual(len(certs), 1)

        n, e = get_rsa_public_key(certs[0]['der'])
        sig = drv.sign('1234', hashlib.sha256(b'transport').digest(),
                       key_ref=certs[0]['key_ref'])
        self.assertTrue(verify_rsa_pkcs1_v1_5(b'transport', sig, n, e, 'SHA256'))


class TestDiscoveryDispatch(unittest.TestCase):

    def test_find_readers_never_raises_and_returns_a_list(self):
        self.assertIsInstance(ccid.find_ccid_readers(), list)

    def test_ugen_discovery_matches_what_is_actually_attached(self):
        '''
        Must be quiet where there is nothing to find (Linux has no ugen nodes at
        all), and must actually find a CCID reader on FreeBSD when one IS
        attached - the earlier version of this test asserted "always empty" and
        duly failed on FreeBSD the moment the backend started working.
        '''

        found = ccid._find_ugen()
        self.assertIsInstance(found, list)

        if not list(Path('/dev').glob('ugen[0-9]*.[0-9]*')):
            self.assertEqual(found, [], 'no ugen nodes exist, so nothing may be reported')
        for reader in found:
            self.assertEqual(reader['backend'], 'ugen')
            self.assertTrue(reader['node'].startswith('/dev/ugen'))
            self.assertIsNotNone(reader['ccid'])          # only CCID devices listed


if __name__ == '__main__':
    unittest.main()
