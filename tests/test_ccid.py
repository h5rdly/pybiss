import struct, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import ccid


# Verbatim from /sys/bus/usb/devices/<circle>/descriptors (31aa:7001).
REAL_BLOB = bytes.fromhex(
    '1201100100000008aa31017000010102030109025d00010100a03209040000030b'
    '00000236211001000703000000c0120000c01200000067320000909a0c0000fe00'
    '00000000000000000000ba04040011010000ffff0000000107058102400000070502'
    '024000000705830308000a'
)


class TestParseDescriptors(unittest.TestCase):

    def setUp(self):
        self.info = ccid.parse_descriptors(REAL_BLOB)

    def test_finds_the_ccid_interface_and_endpoints(self):
        assert self.info['iface'] == 0
        assert self.info['ep_out'] == 0x02
        assert self.info['ep_in'] == 0x81

    def test_reads_ccid_functional_descriptor(self):
        c = self.info['ccid']
        assert c is not None
        assert c['dwFeatures'] == 0x000404BA
        assert c['dwMaxCCIDMessageLength'] == 273
        assert c['dwProtocols'] == 0x03
        assert c['bPINSupport'] == 0x00

    def test_no_ccid_interface_returns_none(self):
        # A device descriptor with a single non-CCID (class 0xFF) interface
        blob = bytes.fromhex('09040000020600000705810240000007050202400000')
        assert ccid.parse_descriptors(blob)['ccid'] is None

    def test_empty_blob_is_safe(self):
        got = ccid.parse_descriptors(b'')
        assert got['ccid'] is None
        assert got['iface'] is None


class TestExchangeLevel(unittest.TestCase):

    def test_decodes_each_level(self):
        assert ccid.exchange_level(0x00000000) == 'character'
        assert ccid.exchange_level(0x00010000) == 'tpdu'
        assert ccid.exchange_level(0x00020000) == 'short_apdu'
        assert ccid.exchange_level(0x000404BA) == 'extended_apdu'

    def test_apdu_level_gate(self):
        assert ccid.is_apdu_level(0x000404BA)
        assert ccid.is_apdu_level(0x00020000)
        assert not ccid.is_apdu_level(0x00010000)
        assert not ccid.is_apdu_level(0x00000000)


class TestGetResponseHandling(unittest.TestCase):
    '''
    transmit_iso7816 must reproduce what pcscd hides for T=0 APDU readers:
    61 XX -> GET RESPONSE and append; 6C XX -> resend with corrected Le.
    '''

    def _replay(self, script):
        ''' Fake xfr: each call pops the next (expected_apdu, response). '''

        sent = []

        def xfr(apdu):
            exp, resp = script[len(sent)]
            sent.append(apdu)
            if exp is not None:
                assert apdu == exp, f'sent {apdu.hex()}, expected {exp.hex()}'
            return resp

        return xfr, sent

    def test_plain_response_passes_through(self):
        xfr, sent = self._replay([(None, bytes.fromhex('6f1d9000'))])
        out = ccid.transmit_iso7816(xfr, bytes.fromhex('00A40000023F00'))
        assert out == bytes.fromhex('6f1d9000')
        assert len(sent) == 1

    def test_61xx_triggers_get_response_and_appends(self):
        # First reply is 61 1F (31 bytes waiting); then GET RESPONSE returns them.
        select = bytes.fromhex('00A40000023F00')
        get_resp = bytes.fromhex('00C000001F')
        fci = bytes.fromhex('6f1d83023f00') + b'\x00' * 25
        xfr, sent = self._replay([
            (select, bytes.fromhex('611F')),
            (get_resp, fci + bytes.fromhex('9000')),
        ])
        out = ccid.transmit_iso7816(xfr, select)
        assert out == fci + bytes.fromhex('9000')
        assert sent[1] == get_resp

    def test_chained_61xx(self):
        cmd = bytes.fromhex('00B0000000')
        xfr, _ = self._replay([
            (cmd, bytes.fromhex('AA') + bytes.fromhex('6103')),
            (bytes.fromhex('00C0000003'), bytes.fromhex('BBBBBB') + bytes.fromhex('6101')),
            (bytes.fromhex('00C0000001'), bytes.fromhex('CC') + bytes.fromhex('9000')),
        ])
        out = ccid.transmit_iso7816(xfr, cmd)
        assert out == bytes.fromhex('AABBBBBBCC9000')

    def test_6cxx_resends_with_corrected_le(self):
        cmd = bytes.fromhex('00B0000000')
        xfr, sent = self._replay([
            (cmd, bytes.fromhex('6C08')),
            (bytes.fromhex('00B0000008'), bytes.fromhex('0102030405060708') + bytes.fromhex('9000')),
        ])
        out = ccid.transmit_iso7816(xfr, cmd)
        assert out == bytes.fromhex('01020304050607089000')


def _frame(payload=b'', status=0x00, error=0x00):
    ''' A raw RDR_to_PC message as a real reader would put on the wire. '''

    return struct.pack('<BIBBBBB', 0x80, len(payload), 0, 0, status, error, 0) + payload


# A muted card answers cmd_status==1 (status 0x40) with bError=0xFE.
_MUTE = _frame(status=0x40, error=0xFE)


class _ScriptedTransport:
    ''' Real fake transport: hand back queued frames, record what was written. '''

    def __init__(self, info, timeout_ms):
        self.reads = list(info['_reads'])
        self.writes = []

    def write(self, data):
        self.writes.append(bytes(data))

    def read(self, maxlen):
        if not self.reads:
            raise ccid.CcidNoResponse('script drained')
        return self.reads.pop(0)

    def close(self):
        pass


class TestPowerOnMuteRetry(unittest.TestCase):
    '''
    A contact card that powered down while idle answers power-on with ICC mute
    (bError=0xFE). power_on re-powers - which is safe because it is idempotent -
    while xfr must NOT retry (a repeated command APDU could burn a PIN try).
    '''

    def setUp(self):
        # Register a scripted backend for the duration of the test; a real fake,
        # swapped back in tearDown, so nothing leaks between tests.
        self._saved = dict(ccid._TRANSPORTS)
        ccid._TRANSPORTS['scripted'] = _ScriptedTransport

    def tearDown(self):
        ccid._TRANSPORTS.clear()
        ccid._TRANSPORTS.update(self._saved)

    def _usb(self, reads):
        info = {
            'backend': 'scripted',
            '_reads': reads,
            'ccid': {'dwFeatures': 0x000404BA, 'dwMaxCCIDMessageLength': 273},
        }
        return ccid.CcidUsb(info)

    def test_power_on_wakes_a_muted_card(self):
        atr = _frame(payload=bytes.fromhex('3B7F'))
        usb = self._usb([_MUTE, _MUTE, atr])          # mute twice, then the ATR
        got = usb.power_on(mute_retries=2, mute_pause=0)
        assert got == bytes.fromhex('3B7F')
        assert len(usb._t.writes) == 3

    def test_power_on_gives_up_after_the_bounded_retries(self):
        usb = self._usb([_MUTE, _MUTE, _MUTE])
        _raised = False
        try:
            usb.power_on(mute_retries=2, mute_pause=0)
        except ccid.CcidMute:
            _raised = True
        assert _raised, 'ccid.CcidMute not raised'
        assert len(usb._t.writes) == 3

    def test_power_on_does_not_retry_when_the_card_answers(self):
        atr = _frame(payload=bytes.fromhex('3B7F'))
        usb = self._usb([atr])
        assert usb.power_on(mute_retries=2, mute_pause=0) == bytes.fromhex('3B7F')
        assert len(usb._t.writes) == 1

    def test_xfr_never_retries_on_mute(self):
        ''' A command APDU is not idempotent: mute surfaces, it is not re-sent. '''

        usb = self._usb([_MUTE])
        _raised = False
        try:
            usb.xfr(bytes.fromhex('00A40000023F00'))
        except ccid.CcidMute:
            _raised = True
        assert _raised, 'ccid.CcidMute not raised'
        assert len(usb._t.writes) == 1


class TestFindReadersIsImportSafe(unittest.TestCase):

    def test_returns_list_and_never_raises(self):
        # On CI (no reader / no sysfs) this is []; with a reader it's populated.
        # Either way it must be a list and must not raise.
        assert isinstance(ccid.find_ccid_readers(), list)


if __name__ == '__main__':
    unittest.main()
