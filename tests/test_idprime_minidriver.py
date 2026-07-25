import hashlib, struct, sys, unittest, zlib
import types

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.cards import (
    BTrustDriver, IDPrimeDriver,
    parse_minidriver_index, is_certificate_entry, decompress_minidriver_cert,
)


def _index_record(file_id: bytes, length: int, name: str) -> bytes:
    ''' Build one 21-byte index record: [fileID:2][len:2 LE][name padded] '''

    return file_id + struct.pack('<H', length) + name.encode('ascii').ljust(17, b'\x00')


def _index_blob(records) -> bytes:
    return bytes([len(records)]) + b''.join(records)


def _minidriver_cert(der: bytes) -> bytes:
    ''' Wrap DER the way the card stores it: 01 00 <u16 len> <zlib stream> '''

    return b'\x01\x00' + struct.pack('<H', len(der)) + zlib.compress(der)


# A minimal but valid DER SEQUENCE: SEQUENCE { INTEGER 5 }
FAKE_DER = bytes.fromhex('3003020105')


class TestParseIndex(unittest.TestCase):

    def test_parses_the_real_object_layout(self):
        blob = _index_blob([
            _index_record(b'\x02\x08', 24582, 'kxc00mscp'),
            _index_record(b'\x02\x09', 34561, 'pubkxc00p11'),
            _index_record(b'\x02\x04', 47110, 'cmapfilemscp'),
        ])
        entries = parse_minidriver_index(blob)
        assert len(entries) == 3
        assert entries[0] == {'file_id': b'\x02\x08', 'length': 24582, 'name': 'kxc00mscp'}
        assert entries[1]['name'] == 'pubkxc00p11'

    def test_empty_index_is_safe(self):
        assert parse_minidriver_index(b'') == []
        assert parse_minidriver_index(b'\x00') == []

    def test_truncated_trailing_record_is_dropped(self):
        blob = bytes([2]) + _index_record(b'\x02\x08', 10, 'kxc00mscp') + b'\x02\x09short'
        assert len(parse_minidriver_index(blob)) == 1


class TestCertificateEntry(unittest.TestCase):

    def test_kxc_and_ksc_are_certs(self):
        assert is_certificate_entry('kxc00mscp')
        assert is_certificate_entry('ksc01mscp')

    def test_pub_and_admin_files_are_not(self):
        for name in ('pubkxc00p11', 'priprk00p11', 'cmapfilemscp', 'cardid', 'tinfop11'):
            assert not is_certificate_entry(name), name


class TestDecompressCert(unittest.TestCase):

    def test_unwraps_zlib_wrapped_der(self):
        assert decompress_minidriver_cert(_minidriver_cert(FAKE_DER)) == FAKE_DER

    def test_plain_der_passes_through(self):
        assert decompress_minidriver_cert(FAKE_DER) == FAKE_DER

    def test_length_mismatch_raises(self):
        good = _minidriver_cert(FAKE_DER)
        # Corrupt the declared uncompressed length (bytes 2-3)
        bad = good[:2] + struct.pack('<H', len(FAKE_DER) + 1) + good[4:]
        _raised = False
        try:
            decompress_minidriver_cert(bad)
        except ValueError:
            _raised = True
        assert _raised, 'ValueError not raised'


class ScriptedCard:
    '''
    Fake card that mimics SELECT + READ BINARY over a set of EFs, so the driver
    walks it exactly as it would real hardware (select applet, read index,
    read each cert). `files` maps 2-byte file-id -> content bytes.
    '''

    def __init__(self, files: dict, atr=b'\x3b\x7f'):
        self.files = files
        self.atr = atr
        self._selected = None

    def get_atr(self):
        return self.atr

    def transmit(self, apdu: bytes) -> bytes:
        apdu = bytes(apdu)
        if apdu[:2] == b'\x00\xa4':                  # SELECT
            if apdu[2] == 0x04:                      # by AID (applet) - always ok
                return b'\x90\x00'
            self._selected = apdu[5:5 + apdu[4]]     # by file-id
            return b'\x90\x00' if self._selected in self.files else b'\x6a\x82'
        if apdu[:2] == b'\x00\xb0':                  # READ BINARY
            content = self.files.get(self._selected, b'')
            offset = (apdu[2] << 8) | apdu[3]
            if offset >= len(content):
                return b'\x62\x82'                   # EOF
            return content[offset:offset + 255] + b'\x90\x00'
        return b'\x90\x00'


class TestDiscoverCertificatesEndToEnd(unittest.TestCase):

    def _card(self):
        index = _index_blob([
            _index_record(b'\x02\x07', 7426, 'priprk00p11'),   # key, not a cert
            _index_record(b'\x02\x08', len(FAKE_DER), 'kxc00mscp'),
            _index_record(b'\x02\x09', 514, 'pubkxc00p11'),    # pubkey helper
        ])
        return ScriptedCard({
            b'\x01\x01': index,
            b'\x02\x08': _minidriver_cert(FAKE_DER),
        })

    def test_driver_extracts_only_the_cert(self):
        driver = IDPrimeDriver(self._card())
        certs = driver.discover_certificates()
        assert len(certs) == 1
        c = certs[0]
        assert c['label'] == 'kxc00mscp'
        assert c['id'] == b'\x02\x08'
        assert c['container'] == 0
        assert c['der'] == FAKE_DER

    def test_factory_routes_the_qes_atr_to_idprime(self):
        card = self._card()
        card.atr = bytes.fromhex('3B7F96000080318065B085050039120FFE829000')
        assert isinstance(BTrustDriver.create(card), IDPrimeDriver)


class _PinCard:
    ''' Captures APDUs; SELECT always ok, everything else returns a fixed SW '''

    def __init__(self, sw=b'\x90\x00'):
        self.sw = sw
        self.sent = []

    def get_atr(self):
        return b''

    def transmit(self, apdu):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        if apdu[:2] == b'\x00\xa4':          # SELECT applet
            return b'\x90\x00'
        return self.sw


class TestIDPrimePinVerify(unittest.TestCase):
    '''
    Encoding validated live on a B-Trust QES token: user PIN reference 0x11,
    padded to 16 bytes with 0x00 (an unpadded PIN is rejected 6700 before the
    counter moves). This pins the exact bytes so a regression can't quietly
    break PIN entry and burn a user's retries.
    '''

    def test_builds_reference_0x11_padded_to_16(self):
        card = _PinCard(b'\x90\x00')
        assert IDPrimeDriver(card).verify_pin('4958')
        verify = card.sent[-1]
        assert verify == bytes.fromhex('0020001110') + b'4958' + b'\x00' * 12

    def test_signature_pin_reference(self):
        card = _PinCard(b'\x90\x00')
        IDPrimeDriver(card).verify_pin('4958', pin_ref=IDPrimeDriver.PIN_REF_SIGNATURE)
        assert card.sent[-1][3] == 0x83

    def test_wrong_pin_reports_tries_remaining(self):
        card = _PinCard(b'\x63\xc2')               # 63 C2 = 2 tries left
        ctx = None
        try:
            IDPrimeDriver(card).verify_pin('0000')
        except Exception as _e:
            ctx = types.SimpleNamespace(exception=_e)
        assert ctx is not None, 'Exception not raised'
        assert '2 tries remaining' in str(ctx.exception)

    def test_blocked_card_is_reported(self):
        card = _PinCard(b'\x69\x83')
        ctx = None
        try:
            IDPrimeDriver(card).verify_pin('0000')
        except Exception as _e:
            ctx = types.SimpleNamespace(exception=_e)
        assert ctx is not None, 'Exception not raised'
        assert 'blocked' in str(ctx.exception).lower()

    def test_get_pin_tries_does_not_send_pin(self):
        card = _PinCard(b'\x63\xc3')               # 63 C3 = 3 tries
        assert IDPrimeDriver(card).get_pin_tries() == 3
        # the query is a case-1 VERIFY: 4 bytes, no PIN body
        query = card.sent[-1]
        assert query == bytes([0x00, 0x20, 0x00, 0x11])

    def test_overlong_pin_rejected_before_transmit(self):
        card = _PinCard()
        _raised = False
        try:
            IDPrimeDriver(card).verify_pin('12345678901234567')   # 17 chars
        except ValueError:
            _raised = True
        assert _raised, 'ValueError not raised'


class _SigningCard:
    '''
    Scripts the signing exchange and captures the APDUs. SELECT/VERIFY/MSE ->
    9000; hash-input echoes back the hash; compute returns a fixed signature.
    File 0005 (keyref) is served for read_keyref_map.
    '''

    KEYREF_0005 = bytes.fromhex('0154000003 0c0001'.replace(' ', ''))   # index0->keyref0x54,pin1
    SIG = bytes(range(0, 128)) * 3                                       # 384-byte fake sig

    def __init__(self):
        self.sent = []
        self._sel = None
        self._last_hash = b''

    def get_atr(self):
        return bytes.fromhex('3B7F96000080318065B085050039120FFE829000')

    def transmit(self, apdu):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        ins = apdu[1] if len(apdu) > 1 else 0
        if apdu[:2] == b'\x00\xa4':
            self._sel = apdu[5:5+apdu[4]] if apdu[2] == 0x00 else None
            return b'\x90\x00'
        if apdu[:2] == b'\x00\xb0':                       # READ BINARY (keyref file)
            content = self.KEYREF_0005 if self._sel == b'\x00\x05' else b''
            off = (apdu[2] << 8) | apdu[3]
            return (content[off:off+255] + b'\x90\x00') if off < len(content) else b'\x62\x82'
        if ins == 0x20:                                   # VERIFY
            return b'\x90\x00'
        if apdu[:4] == b'\x00\x2a\x90\xa0':               # hash input -> echo hash
            self._last_hash = apdu[7:7+apdu[6]]
            return self._last_hash + b'\x90\x00'
        if apdu[:4] == b'\x00\x2a\x9e\x9a':               # compute -> signature
            return self.SIG + b'\x90\x00'
        if apdu[:2] == b'\x00\x22':                       # MSE
            return b'\x90\x00'
        return b'\x90\x00'


class TestIDPrimeSigning(unittest.TestCase):

    def test_read_keyref_map(self):
        drv = IDPrimeDriver(_SigningCard())
        drv.select_applet()
        assert drv.read_keyref_map() == {0: {'key_ref': 0x54, 'pin_index': 1}}

    def test_mse_bytes(self):
        card = _SigningCard()
        IDPrimeDriver(card).set_security_environment(0x54)
        # 00 22 41 B6 06  80 01 42  84 01 54
        assert card.sent[-1] == bytes.fromhex('0022 41B6 06 800142 840154'.replace(' ', ''))

    def test_compute_sends_raw_hash_not_padded_block(self):
        card = _SigningCard()
        h = hashlib.sha256(b'x').digest()
        sig = IDPrimeDriver(card).compute_signature(h)
        hash_apdu = [a for a in card.sent if a[:4] == b'\x00\x2a\x90\xa0'][0]
        # exactly: 00 2A 90 A0 22 90 20 <32B hash> 20  -- raw hash, no PKCS#1 pad
        assert hash_apdu == bytes.fromhex('002a90a0229020') + h + b'\x20'
        assert len(sig) == 384

    def test_sign_orchestrates_verify_mse_compute(self):
        card = _SigningCard()
        drv = IDPrimeDriver(card)
        sig = drv.sign('4958', hashlib.sha256(b'doc').digest(), key_ref=0x54)
        assert len(sig) == 384
        seq = [a[:2] for a in card.sent]
        assert b'\x00\x20' in seq
        assert b'\x00\x22' in seq
        # verify precedes MSE precedes compute
        assert seq.index(b'\x00\x20') < seq.index(b'\x00\x22')

    def test_discover_attaches_key_ref(self):
        # index with one cert (kxc00) + its cert file + keyref file
        idx = _index_blob([_index_record(b'\x02\x08', len(FAKE_DER), 'kxc00mscp')])

        class Card(_SigningCard):
            def transmit(self, apdu):
                apdu = bytes(apdu)
                if apdu[:2] == b'\x00\xa4' and apdu[2] == 0x00:
                    self._sel = apdu[5:5+apdu[4]]; return b'\x90\x00'
                if apdu[:2] == b'\x00\xb0':
                    files = {b'\x01\x01': idx, b'\x02\x08': _minidriver_cert(FAKE_DER),
                             b'\x00\x05': self.KEYREF_0005}
                    c = files.get(self._sel, b''); off = (apdu[2]<<8)|apdu[3]
                    return (c[off:off+255]+b'\x90\x00') if off < len(c) else b'\x62\x82'
                return super().transmit(apdu)

        certs = IDPrimeDriver(Card()).discover_certificates()
        assert certs[0]['key_ref'] == 0x54
        assert certs[0]['pin_index'] == 1


if __name__ == '__main__':
    unittest.main()
