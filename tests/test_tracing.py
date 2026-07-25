import json, os, sys, tempfile, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.tracing import TracingConnection, ReplayConnection
from tests.mocks import FakeSmartCardConnection


class TestTracingConnection(unittest.TestCase):

    def _card(self, responses, atr=b'\x3b\x01'):
        card = FakeSmartCardConnection()
        card.atr_bytes = atr
        card.transmit_responses = list(responses)
        return card

    def test_records_atr_and_exchanges(self):
        card = self._card([b'\x6a\x82', b'\x90\x00'])
        rec = TracingConnection(card)

        rec.get_atr()
        rec.transmit(b'\x00\xa4\x04\x00')
        rec.transmit(b'\x00\xb0\x00\x00')

        data = rec.to_dict()
        assert data['atr'] == '3B01'
        assert data['exchanges'] == [
            {'apdu': '00A40400', 'response': '6A82'},
            {'apdu': '00B00000', 'response': '9000'},
        ]

    def test_transmit_returns_underlying_response_unchanged(self):
        card = self._card([b'\xca\xfe\x90\x00'])
        rec = TracingConnection(card)
        assert rec.transmit(b'\x00\x01') == b'\xca\xfe\x90\x00'

    def test_to_dict_lazily_fills_atr(self):
        rec = TracingConnection(self._card([], atr=b'\x3b\x99'))
        # get_atr never called explicitly; to_dict() should still capture it
        assert rec.to_dict()['atr'] == '3B99'

    def test_save_writes_loadable_json(self):
        card = self._card([b'\x90\x00'])
        rec = TracingConnection(card)
        rec.get_atr()
        rec.transmit(b'\x00\xa4\x00\x00')

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'card.trace.json')
            rec.save(path)
            with open(path) as f:
                loaded = json.load(f)
        assert loaded == rec.to_dict()


class TestReplayConnection(unittest.TestCase):

    TRACE = {
        'atr': '3B7F',
        'exchanges': [
            {'apdu': '00A40400', 'response': '9000'},
            {'apdu': '00B00000', 'response': 'DEAD9000'},
        ],
    }

    def test_keyed_replay_matches_by_apdu_order_independent(self):
        conn = ReplayConnection.from_dict(self.TRACE)
        # Query in reverse of recorded order - keyed mode still resolves
        assert conn.transmit(b'\x00\xb0\x00\x00') == b'\xde\xad\x90\x00'
        assert conn.transmit(b'\x00\xa4\x04\x00') == b'\x90\x00'
        assert conn.get_atr() == b'\x3b\x7f'

    def test_keyed_replay_unknown_apdu_raises(self):
        conn = ReplayConnection.from_dict(self.TRACE)
        _raised = False
        try:
            conn.transmit(b'\x00\xff\xff\xff')
        except Exception:
            _raised = True
        assert _raised, 'Exception not raised'

    def test_repeated_apdu_returns_responses_in_order(self):
        trace = {'atr': '', 'exchanges': [
            {'apdu': '00B00000', 'response': 'AA9000'},
            {'apdu': '00B00000', 'response': 'BB9000'},
        ]}
        conn = ReplayConnection.from_dict(trace)
        assert conn.transmit(b'\x00\xb0\x00\x00') == b'\xaa\x90\x00'
        assert conn.transmit(b'\x00\xb0\x00\x00') == b'\xbb\x90\x00'
        # Drained single-shot repeats its last recorded response
        assert conn.transmit(b'\x00\xb0\x00\x00') == b'\xbb\x90\x00'

    def test_sequential_replay_enforces_order(self):
        conn = ReplayConnection.from_dict(self.TRACE, sequential=True)
        assert conn.transmit(b'\x00\xa4\x04\x00') == b'\x90\x00'
        assert conn.transmit(b'\x00\xb0\x00\x00') == b'\xde\xad\x90\x00'

    def test_sequential_replay_rejects_wrong_apdu(self):
        conn = ReplayConnection.from_dict(self.TRACE, sequential=True)
        _raised = False
        try:
            conn.transmit(b'\x00\xb0\x00\x00')  # expected 00A40400 first
        except Exception:
            _raised = True
        assert _raised, 'Exception not raised'

    def test_roundtrip_record_then_replay_drives_a_driver(self):
        ''' A recorded trace replays identically to the original card '''

        card = FakeSmartCardConnection()
        card.atr_bytes = b'\x3b\x7f'
        card.transmit_responses = [b'\x90\x00', b'\xbe\xef\x90\x00']

        rec = TracingConnection(card)
        rec.get_atr()
        a = rec.transmit(b'\x00\xa4\x04\x00')
        b = rec.transmit(b'\x00\xca\x00\x00')

        replay = ReplayConnection.from_dict(rec.to_dict(), sequential=True)
        assert replay.get_atr() == b'\x3b\x7f'
        assert replay.transmit(b'\x00\xa4\x04\x00') == a
        assert replay.transmit(b'\x00\xca\x00\x00') == b


class TestFixtureReplayDrivesDriver(unittest.TestCase):
    '''
    Replay-driven regression per driver: a frozen MiniDriver trace replays
    through the real IDPrimeDriver with no hardware, catching any regression in
    the discovery walk against a fixed byte-for-byte ground truth. The fixture
    is a synthetic 'Test User' card (no PII); the identical walk was verified
    against a real B-Trust QES token, whose trace is deliberately not committed.
    '''

    FIXTURE = os.path.join(os.path.dirname(__file__),
                           'fixtures', 'idprime_minidriver.trace.json')

    def test_idprime_discovery_replays_from_fixture(self):
        from src.cards import BTrustDriver

        conn = ReplayConnection.load(self.FIXTURE)
        assert conn.get_atr().hex().upper() == '3B7F96000080318065B085050039120FFE829000'
        with conn.transaction():
            driver = BTrustDriver.create(conn)
            assert driver.__class__.__name__ == 'IDPrimeDriver'
            certs = driver.discover_certificates()

        assert len(certs) == 1
        assert certs[0]['label'] == 'kxc00mscp'
        assert certs[0]['key_ref'] == 0x54
        assert certs[0]['der'].startswith(b'\x30\x82')


if __name__ == '__main__':
    unittest.main()
