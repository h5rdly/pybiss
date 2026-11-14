import os, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import mcp


class TestMcpProtocol(unittest.IsolatedAsyncioTestCase):

    async def test_initialize(self):
        r = await mcp.MCPServer().handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'})
        assert r['result']['protocolVersion'] == mcp.PROTOCOL_VERSION
        assert r['result']['serverInfo']['name'] == 'pybiss'

    async def test_tools_list_advertises_read_and_write(self):
        r = await mcp.MCPServer().handle({'id': 2, 'method': 'tools/list'})
        names = {t['name'] for t in r['result']['tools']}
        assert {'list_readers', 'pin_status', 'list_certificates', 'token_info',
                'replay_trace'} <= names            # read-only
        assert {'change_pin', 'unblock_pin', 'change_puk', 'import_certificate'} <= names

    async def test_unknown_method_errors(self):
        r = await mcp.MCPServer().handle({'id': 3, 'method': 'bogus'})
        assert r['error']['code'] == -32601

    async def test_notification_gets_no_reply(self):
        r = await mcp.MCPServer().handle({'method': 'notifications/initialized'})
        assert r is None

    async def test_read_tool_list_readers(self):
        import src.detector as det
        orig = det.get_readers
        det.get_readers = lambda: ['Fake Reader 0']
        try:
            r = await mcp.MCPServer().handle({'id': 4, 'method': 'tools/call',
                'params': {'name': 'list_readers', 'arguments': {}}})
        finally:
            det.get_readers = orig
        assert 'Fake Reader 0' in r['result']['content'][0]['text']

    async def test_replay_trace_is_hardware_free(self):
        fx = os.path.join(os.path.dirname(__file__), 'fixtures', 'idprime_minidriver.trace.json')
        r = await mcp.MCPServer().handle({'id': 5, 'method': 'tools/call',
            'params': {'name': 'replay_trace', 'arguments': {'path': fx}}})
        text = r['result']['content'][0]['text']
        assert 'IDPrimeDriver' in text and 'kxc00mscp' in text


class TestMcpWriteGate(unittest.IsolatedAsyncioTestCase):
    ''' The safety core: a write tool NEVER runs without a human confirmation,
        and the PIN is collected at the terminal, never from the tool call. '''

    def setUp(self):
        import src.card_service as cs
        self.cs = cs
        self._orig = cs.change_pin
        self.calls = []
        cs.change_pin = lambda old, new, **k: self.calls.append((old, new))

    def tearDown(self):
        self.cs.change_pin = self._orig

    async def test_declined_write_never_executes(self):
        # confirm returns None == human said no, or there's no interactive tty
        srv = mcp.MCPServer(confirm=lambda summary, prompts: None)
        r = await srv.handle({'id': 6, 'method': 'tools/call',
            'params': {'name': 'change_pin', 'arguments': {}}})
        assert 'cancelled' in r['result']['content'][0]['text']
        assert self.calls == []                    # the card was never touched

    async def test_confirmed_write_uses_terminal_secrets(self):
        srv = mcp.MCPServer(confirm=lambda summary, prompts: {'current PIN': '4958', 'new PIN': '0000'})
        r = await srv.handle({'id': 7, 'method': 'tools/call',
            'params': {'name': 'change_pin', 'arguments': {}}})
        assert 'PIN changed' in r['result']['content'][0]['text']
        assert self.calls == [('4958', '0000')]    # secrets came from confirm, not args

    async def test_write_tool_schema_accepts_no_pin_argument(self):
        # proves an LLM cannot pass a PIN through the tool call at all
        tool = next(t for t in mcp.WRITE_TOOLS if t['name'] == 'change_pin')
        assert tool['inputSchema'].get('properties') == {}


if __name__ == '__main__':
    unittest.main()
