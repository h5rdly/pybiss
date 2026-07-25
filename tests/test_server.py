import asyncio, json, sys, unittest, logging

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.server import Request, CORS, MiniServer

logging.getLogger().setLevel(logging.CRITICAL) # Hide the deliberate error traceback


# -- Mock Async Streams 

'''
These simulate asyncio network sockets, so we can test the HTTP protocol 
instantly without actually opening ports/
'''

class MockReader:

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
    

    async def readexactly(self, n: int):
        res = self.data[self.pos:self.pos+n]
        self.pos += n
        return res


    async def readline(self):
        
        if self.pos >= len(self.data):
            return b''
        idx = self.data.find(b'\n', self.pos)
        if idx == -1:
            res = self.data[self.pos:]
            self.pos = len(self.data)
            return res
        res = self.data[self.pos:idx+1]
        self.pos = idx + 1
        
        return res



class MockWriter:

    def __init__(self):
        self.output = b''
        self.is_closed = False

    def write(self, data: bytes):
        self.output += data

    async def drain(self):
        pass

    def close(self):
        self.is_closed = True

    async def wait_closed(self):
        pass



class TestMiniServer(unittest.IsolatedAsyncioTestCase):

    def test_request_json_parsing(self):
        ''' Tests that the Request object safely parses JSON, or returns {} '''
        
        # Valid JSON
        req = Request('POST', '/', {}, b'{"key": "value"}')
        assert req.json == {'key': 'value'}

        # Invalid JSON gracefully degrades
        req_bad = Request('POST', '/', {}, b'NOT_JSON')
        assert req_bad.json == {}

        # Empty body gracefully degrades
        req_empty = Request('POST', '/', {}, b'')
        assert req_empty.json == {}


    async def test_get_route_sync(self):
        ''' Tests a standard synchronous GET request '''
        
        app = MiniServer()
        CORS(app)

        @app.get('/status')
        def status(req):
            return {'status': 'ok'}

        reader = MockReader(b'GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        assert writer.is_closed
        assert b'200 OK' in writer.output
        assert b'{"status": "ok"}' in writer.output


    async def test_post_route_async(self):
        ''' Tests an asynchronous POST request with a JSON body '''
        
        app = MiniServer()
        CORS(app)

        @app.post('/echo')
        async def echo(req):
            # Await a fake async operation to prove event loop works
            await asyncio.sleep(0.01) 
            return req.json

        req_text = (
            'POST /echo HTTP/1.1\r\n'
            'Host: 127.0.0.1\r\n'
            'Content-Length: 17\r\n'
            '\r\n'
            '{"echo": "hello"}'
        ).encode('utf-8')

        reader = MockReader(req_text)
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        assert b'200 OK' in writer.output
        assert b'{"echo": "hello"}' in writer.output


    async def test_route_ignores_query_string(self):
        """ Portals probe with a cache-buster (GET /version?_=<ts>) - must route """

        app = MiniServer()
        CORS(app)

        @app.get('/version')
        def version(req):
            return {'version': '3.46'}

        reader = MockReader(b'GET /version?_=1784914461508 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        writer = MockWriter()

        await app.handle_client(reader, writer)

        assert b'200 OK' in writer.output
        assert b'"3.46"' in writer.output


    async def test_404_not_found(self):
        ''' Tests that unregistered routes return a 404 '''
        
        app = MiniServer()
        CORS(app)

        reader = MockReader(b'GET /does-not-exist HTTP/1.1\r\n\r\n')
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        assert b'404 Not Found' in writer.output
        assert b'{"error": "Not Found"}' in writer.output


    async def test_500_internal_error_handling(self):
        ''' Tests that handler crashes are caught and return a 500 without killing the server '''
        
        app = MiniServer()
        CORS(app)

        @app.get('/crash')
        def crash(req):
            raise Exception('Deliberate crash for testing')

        reader = MockReader(b'GET /crash HTTP/1.1\r\n\r\n')
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        assert b'500 Internal Server Error' in writer.output
        assert b'Deliberate crash for testing' in writer.output


    async def test_cors_preflight_and_pna(self):
        ''' 
        Tests that OPTIONS requests are automatically intercepted 
        and Private Network Access headers are correctly mirrored.
        '''
        
        app = MiniServer()
        CORS(app, allowed_origins='https://bank.borica.bg')

        req_text = (
            'OPTIONS /sign HTTP/1.1\r\n'
            'Origin: https://bank.borica.bg\r\n'
            'Access-Control-Request-Private-Network: true\r\n'
            '\r\n'
        ).encode('utf-8')

        reader = MockReader(req_text)
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        # Must return 204 No Content for Preflight
        assert b'204 No Content' in writer.output
        
        # Must reflect the specific Origin, not '*'
        assert b'Access-Control-Allow-Origin: https://bank.borica.bg' in writer.output
        
        # MUST include the PNA bypass header
        assert b'Access-Control-Allow-Private-Network: true' in writer.output

    async def test_cors_open_origin_matches_daemon(self):
        ''' Default (no credentials): sends literal '*' like the official daemon, not a reflection '''

        app = MiniServer()
        CORS(app)  # defaults: origin '*', no credentials

        req_text = (
            'GET /status HTTP/1.1\r\n'
            'Origin: https://random-site.com\r\n'
            '\r\n'
        ).encode('utf-8')

        reader = MockReader(req_text)
        writer = MockWriter()

        await app.handle_client(reader, writer)

        assert b'Access-Control-Allow-Origin: *' in writer.output
        assert b'Access-Control-Allow-Credentials' not in writer.output
        assert b'random-site.com' not in writer.output

    async def test_cors_credentialed_mode_reflects_origin(self):
        ''' Opt-in credentialed mode reflects the Origin (since '*' is forbidden with credentials) '''

        app = MiniServer()
        CORS(app, allow_credentials=True)

        req_text = (
            'GET /status HTTP/1.1\r\n'
            'Origin: https://random-site.com\r\n'
            '\r\n'
        ).encode('utf-8')

        reader = MockReader(req_text)
        writer = MockWriter()

        await app.handle_client(reader, writer)

        assert b'Access-Control-Allow-Origin: https://random-site.com' in writer.output
        assert b'Access-Control-Allow-Credentials: true' in writer.output


if __name__ == '__main__':
    unittest.main()