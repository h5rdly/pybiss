import asyncio, json, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.server import Request, CORS, MiniServer


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
        self.assertEqual(req.json, {'key': 'value'})

        # Invalid JSON gracefully degrades
        req_bad = Request('POST', '/', {}, b'NOT_JSON')
        self.assertEqual(req_bad.json, {})

        # Empty body gracefully degrades
        req_empty = Request('POST', '/', {}, b'')
        self.assertEqual(req_empty.json, {})


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
        
        self.assertTrue(writer.is_closed)
        self.assertIn(b'200 OK', writer.output)
        self.assertIn(b'{"status": "ok"}', writer.output)


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
        
        self.assertIn(b'200 OK', writer.output)
        self.assertIn(b'{"echo": "hello"}', writer.output)


    async def test_404_not_found(self):
        ''' Tests that unregistered routes return a 404 '''
        
        app = MiniServer()
        CORS(app)

        reader = MockReader(b'GET /does-not-exist HTTP/1.1\r\n\r\n')
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        self.assertIn(b'404 Not Found', writer.output)
        self.assertIn(b'{"error": "Not Found"}', writer.output)


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
        
        self.assertIn(b'500 Internal Server Error', writer.output)
        self.assertIn(b'Deliberate crash for testing', writer.output)


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
        self.assertIn(b'204 No Content', writer.output)
        
        # Must reflect the specific Origin, not '*'
        self.assertIn(b'Access-Control-Allow-Origin: https://bank.borica.bg', writer.output)
        
        # MUST include the PNA bypass header
        self.assertIn(b'Access-Control-Allow-Private-Network: true', writer.output)

    async def test_cors_dynamic_origin_reflection(self):
        ''' Tests that if allowed_origins is '*', it dynamically reflects the requester '''
        
        app = MiniServer()
        CORS(app, allowed_origins='*')

        req_text = (
            'GET /status HTTP/1.1\r\n'
            'Origin: https://random-site.com\r\n'
            '\r\n'
        ).encode('utf-8')

        reader = MockReader(req_text)
        writer = MockWriter()
        
        await app.handle_client(reader, writer)
        
        self.assertIn(b'Access-Control-Allow-Origin: https://random-site.com', writer.output)


if __name__ == '__main__':
    unittest.main()