import asyncio, inspect, json, logging, ssl


class Request:

    def __init__(self, method: str, path: str, headers: dict, body: bytes):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    @property
    def json(self) -> dict:
        if self.body:
            try:
                return json.loads(self.body.decode('utf-8'))
            except json.JSONDecodeError:
                pass
        return {}


class CORS:
    
    def __init__(self, app, allowed_origins='*', allow_credentials=True):

        self.allowed_origins = allowed_origins
        self.allow_credentials = allow_credentials
        # Attach the CORS handler to the application instance
        app.cors = self


    def get_headers(self, req_headers: dict) -> dict:

        headers = {}
        origin = req_headers.get('origin', '*')
        
        # Browsers strictly forbid '*' if allow_credentials is True.
        # To bypass this, we dynamically reflect the requesting Origin.
        headers['Access-Control-Allow-Origin'] = origin if self.allowed_origins == '*' else self.allowed_origins
        
        if self.allow_credentials:
            headers['Access-Control-Allow-Credentials'] = 'true'
            
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        
        # For BISS: Chrome Private Network Access (PNA) bypass
        if req_headers.get('access-control-request-private-network') == 'true':
            headers['Access-Control-Allow-Private-Network'] = 'true'
            
        return headers


class MiniServer:
    
    def __init__(self):
        self.routes = {}
        self.cors = None

    def get(self, path: str): return self.route('GET', path)
    def post(self, path: str): return self.route('POST', path)


    def route(self, method: str, path: str):

        def decorator(f):
            self.routes[(method.upper(), path)] = f
            return f

        return decorator


    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        
        try:
            request_line = await reader.readline()
            if not request_line: return
            
            parts = request_line.decode().strip().split()
            if len(parts) != 3: return
            method, path, protocol = parts

            headers = {}
            content_length = 0
            while True:
                line = await reader.readline()
                if line == b'\r\n' or not line: break
                k, v = line.decode('utf-8').strip().split(':', 1)
                headers[k.lower()] = v.strip()
                if k.lower() == 'content-length':
                    content_length = int(v.strip())

            # Generate CORS headers dynamically based on the incoming request
            cors_headers_dict = self.cors.get_headers(headers) if self.cors else {}
            cors_headers_str = ''.join(f'{k}: {v}\r\n' for k, v in cors_headers_dict.items())

            # Intercept and resolve OPTIONS preflight requests
            if method == 'OPTIONS':
                res_body = b''
                status = '204 No Content'
            else:
                body = await reader.readexactly(content_length) if content_length > 0 else b''
                req = Request(method, path, headers, body)

                handler = self.routes.get((method, path))
                if handler:
                    try:
                        # Support both async and sync endpoints
                        if inspect.iscoroutinefunction(handler):
                            res_data = await handler(req)
                        else:
                            res_data = handler(req)
                        res_body = json.dumps(res_data).encode('utf-8')
                        status = '200 OK'
                    except Exception as e:
                        res_body = json.dumps({'error': str(e)}).encode('utf-8')
                        status = '500 Internal Server Error'
                        logging.error(f'Handler error: {e}', exc_info=True)
                else:
                    res_body = json.dumps({'error': 'Not Found'}).encode('utf-8')
                    status = '404 Not Found'

            response = (
                f'{protocol} {status}\r\n'
                f'Content-Type: application/json\r\n'
                f'Content-Length: {len(res_body)}\r\n'
                f'{cors_headers_str}\r\n'
            ).encode('utf-8') + res_body

            writer.write(response)
            await writer.drain()

        except Exception as e:
            logging.error(f'Connection error: {e}')
        finally:
            writer.close()
            await writer.wait_closed()


    def run(self, host='127.0.0.1', port=8080, use_ssl=False):

        ssl_context = None
        if use_ssl:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile='localhost.pem', keyfile='localhost.key')

        async def serve():
            server = await asyncio.start_server(
                self.handle_client, host, port, ssl=ssl_context
            )
            protocol = 'https' if use_ssl else 'http'
            print(f'PyBiss Daemon listening on {protocol}://{host}:{port}')
            async with server:
                await server.serve_forever()
                
        try:
            asyncio.run(serve())
        except KeyboardInterrupt:
            print('\nShutting down daemon.')

