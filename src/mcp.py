'''
MCP server exposing pybiss card inspection as tools, so any Model Context
Protocol host (Claude Code, etc.) can inspect a smart card natively instead of
hand-writing throwaway scripts.

Stdlib only - newline-delimited JSON-RPC 2.0 over stdio, mirroring purecdp.mcp.
No third-party `mcp` package, in keeping with pybiss's dependency-free ethos.

Safety split (the card is a single, brickable QES token):
  * READ-ONLY tools run freely - they can never spend a PIN attempt or write:
    list_readers, detect_card, pin_status (a no-decrement status query),
    list_certificates (public certs, no PIN), token_info, replay_trace.
  * WRITE / PIN-spending tools (change_pin, unblock_pin, change_puk,
    import_certificate) require a HUMAN confirmation at the terminal (/dev/tty)
    for EVERY call, and the PIN/PUK is typed there - never passed as a tool
    argument, so the LLM never sees it and can never fire one blind. With no
    interactive terminal, they refuse.

Run from an MCP host as a subprocess:  python -m src.mcp

The protocol layer (MCPServer.handle) is transport-free and unit-tested by
feeding it JSON-RPC dicts; serve_stdio wires it to real stdin/stdout.
'''

import asyncio
import json
import sys
import typing
from contextlib import suppress

PROTOCOL_VERSION = '2024-11-05'


READ_TOOLS: list[dict] = [
    {'name': 'list_readers',
     'description': 'List the PC/SC smart-card readers currently attached.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'detect_card',
     'description': 'Detect inserted card(s): ATR and the identified provider '
                    '(GEMALTO / CRYPTOVISION / SIEMENS).',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'pin_status',
     'description': 'Remaining PIN attempts for the user and signature PINs. '
                    'Read-only: uses a status query that does NOT spend an attempt.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'list_certificates',
     'description': 'List certificates on the card (label, subject, size, key '
                    'ref). Read-only discovery of PUBLIC certs - no PIN.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'token_info',
     'description': 'Card summary: reader, ATR, provider, driver, certificate '
                    'count. No PIN, and no vendor PKCS#11 (avoids the IDPrime '
                    'library that can segfault a long-lived server).',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'replay_trace',
     'description': 'Inspect a recorded card trace (.trace.json) with NO '
                    'hardware: replays it through the driver and lists its certs.',
     'inputSchema': {'type': 'object',
                     'properties': {'path': {'type': 'string'}},
                     'required': ['path']}},
]

WRITE_TOOLS: list[dict] = [
    {'name': 'change_pin',
     'description': 'Change the card USER PIN. Requires human confirmation at '
                    'the terminal; the current and new PIN are typed there, '
                    'never passed here. A wrong PIN spends an attempt.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'unblock_pin',
     'description': 'Unblock the PIN with the PUK. Human-confirmed at the '
                    'terminal; PUK and new PIN typed there. WRONG PUK CAN BRICK '
                    'THE CARD.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'change_puk',
     'description': 'Change the PUK. Human-confirmed at the terminal; codes '
                    'typed there.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'import_certificate',
     'description': 'Write a certificate (DER/PEM file) to the card. '
                    'Human-confirmed at the terminal; PIN typed there.',
     'inputSchema': {'type': 'object',
                     'properties': {'cert_path': {'type': 'string'}},
                     'required': ['cert_path']}},
]

_WRITE_NAMES = frozenset(t['name'] for t in WRITE_TOOLS)


def _tty_confirm(summary: str, prompts: list[str]) -> dict | None:
    '''
    Ask the HUMAN at the controlling terminal to approve a card write and type
    any secrets there. Returns {prompt: value} on approval, None if declined or
    there is no interactive terminal (fail-safe: no tty -> no write).
    '''

    import getpass
    try:
        tty = open('/dev/tty', 'r+')
    except OSError:
        return None                        # no controlling terminal -> refuse
    try:
        tty.write(f'\n[pybiss MCP] {summary}\n  Proceed? [y/N]: ')
        tty.flush()
        if tty.readline().strip().lower() not in ('y', 'yes'):
            return None
        values = {}
        for p in prompts:
            # getpass reads from /dev/tty without echo - keeps PINs off screen
            values[p] = getpass.getpass(f'  {p}: ')
        return values
    finally:
        tty.close()


# --- read-only implementations (never spend a PIN, never write) --------------

def _read_card(fn):
    from .card_access import _open_card
    from .cards import BTrustDriver
    cm = _open_card()
    conn = cm.__enter__()
    try:
        with conn.transaction():
            return fn(BTrustDriver.create(conn))
    finally:
        cm.__exit__(None, None, None)


def _list_readers() -> str:
    from . import detector
    readers = detector.get_readers()
    return '\n'.join(readers) if readers else 'No readers attached.'


def _detect_card() -> str:
    from . import detector
    atrs = detector.get_connected_atrs(ccid_fallback=True)
    if not atrs:
        return 'No card detected.'
    return '\n'.join(f'ATR {a}  ->  provider {detector.identify_provider(a) or "unknown"}'
                     for a in atrs)


def _pin_status() -> str:
    def fn(d):
        if not hasattr(d, 'get_pin_tries'):
            return f'{d.__class__.__name__} does not support a PIN-status query.'
        out = []
        for label, ref in (('user', getattr(d, 'PIN_REF_USER', 0x11)),
                           ('signature', getattr(d, 'PIN_REF_SIGNATURE', 0x83))):
            try:
                n = d.get_pin_tries(ref)
                out.append(f'{label} PIN: '
                           + ('verified this session' if n == -1 else f'{n}/3 attempts remaining'))
            except Exception as e:
                out.append(f'{label} PIN: query failed ({e})')
        return '\n'.join(out)
    return _read_card(fn)


def _list_certificates() -> str:
    from .cert_parser import get_x509_subject

    def fn(d):
        certs = d.discover_certificates()
        lines = [f'{len(certs)} certificate(s):']
        for c in certs:
            der = c.get('der', b'')
            subj = get_x509_subject(der) if der else '(no DER)'
            lines.append(f"  - {c.get('label', '?')}: {subj}  "
                         f"({len(der)} bytes, key_ref={c.get('key_ref')})")
        return '\n'.join(lines)
    return _read_card(fn)


def _token_info() -> str:
    # Deliberately PKCS#11-free: card_service.token_info() prefers the vendor
    # IDPrime library, which can SEGFAULT in C_GetSlotList and take the whole
    # MCP server down (a signal, uncatchable). Build the summary from the safe
    # detector + raw-APDU path instead - the same one pin_status uses.
    from . import detector
    readers = detector.get_readers()
    atrs = detector.get_connected_atrs(ccid_fallback=True)
    if not atrs:
        return 'No card detected.'
    atr = atrs[0]
    lines = [f'reader: {readers[0] if readers else "(direct CCID)"}',
             f'ATR: {atr}',
             f'provider: {detector.identify_provider(atr) or "unknown"}']
    try:
        lines += _read_card(lambda d: [f'driver: {d.__class__.__name__}',
                                       f'certificates: {len(d.discover_certificates())}'])
    except Exception as e:
        lines.append(f'(driver read failed: {e})')
    return '\n'.join(lines)


def _replay_trace(path: str) -> str:
    from .tracing import ReplayConnection
    from .cards import BTrustDriver
    from .cert_parser import get_x509_subject
    conn = ReplayConnection.load(path)
    lines = [f'ATR {conn.get_atr().hex().upper()}']
    with conn.transaction():
        d = BTrustDriver.create(conn)
        lines.append(f'driver: {d.__class__.__name__}')
        for c in d.discover_certificates():
            der = c.get('der', b'')
            lines.append(f"  - {c.get('label', '?')}: "
                         f"{get_x509_subject(der) if der else '(no DER)'} ({len(der)}B)")
    return '\n'.join(lines)


def _result(msg_id, result: dict) -> dict:
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def _error(msg_id, code: int, message: str) -> dict:
    return {'jsonrpc': '2.0', 'id': msg_id, 'error': {'code': code, 'message': message}}


class MCPServer:
    '''
    MCP protocol handler for card inspection. `confirm` is the human-gate for
    write tools - the injection point for tests; production uses _tty_confirm.
    '''

    def __init__(self, confirm: typing.Callable[[str, list], dict | None] | None = None):
        self._confirm = confirm or _tty_confirm

    def _tools(self) -> list[dict]:
        return READ_TOOLS + WRITE_TOOLS      # all advertised; writes are call-gated

    async def handle(self, msg: dict) -> dict | None:
        method = msg.get('method')
        msg_id = msg.get('id')
        if method == 'initialize':
            return _result(msg_id, {
                'protocolVersion': PROTOCOL_VERSION,
                'capabilities': {'tools': {}},
                'serverInfo': {'name': 'pybiss', 'version': '0'},
            })
        if method == 'tools/list':
            return _result(msg_id, {'tools': self._tools()})
        if method == 'tools/call':
            return await self._call_tool(msg_id, msg.get('params') or {})
        if method == 'ping':
            return _result(msg_id, {})
        if method is not None and method.startswith('notifications/'):
            return None
        if msg_id is not None:
            return _error(msg_id, -32601, f'method not found: {method}')
        return None

    async def _call_tool(self, msg_id, params: dict) -> dict:
        name = params.get('name')
        args = params.get('arguments') or {}
        try:
            # card I/O is blocking; keep the event loop free
            text = await asyncio.to_thread(self._run_tool, name, args)
            return _result(msg_id, {'content': [{'type': 'text', 'text': text}]})
        except Exception as exc:            # tool errors reported in-band, per MCP
            return _result(msg_id, {'content': [{'type': 'text', 'text': f'error: {exc}'}],
                                    'isError': True})

    def _run_tool(self, name: str | None, args: dict) -> str:
        if name == 'list_readers':      return _list_readers()
        if name == 'detect_card':       return _detect_card()
        if name == 'pin_status':        return _pin_status()
        if name == 'list_certificates': return _list_certificates()
        if name == 'token_info':        return _token_info()
        if name == 'replay_trace':      return _replay_trace(args['path'])
        if name in _WRITE_NAMES:        return self._run_write_tool(name, args)
        raise ValueError(f'unknown tool {name!r}')

    def _run_write_tool(self, name: str, args: dict) -> str:
        from . import card_service
        if name == 'change_pin':
            got = self._confirm('Change the card USER PIN (a wrong PIN spends an attempt).',
                                ['current PIN', 'new PIN'])
            if not got:
                return 'cancelled (declined or no interactive terminal).'
            card_service.change_pin(got['current PIN'], got['new PIN'])
            return 'PIN changed.'
        if name == 'unblock_pin':
            got = self._confirm('Unblock the PIN with the PUK. A WRONG PUK CAN BRICK THE CARD.',
                                ['PUK', 'new PIN'])
            if not got:
                return 'cancelled (declined or no interactive terminal).'
            card_service.unblock_pin(got['PUK'], got['new PIN'])
            return 'PIN unblocked.'
        if name == 'change_puk':
            got = self._confirm('Change the card PUK.', ['current PUK', 'new PUK'])
            if not got:
                return 'cancelled (declined or no interactive terminal).'
            card_service.change_puk(got['current PUK'], got['new PUK'])
            return 'PUK changed.'
        if name == 'import_certificate':
            cert_path = args['cert_path']
            with open(cert_path, 'rb') as f:
                blob = f.read()
            if b'-----BEGIN' in blob:
                from .cert_parser import pem_to_der
                blob = pem_to_der(blob)[0]
            got = self._confirm(f'Write certificate {cert_path} to the card.', ['PIN'])
            if not got:
                return 'cancelled (declined or no interactive terminal).'
            card_service.import_certificate(blob, got['PIN'])
            return 'certificate imported.'
        raise ValueError(f'unknown write tool {name!r}')


async def serve_stdio(server: MCPServer) -> None:
    ''' Run `server` over stdin/stdout (newline-delimited JSON-RPC 2.0) '''

    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:                        # EOF
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        response = await server.handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()


def main(argv: typing.Sequence[str] | None = None) -> None:
    asyncio.run(serve_stdio(MCPServer()))


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        main()
