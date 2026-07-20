'''
serve a scripted smart card to pcscd through the vsmartcard vpcd driver

vpcd (libifdvpcd) is an IFD handler that pcscd loads like any reader driver. It 
listens on a TCP port and speaks a tiny APDU protocol. We connect to it and answer 
as the card. So pybiss's real transport stack - 
src/sc_ffi (ctypes) -> libpcsclite -> pcscd -> vpcd -> us - runs end to end.

That is a strict subset of what tests/test_utils/f_ccid.py covers on Linux (f_ccid also
exercises libccid and the USB layer). vpcd earns its keep OFF Linux: dummy_hcd
is Linux-only, while pcscd is not, and src/sc_types.py has three different
ctypes branches (libpcsclite / PCSC.framework / winscard.dll) of which only the
Linux one has ever met a live daemon. See tools/vpcd_design.md.

The card is tests/synthetic_card.SyntheticIDPrimeCard (real RSA, zero PII), or
any recorded trace via --replay. Pure stdlib: identical on every platform.

    python tests/test_utils/vpcd_card.py                     # serve a synthetic card
    python tests/test_utils/vpcd_card.py --replay trace.json # replay a captured trace
    python tests/test_utils/vpcd_card.py --print-conf        # emit the reader.conf snippet
'''

import argparse, socket, struct, sys, time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path[:0] = [str(_ROOT), str(_ROOT / 'tests')]

VPCD_PORT = 35963                      # vpcd's first slot (35964 is the second)

# vpcd.h: control messages are a single byte; anything longer is an APDU.
CTRL_LEN = 1
CTRL_OFF, CTRL_ON, CTRL_RESET, CTRL_ATR = 0, 1, 2, 4


class Disconnected(Exception):
    ''' vpcd closed the connection (pcscd stopped, or the driver unloaded) '''


# --- framing: uint16 big-endian length prefix, then the payload --------------

def frame(payload: bytes) -> bytes:
    return struct.pack('!H', len(payload)) + bytes(payload)


def recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Disconnected()
        buf += chunk
    return buf


def recv_message(sock) -> bytes:
    ''' One length-prefixed message from vpcd (may be b'' for a zero-length one) '''

    (size,) = struct.unpack('!H', recv_exact(sock, 2))
    return recv_exact(sock, size) if size else b''


# --- the protocol engine -----------------------------------------------------

def handle_message(card, msg: bytes):
    '''
    One message from vpcd -> the bytes to send back, or None when the protocol
    wants no reply. ONLY the ATR request is answered; power on/off and reset are
    silent state changes (replying to them would desync the stream).
    '''

    if len(msg) == CTRL_LEN:
        cmd = msg[0]
        if cmd == CTRL_ATR:
            return frame(card.get_atr())
        if cmd in (CTRL_OFF, CTRL_ON, CTRL_RESET):
            reset = getattr(card, 'reset', None)    # optional on the card duck type
            if cmd in (CTRL_RESET, CTRL_OFF) and callable(reset):
                reset()
            return None
        return None                                 # unknown control: stay quiet
    if not msg:
        return None                                 # zero-length: nothing to do
    return frame(card.transmit(msg))                # an APDU, 1:1 with the card


def serve_connection(card, sock, log=print) -> None:
    ''' Answer vpcd on an established socket until it hangs up '''

    while True:
        msg = recv_message(sock)
        reply = handle_message(card, msg)
        if log:
            kind = ('ctrl 0x%02X' % msg[0]) if len(msg) == CTRL_LEN else f'apdu[{len(msg)}]'
            log(f'  {kind} -> {"none" if reply is None else str(len(reply) - 2) + " bytes"}')
        if reply is not None:
            sock.sendall(reply)


def serve(card, host='127.0.0.1', port=VPCD_PORT, retry=True, log=print) -> None:
    '''
    Connect to vpcd and act as the card. vpcd LISTENS (upstream default: one port
    per slot, 35963/35964) and we dial in - our connection IS the card insertion.
    Reconnects when pcscd restarts, so the card "reappears".
    '''

    while True:
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.settimeout(None)
                log(f'[vpcd] connected to {host}:{port} - card inserted')
                serve_connection(card, sock, log=log)
        except Disconnected:
            log('[vpcd] vpcd hung up - card removed')
        except ConnectionRefusedError:
            log(f'[vpcd] nothing listening on {host}:{port} '
                '(is pcscd running with the vpcd reader configured?)')
        except OSError as e:
            log(f'[vpcd] connection error: {e}')
        if not retry:
            return
        time.sleep(1)


# --- reader.conf helper ------------------------------------------------------

_CONF_SEARCH = [
    '/usr/lib/pcsc/drivers/serial/libifdvpcd.so',        # Arch / Debian
    '/usr/lib64/pcsc/drivers/serial/libifdvpcd.so',      # Fedora
    '/usr/local/lib/pcsc/drivers/serial/libifdvpcd.so',  # FreeBSD / local build
    '/usr/local/lib/libifdvpcd.so',
]


def print_conf(port=VPCD_PORT) -> None:
    ''' The reader.conf.d snippet, with LIBPATH resolved if we can find it '''

    found = next((p for p in _CONF_SEARCH if Path(p).exists()), None)
    if sys.platform == 'darwin':
        print('# macOS has no reader.conf: SmartCardServices loads driver bundles.')
        print('# Drop ifd-vpcd.bundle into:')
        print('#   /usr/local/libexec/SmartCardServices/drivers')
        return
    conf_dir = ('/usr/local/etc/reader.conf.d' if 'bsd' in sys.platform
                else '/etc/reader.conf.d')
    print(f'# write this to {conf_dir}/vpcd , then restart pcscd')
    if not found:
        print('# WARNING: libifdvpcd.so not found; install vsmartcard and fix LIBPATH')
    print('FRIENDLYNAME "Virtual PCD"')
    print(f'DEVICENAME   /dev/null:0x{port:04X}')
    print(f'LIBPATH      {found or _CONF_SEARCH[0]}')
    print(f'CHANNELID    0x{port:04X}')


# --- entry point -------------------------------------------------------------

def build_card(args):
    if args.replay:
        from src.tracing import ReplayConnection
        import json
        return ReplayConnection.from_dict(json.loads(Path(args.replay).read_text()))
    from synthetic_card import synthetic_idprime_card
    return synthetic_idprime_card(name=args.name, personal_id=args.personal_id,
                                  email=args.email)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=VPCD_PORT)
    p.add_argument('--name', default='VPCD Virtual Signer')
    p.add_argument('--personal-id', default='PNOBG-0000000001')
    p.add_argument('--email', default=None)
    p.add_argument('--replay', metavar='TRACE.json',
                   help='serve a recorded trace instead of a synthetic card')
    p.add_argument('--once', action='store_true',
                   help='do not reconnect after vpcd hangs up')
    p.add_argument('--quiet', action='store_true')
    p.add_argument('--print-conf', action='store_true',
                   help='print the reader.conf.d snippet and exit')
    args = p.parse_args(argv)

    if args.print_conf:
        print_conf(args.port)
        return 0

    card = build_card(args)
    log = (lambda *a: None) if args.quiet else print
    log(f'[vpcd] serving card with ATR {card.get_atr().hex().upper()}')
    try:
        serve(card, args.host, args.port, retry=not args.once, log=log)
    except KeyboardInterrupt:
        log('\n[vpcd] stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
