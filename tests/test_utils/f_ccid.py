'''
f_ccid - a virtual USB CCID reader with a synthetic card behind it.

This is the DEVICE side of USB CCID (the mirror of src/ccid.py, which is the
host side): it registers a software USB gadget on the kernel's virtual bus
(dummy_hcd) and answers PC_to_RDR_* messages, so the whole OS - lsusb, libccid,
pcscd, and pybiss's own src/ccid.py - sees a real reader with a card inserted.
The card is tests/synthetic_card.SyntheticIDPrimeCard: MiniDriver layout,
real RSA signatures, zero PII. See tools/f_ccid_design.md for the rationale.

Needs root and the dummy_hcd + libcomposite modules (modprobed automatically).

    sudo python tests/test_utils/f_ccid.py            # foreground; Ctrl-C tears down
    sudo python tests/test_utils/f_ccid.py start      # background daemon (log/pid in /run)
    sudo python tests/test_utils/f_ccid.py stop       # kill daemon + tear down
    sudo python tests/test_utils/f_ccid.py teardown   # just clean up a leftover gadget

Success check (as the normal user, no root):

    python -c "from src.ccid import find_ccid_readers; print(find_ccid_readers())"
'''

import os, signal, struct, subprocess, sys, threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path[:0] = [str(_ROOT), str(_ROOT / 'tests')]

from test_ccid import REAL_BLOB                      # pinned Circle CCR7115 bytes
from synthetic_card import synthetic_idprime_card

GADGET = Path('/sys/kernel/config/usb_gadget/pybiss')
MOUNT = Path('/run/pybiss_ffs')
PIDFILE = Path('/run/pybiss_f_ccid.pid')
LOGFILE = Path('/run/pybiss_f_ccid.log')
# Must be a VID:PID libccid lists in its Info.plist: pcsc-lite's get_driver()
# matches the CCID *class* driver by idVendor/idProduct, not by USB class alone
# (class-only binding is the kernel's job, not pcscd's). We present the real
# Circle CCR7115 - the same reader our descriptor blob is captured from.
VID, PID = '0x31AA', '0x7001'                        # Circle CCR7115 ICC


def log(*parts):
    print(*parts, flush=True)


# --- USB / FunctionFS descriptors --------------------------------------------
# The interface descriptor (class 0x0B) and the 54-byte CCID functional
# descriptor are lifted VERBATIM from the real reader blob pinned in
# tests/test_ccid.py, so what libccid parses here is exactly what it parses on
# genuine hardware: extended-APDU level (dwFeatures 0x000404BA), T=0+T=1,
# no clock/data-rate lists (so no class control requests to answer).

def _pluck(blob: bytes, dtype: int) -> bytes:
    i = 0
    while i + 1 < len(blob):
        n = blob[i]
        if n == 0:
            break
        if blob[i + 1] == dtype:
            return blob[i:i + n]
        i += n
    raise ValueError(f'descriptor 0x{dtype:02X} not found')


# The real reader's iInterface is 2 (a string ref); FunctionFS then demands a
# 2-entry string table (strings_count = highest referenced index). Zero it so
# the interface carries no string and any table shape is accepted.
_iface = bytearray(_pluck(REAL_BLOB, 0x04))          # 09 04 .. class 0x0B ..
_iface[8] = 0                                        # iInterface -> none
INTERFACE_DESC = bytes(_iface)
CCID_FUNCTIONAL = _pluck(REAL_BLOB, 0x21)            # the 54-byte class descriptor


def _ep(addr, attrs, mps, interval=0):
    return struct.pack('<BBBBHB', 7, 5, addr, attrs, mps, interval)


def _speed_descs(bulk_mps, intr_interval):
    # Endpoint file numbering follows declaration order: ep1/ep2/ep3.
    return (INTERFACE_DESC + CCID_FUNCTIONAL
            + _ep(0x81, 0x02, bulk_mps)              # bulk IN  -> ep1 (we write)
            + _ep(0x02, 0x02, bulk_mps)              # bulk OUT -> ep2 (we read)
            + _ep(0x83, 0x03, 8, intr_interval))     # intr IN  -> ep3 (notify)


def build_descriptors() -> bytes:
    ''' usb_functionfs_descs_head_v2: magic 3, FS+HS flags, 5 descriptors each '''

    fs = _speed_descs(64, 10)                        # FS interval: ms
    hs = _speed_descs(512, 7)                        # HS interval: 2^(7-1) uframes
    body = struct.pack('<II', 5, 5) + fs + hs
    return struct.pack('<III', 3, 12 + len(body), 1 | 2) + body


def build_strings() -> bytes:
    ''' One en-US table with a single label. Nothing references it (we zero
        iInterface above), it just keeps to the well-trodden 1-lang/1-string
        shape every real-world gadget uses. '''

    body = struct.pack('<H', 0x0409) + b'pybiss CCID\x00'
    return struct.pack('<IIII', 2, 16 + len(body), 1, 1) + body


# --- the CCID protocol engine (device side) -----------------------------------
# 10-byte header both ways: <BIBBBBB> = type, dwLength, bSlot, bSeq, 3 extras.
# We echo bSlot/bSeq and answer with bStatus 0x00 (card present and active).

def _msg(mtype, data, slot, seq, status=0x00, error=0x00, extra=0x00):
    return struct.pack('<BIBBBBB', mtype, len(data), slot, seq,
                       status, error, extra) + data


# T=0 parameter block matching the ATR's TA1=0x96 (Fi/Di), WI=10
_T0_PARAMS = bytes([0x96, 0x00, 0x00, 0x0A, 0x00])


def dispatch(card, mtype, payload, slot, seq) -> bytes:
    ''' One PC_to_RDR message -> the RDR_to_PC reply '''

    if mtype == 0x62:                                # IccPowerOn -> ATR
        return _msg(0x80, card.get_atr(), slot, seq)
    if mtype == 0x63:                                # IccPowerOff -> inactive
        return _msg(0x81, b'', slot, seq, status=0x01)
    if mtype == 0x65:                                # GetSlotStatus -> active
        return _msg(0x81, b'', slot, seq)
    if mtype == 0x6F:                                # XfrBlock -> the card
        return _msg(0x80, bytes(card.transmit(payload)), slot, seq)
    if mtype in (0x61, 0x6C, 0x6D):                  # Set/Get/ResetParameters
        return _msg(0x82, _T0_PARAMS, slot, seq)     # extra=0: T=0
    if mtype == 0x6B:                                # Escape -> command failed
        return _msg(0x83, b'', slot, seq, status=0x40)
    return _msg(0x81, b'', slot, seq)                # anything else: happy status


def serve_bulk(card, ep_out, ep_in):
    '''
    The reader main loop: read PC_to_RDR messages off the bulk-OUT endpoint,
    write replies to bulk-IN. Buffered so a message split across reads (or two
    messages landing in one) is handled. Exits when the endpoint dies
    (DISABLE/unbind makes the read raise).
    '''

    buf = b''
    while True:
        try:
            chunk = os.read(ep_out, 4096)
        except OSError as e:
            log(f'[bulk] endpoint closed ({e}); loop exiting')
            return
        buf += chunk
        while len(buf) >= 10:
            mtype, dlen, slot, seq, *_ = struct.unpack('<BIBBBBB', buf[:10])
            if len(buf) < 10 + dlen:
                break
            payload, buf = buf[10:10 + dlen], buf[10 + dlen:]
            reply = dispatch(card, mtype, payload, slot, seq)
            log(f'[ccid] {mtype:02X} len={dlen} -> {reply[0]:02X} len={len(reply)-10}')
            try:
                os.write(ep_in, reply)
            except OSError as e:
                log(f'[bulk] reply write failed ({e}); loop exiting')
                return


def notify_slot_change(ep_intr):
    ''' RDR_to_PC_NotifySlotChange: slot 0 present + changed. Blocks until the
        host actually polls the interrupt pipe, hence its own daemon thread. '''

    try:
        os.write(ep_intr, b'\x50\x03')
        log('[intr] slot-change notify delivered')
    except OSError as e:
        log(f'[intr] notify not delivered ({e}) - harmless, host polls status')


# --- FunctionFS ep0: descriptors, events, control requests --------------------

_EVENT_NAMES = {0: 'BIND', 1: 'UNBIND', 2: 'ENABLE', 3: 'DISABLE',
                4: 'SETUP', 5: 'SUSPEND', 6: 'RESUME'}


def _handle_setup(ep0, setup: bytes):
    ''' Answer a class/vendor control request. With no clock/data-rate lists in
        the descriptor nothing meaningful should arrive; ack whatever does. '''

    bmreq, breq, wval, widx, wlen = struct.unpack('<BBHHH', setup)
    log(f'[ep0] SETUP bmRequestType={bmreq:02X} bRequest={breq:02X} wLength={wlen}')
    try:
        if bmreq & 0x80:
            os.write(ep0, b'')                       # IN: empty data stage
        else:
            os.read(ep0, wlen)                       # OUT: drain / status ack
    except OSError:
        pass


def event_loop(ep0, card):
    ''' Read 12-byte usb_functionfs_event records; manage endpoint lifecycle '''

    eps = []
    while True:
        data = os.read(ep0, 12 * 16)
        for off in range(0, len(data) - 11, 12):
            setup, etype = data[off:off + 8], data[off + 8]
            log(f'[ep0] event: {_EVENT_NAMES.get(etype, etype)}')

            if etype == 2:                           # ENABLE: host configured us
                for fd in eps:
                    try: os.close(fd)
                    except OSError: pass
                ep_in = os.open(MOUNT / 'ep1', os.O_RDWR)
                ep_out = os.open(MOUNT / 'ep2', os.O_RDWR)
                ep_intr = os.open(MOUNT / 'ep3', os.O_RDWR)
                eps = [ep_in, ep_out, ep_intr]
                threading.Thread(target=serve_bulk, args=(card, ep_out, ep_in),
                                 daemon=True).start()
                threading.Thread(target=notify_slot_change, args=(ep_intr,),
                                 daemon=True).start()
                log('[gadget] enumerated and enabled - reader is live')

            elif etype in (1, 3):                    # UNBIND / DISABLE
                for fd in eps:
                    try: os.close(fd)
                    except OSError: pass
                eps = []

            elif etype == 4:                         # SETUP
                _handle_setup(ep0, setup)


# --- gadget lifecycle (configfs) ----------------------------------------------

def _w(rel, text):
    (GADGET / rel).write_text(text)


def _pick_udc() -> str:
    try:
        udcs = sorted(os.listdir('/sys/class/udc'))
    except OSError:
        udcs = []
    if not udcs:
        raise SystemExit(
            'no UDC available: dummy_hcd provides the virtual device controller, '
            'and it is not loaded. `modprobe dummy_hcd` failed - is a matching '
            'module tree installed for the RUNNING kernel (uname -r)?')
    return next((u for u in udcs if 'dummy' in u), udcs[0])


def setup() -> int:
    ''' Build the configfs gadget, mount FunctionFS, feed ep0. Returns ep0 fd
        (gadget is NOT yet bound to the UDC - bind() after this). '''

    # dummy_hcd is the virtual USB host+device controller (it supplies the UDC we
    # bind to); libcomposite/usb_f_fs give us configfs gadgets + FunctionFS. Note
    # `modprobe -a`: without -a, only the FIRST name is a module and the rest are
    # parsed as parameters to it. Modules do not survive a reboot, so load them
    # here rather than expecting the user to remember.
    subprocess.run(['modprobe', '-a', 'dummy_hcd', 'libcomposite', 'usb_f_fs'],
                   check=False)
    if not GADGET.parent.is_dir():
        raise SystemExit('configfs usb_gadget dir missing - modprobe libcomposite failed?')

    GADGET.mkdir()
    _w('idVendor', VID)
    _w('idProduct', PID)
    _w('bcdDevice', '0x0100')
    (GADGET / 'strings/0x409').mkdir(parents=True)
    _w('strings/0x409/manufacturer', 'pybiss')
    _w('strings/0x409/product', 'Virtual CCID Reader')
    _w('strings/0x409/serialnumber', 'F0CC1D')
    (GADGET / 'configs/c.1/strings/0x409').mkdir(parents=True)
    _w('configs/c.1/strings/0x409/configuration', 'ccid')
    _w('configs/c.1/MaxPower', '100')
    (GADGET / 'functions/ffs.ccid').mkdir(parents=True)
    os.symlink(GADGET / 'functions/ffs.ccid', GADGET / 'configs/c.1/ffs.ccid')

    MOUNT.mkdir(exist_ok=True)
    subprocess.run(['mount', '-t', 'functionfs', 'ccid', str(MOUNT)], check=True)

    ep0 = os.open(MOUNT / 'ep0', os.O_RDWR)
    for label, blob in (('descriptors', build_descriptors()),
                        ('strings', build_strings())):
        try:
            os.write(ep0, blob)
            log(f'[gadget] {label} accepted ({len(blob)} bytes)')
        except OSError as e:
            log(f'[gadget] {label} REJECTED ({e}) - dmesg tail:')
            log(_dmesg_tail())
            raise
    return ep0


def _dmesg_tail(lines=15):
    try:
        out = subprocess.run(['dmesg'], capture_output=True, text=True).stdout
        return '\n'.join(out.splitlines()[-lines:])
    except OSError as e:
        return f'(dmesg unavailable: {e})'


def bind():
    udc = _pick_udc()
    _w('UDC', udc)
    log(f'[gadget] bound to {udc} - virtual reader plugged in')


def teardown(quiet=False):
    ''' Undo everything, tolerating any partial state (crashed previous run) '''

    def step(what, fn):
        try:
            fn()
        except (OSError, subprocess.CalledProcessError) as e:
            if not quiet:
                log(f'[teardown] {what}: {getattr(e, "strerror", None) or e}')

    step('unbind UDC', lambda: (GADGET / 'UDC').write_text(''))
    step('umount ffs', lambda: subprocess.run(
        ['umount', str(MOUNT)], check=True, capture_output=True))
    step('unlink function', lambda: (GADGET / 'configs/c.1/ffs.ccid').unlink())
    for d in ('configs/c.1/strings/0x409', 'configs/c.1',
              'functions/ffs.ccid', 'strings/0x409', ''):
        step(f'rmdir {d or "gadget"}', (GADGET / d).rmdir)
    step('rmdir mountpoint', MOUNT.rmdir)
    step('remove pidfile', PIDFILE.unlink)


# --- entry points --------------------------------------------------------------

def _daemonize():
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    fd = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0), os.dup2(fd, 1), os.dup2(fd, 2)
    PIDFILE.write_text(str(os.getpid()))


def run(daemon=False):
    if os.geteuid() != 0:
        raise SystemExit('needs root (configfs + functionfs): sudo python tests/test_utils/f_ccid.py')
    card = synthetic_idprime_card(name='F CCID Virtual Signer',
                                  personal_id='PNOBG-0000000001')
    teardown(quiet=True)                             # clear any leftovers first
    if daemon:
        _daemonize()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    try:
        ep0 = setup()
        bind()
        event_loop(ep0, card)
    except KeyboardInterrupt:
        pass
    finally:
        log('[gadget] tearing down')
        teardown(quiet=True)


def stop():
    try:
        os.kill(int(PIDFILE.read_text()), signal.SIGTERM)
        log('daemon signalled')
    except (OSError, ValueError) as e:
        log(f'no running daemon ({e}); cleaning up anyway')
    import time
    time.sleep(0.5)
    teardown(quiet=True)


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'run'
    if mode == 'run':
        run()
    elif mode == 'start':
        run(daemon=True)
    elif mode == 'stop':
        stop()
    elif mode == 'teardown':
        teardown()
    else:
        raise SystemExit(__doc__)
