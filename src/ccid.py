'''
Direct USB CCID transport - talk to a smart-card reader over usbfs, with no
PC/SC daemon, no libccid, and no vendor middleware. Pure stdlib + ctypes.

Why this exists: on Linux the login seat user already owns the reader's raw USB
node (systemd's uaccess tags any Chip/SmartCard interface), so pybiss can drive
an *APDU-level* reader itself and stay self-contained - the "no install" story
the rest of the project aims for. It is a bottom-tier fallback, never a PC/SC
replacement: PC/SC still wins when it works, and this steps in only when it
finds nothing.

Two transports, one protocol. The CCID message layer is identical everywhere;
only the raw-USB access differs, so each OS gets a small transport class:

  * Linux   - usbfs (/dev/bus/usb/BBB/DDD): claim the interface, bulk transfers
              via USBDEVFS_BULK ioctls. Discovery through sysfs.
  * FreeBSD - ugen(4): every endpoint has its OWN device node (/dev/usb/B.D.E;
              /dev/ugenB.D is a symlink to the control one) and bulk I/O is plain
              read()/write() - no ioctl marshalling and no interface claim
              (opening the endpoint node is the claim). Discovery walks /dev and
              asks the control node for its descriptors.

Verified end to end on FreeBSD 15.1: tests/test_utils/f_ccid.py conjures a virtual CCID
reader on the host, `tools/freebsd_vm.py --usb 31aa:7001 boot` passes it into the
guest, and the real backends discover the certificate and produce a verifying
signature over ugen - no pcscd, no libusb, no physical hardware.

Scope and limits:
  * Linux and FreeBSD. Windows' usbccid.sys owns the device and macOS has its
    own CCID driver - but both ship PC/SC in the OS, so nothing is missing there.
    Everything here degrades to "no readers" off Linux/FreeBSD rather than raising.
  * APDU-level readers only (dwFeatures exchange level 0x02/0x04). The reader's
    firmware must do the T=0/T=1 framing; we do NOT implement a T=1 state
    machine. A TPDU/character-level reader is reported unsupported.
  * Fights with pcscd over the interface: claiming one pcscd already holds fails
    with EBUSY. That's the intended precedence (PC/SC first - see app._open_card).
  * Needs read/write on the raw USB node. Linux: systemd's uaccess tags any
    Chip/SmartCard interface for the seat user, so it just works. FreeBSD: devfs
    is root-only by default, so a devfs.rules entry is needed.

CcidConnection mirrors sc_ffi.SmartCardConnection's duck type
(get_atr / transmit / transaction), so BTrustDriver and the PKCS#15 layer run
over it unchanged.
'''

import ctypes, errno, os, struct, sys, time
from pathlib import Path

_SYSFS = Path('/sys/bus/usb/devices')
_DEV = Path('/dev')

# USB descriptor types
_DESC_INTERFACE = 0x04
_DESC_ENDPOINT = 0x05
_DESC_CCID = 0x21
_CCID_INTERFACE_CLASS = 0x0B     # Chip/SmartCard Interface Device

# PC_to_RDR message types (USB CCID spec 1.1, section 6.1)
_MSG_ICC_POWER_ON = 0x62
_MSG_ICC_POWER_OFF = 0x63
_MSG_GET_SLOT_STATUS = 0x65
_MSG_XFR_BLOCK = 0x6F

# dwFeatures exchange level (bits 16-19)
_EXCHANGE_MASK = 0x000F0000
_EXCHANGE_LEVELS = {
    0x00000000: 'character',
    0x00010000: 'tpdu',
    0x00020000: 'short_apdu',
    0x00040000: 'extended_apdu',
}
_APDU_LEVELS = ('short_apdu', 'extended_apdu')


class CcidError(Exception):
    ''' A CCID-level failure (transport, claim, or reader bStatus/bError) '''


class CcidNoResponse(CcidError):
    ''' The reader sent nothing at all - the request never landed (see _exchange) '''


class CcidMute(CcidError):
    '''
    The card answered ICC mute (bError=0xFE): powered down while idle, or no card
    at all. Distinct from CcidNoResponse (the reader itself stayed silent) so the
    idempotent power-on path can retry it - see CcidUsb.power_on.
    '''


# --- pure descriptor parsing (no device access; testable without hardware) ---

def parse_descriptors(blob: bytes) -> dict:
    '''
    Walk a raw USB descriptor blob and pull out the first Chip/SmartCard
    interface: its number, bulk IN/OUT endpoints, and the CCID functional
    descriptor fields we need. Returns {'ccid': None, ...} when there is no
    CCID interface.
    '''

    i = 0
    result = {'ccid': None, 'iface': None, 'ep_in': None, 'ep_out': None}

    while i + 1 < len(blob):
        blength, btype = blob[i], blob[i + 1]
        if blength == 0:
            break
        d = blob[i:i + blength]

        if btype == _DESC_INTERFACE and blength >= 9:
            iface_num, iface_class = d[2], d[5]
            if iface_class == _CCID_INTERFACE_CLASS and result['iface'] is None:
                result['iface'] = iface_num
            elif result['iface'] == iface_num and iface_class != _CCID_INTERFACE_CLASS:
                result['iface'] = None   # a later altsetting left the class

        elif (btype == _DESC_CCID and blength >= 54
              and result['iface'] is not None and result['ccid'] is None):
            result['ccid'] = {
                'bcdCCID': f'{d[3]}.{d[2]:02x}',
                'bMaxSlotIndex': d[4],
                'dwProtocols': struct.unpack_from('<I', d, 6)[0],
                'dwMaxIFSD': struct.unpack_from('<I', d, 28)[0],
                'dwFeatures': struct.unpack_from('<I', d, 40)[0],
                'dwMaxCCIDMessageLength': struct.unpack_from('<I', d, 44)[0],
                'bPINSupport': d[52],
            }

        elif (btype == _DESC_ENDPOINT and blength >= 7
              and result['iface'] is not None):
            addr, attrs = d[2], d[3]
            if attrs & 0x03 == 0x02:      # bulk
                if addr & 0x80:
                    if result['ep_in'] is None:
                        result['ep_in'] = addr
                elif result['ep_out'] is None:
                    result['ep_out'] = addr

        i += blength

    return result


def exchange_level(dw_features: int) -> str:
    ''' 'character' | 'tpdu' | 'short_apdu' | 'extended_apdu' | 'unknown' '''

    return _EXCHANGE_LEVELS.get(dw_features & _EXCHANGE_MASK, 'unknown')


def is_apdu_level(dw_features: int) -> bool:
    ''' True if the reader firmware does its own T=0/T=1 framing '''

    return exchange_level(dw_features) in _APDU_LEVELS


# --- reader discovery ---------------------------------------------------------

def find_ccid_readers() -> list[dict]:
    '''
    Every connected USB device that exposes a CCID interface. Empty list on an
    unsupported OS or when nothing is found - never raises. Each entry carries
    the parsed descriptors plus 'node', 'name', 'vid', 'pid' and the 'backend'
    that can drive it.
    '''

    if _SYSFS.is_dir():
        return _find_usbfs()
    if sys.platform.startswith('freebsd'):
        return _find_ugen()
    return []                            # Windows / macOS: PC/SC covers them


def _find_usbfs() -> list[dict]:
    ''' Linux: sysfs publishes the raw descriptor blob, world-readable '''

    out = []
    for dev in sorted(_SYSFS.glob('*')):
        desc = dev / 'descriptors'
        if not desc.exists():
            continue
        try:
            info = parse_descriptors(desc.read_bytes())
            if info['ccid'] is None or info['ep_in'] is None or info['ep_out'] is None:
                continue
            bus = int((dev / 'busnum').read_text())
            num = int((dev / 'devnum').read_text())
            info['node'] = f'/dev/bus/usb/{bus:03d}/{num:03d}'
            info['name'] = _read_text(dev / 'product') or '?'
            info['vid'] = _read_text(dev / 'idVendor') or '????'
            info['pid'] = _read_text(dev / 'idProduct') or '????'
            info['backend'] = 'usbfs'
        except OSError, ValueError:
            continue
        out.append(info)
    return out


def _find_ugen() -> list[dict]:
    '''
    FreeBSD: no sysfs, so ask each ugen control node for its descriptors. The
    control node is /dev/ugenB.D; /dev/ugenB.D.E are its endpoints (skipped).
    Needs read access to the node - devfs is root-only unless a devfs.rules
    entry says otherwise.
    '''

    out = []
    for node in sorted(_DEV.glob('ugen[0-9]*.[0-9]*')):
        if node.name.count('.') != 1:    # an endpoint node, not the control one
            continue
        try:
            info = _ugen_probe(str(node))
        except OSError:
            continue                     # no permission, or it vanished
        if info is not None:
            out.append(info)
    return out


def _read_text(p: Path):
    try:
        return p.read_text().strip()
    except OSError:
        return None


# --- Linux transport: usbfs ioctls (linux/usbdevice_fs.h) --------------------

_IOC_WRITE, _IOC_READ = 1, 2


def _IOC(direction, typ, nr, size):
    return (direction << 30) | (size << 16) | (ord(typ) << 8) | nr


class _BulkTransfer(ctypes.Structure):
    _fields_ = [('ep', ctypes.c_uint), ('len', ctypes.c_uint),
                ('timeout', ctypes.c_uint), ('data', ctypes.c_void_p)]


_USBDEVFS_CLAIMINTERFACE = _IOC(_IOC_READ, 'U', 15, ctypes.sizeof(ctypes.c_uint))
_USBDEVFS_RELEASEINTERFACE = _IOC(_IOC_READ, 'U', 16, ctypes.sizeof(ctypes.c_uint))
_USBDEVFS_BULK = _IOC(_IOC_READ | _IOC_WRITE, 'U', 2, ctypes.sizeof(_BulkTransfer))


class _UsbfsTransport:
    ''' Linux: one node for the whole device; claim the interface, bulk by ioctl '''

    def __init__(self, info: dict, timeout_ms: int):
        import fcntl
        self._fcntl = fcntl
        self.info, self.timeout = info, timeout_ms
        self.fd = os.open(info['node'], os.O_RDWR)
        try:
            fcntl.ioctl(self.fd, _USBDEVFS_CLAIMINTERFACE, ctypes.c_uint(info['iface']))
        except OSError as e:
            os.close(self.fd)
            raise CcidError(f'cannot claim CCID interface (pcscd holding it?): {e}')

    def _bulk(self, ep, data=None, length=0):
        if data is not None:
            buf, n = ctypes.create_string_buffer(bytes(data), len(data)), len(data)
        else:
            buf, n = ctypes.create_string_buffer(length), length
        bt = _BulkTransfer(ep=ep, len=n, timeout=self.timeout,
                           data=ctypes.cast(buf, ctypes.c_void_p))
        n = self._fcntl.ioctl(self.fd, _USBDEVFS_BULK, bt)
        return buf.raw[:n]

    def write(self, data: bytes):
        self._bulk(self.info['ep_out'], data)

    def read(self, maxlen: int) -> bytes:
        try:
            return self._bulk(self.info['ep_in'], length=maxlen)
        except OSError as e:
            if e.errno == errno.ETIMEDOUT:   # same story as an all-ZLP read
                raise CcidNoResponse('reader did not answer within the timeout')
            raise

    def close(self):
        try:
            self._fcntl.ioctl(self.fd, _USBDEVFS_RELEASEINTERFACE,
                              ctypes.c_uint(self.info['iface']))
        except OSError:
            pass
        finally:
            os.close(self.fd)


# --- FreeBSD transport: ugen(4) ----------------------------------------------
#
# FreeBSD encodes ioctls differently from Linux: a 13-bit size field, and the
# direction bits live in the top three bits (sys/sys/ioccom.h). Getting the size
# wrong does not fail cleanly - it names a DIFFERENT ioctl - so every number
# below is derived from the real struct, not hardcoded.

_FBSD_IOCPARM_MASK = (1 << 13) - 1
_FBSD_IOC_OUT, _FBSD_IOC_IN = 0x40000000, 0x80000000
_FBSD_IOC_INOUT = _FBSD_IOC_IN | _FBSD_IOC_OUT


def _FIOC(direction, group, nr, size):
    return direction | ((size & _FBSD_IOCPARM_MASK) << 16) | (ord(group) << 8) | nr


class _UsbGenDescriptor(ctypes.Structure):
    ''' struct usb_gen_descriptor (sys/dev/usb/usb_ioctl.h) '''

    _fields_ = [
        ('ugd_data', ctypes.c_void_p),
        ('ugd_lang_id', ctypes.c_uint16), ('ugd_maxlen', ctypes.c_uint16),
        ('ugd_actlen', ctypes.c_uint16), ('ugd_offset', ctypes.c_uint16),
        ('ugd_config_index', ctypes.c_uint8), ('ugd_string_index', ctypes.c_uint8),
        ('ugd_iface_index', ctypes.c_uint8), ('ugd_altif_index', ctypes.c_uint8),
        ('ugd_endpt_index', ctypes.c_uint8), ('ugd_report_type', ctypes.c_uint8),
        ('reserved', ctypes.c_uint8 * 8),
    ]


_USB_UNCONFIG_INDEX = 0xFF               # "the current config" (usb_generic.c)
_USB_DEVICE_DESC_LEN = 18                # the standard USB device descriptor

_USB_GET_DEVICE_DESC = _FIOC(_FBSD_IOC_OUT, 'U', 105, _USB_DEVICE_DESC_LEN)
_USB_GET_FULL_DESC = _FIOC(_FBSD_IOC_INOUT, 'U', 109, ctypes.sizeof(_UsbGenDescriptor))
_USB_SET_RX_SHORT_XFER = _FIOC(_FBSD_IOC_IN, 'U', 113, ctypes.sizeof(ctypes.c_int))
_USB_SET_RX_TIMEOUT = _FIOC(_FBSD_IOC_IN, 'U', 114, ctypes.sizeof(ctypes.c_int))
_USB_SET_TX_TIMEOUT = _FIOC(_FBSD_IOC_IN, 'U', 137, ctypes.sizeof(ctypes.c_int))


def _ugen_probe(node: str):
    '''
    Descriptors for one ugen control node, or None if it is not a CCID reader.
    Reuses parse_descriptors() - the config blob the kernel hands back has the
    same interface/endpoint/CCID descriptors Linux exposes via sysfs.
    '''

    import fcntl
    fd = os.open(node, os.O_RDONLY)
    try:
        buf = ctypes.create_string_buffer(1024)
        ugd = _UsbGenDescriptor()
        ugd.ugd_data = ctypes.cast(buf, ctypes.c_void_p)
        ugd.ugd_maxlen = ctypes.sizeof(buf)
        ugd.ugd_config_index = _USB_UNCONFIG_INDEX
        fcntl.ioctl(fd, _USB_GET_FULL_DESC, ugd)

        info = parse_descriptors(buf.raw[:ugd.ugd_actlen])
        if info['ccid'] is None or info['ep_in'] is None or info['ep_out'] is None:
            return None

        dd = ctypes.create_string_buffer(_USB_DEVICE_DESC_LEN)
        fcntl.ioctl(fd, _USB_GET_DEVICE_DESC, dd)
        vid, pid = struct.unpack_from('<HH', dd.raw, 8)   # idVendor, idProduct

        info['node'] = node
        info['vid'], info['pid'] = f'{vid:04x}', f'{pid:04x}'
        info['name'] = f'CCID reader {vid:04x}:{pid:04x}'
        info['backend'] = 'ugen'
        return info
    finally:
        os.close(fd)


def _ugen_endpoint_path(node: str, ep_addr: int) -> str:
    '''
    The device node for one endpoint of a ugen device.

    /dev/ugenB.D is a SYMLINK to /dev/usb/B.D.0 (the control endpoint); the data
    endpoints are its siblings, /dev/usb/B.D.E, where E is the endpoint NUMBER -
    the low nibble of bEndpointAddress. (The man page's "/dev/ugenB.D.E" spelling
    does not exist on disk.)

    E must come from the ENUMERATED descriptors, never from what a device asked
    for: a USB device controller is free to reassign addresses. Our own f_ccid
    gadget requests interrupt endpoint 0x83 and is given 0x85 - and FreeBSD duly
    names that node /dev/usb/B.D.5.
    '''

    real = Path(node).resolve()                    # /dev/usb/B.D.0
    bus_dev = real.name.rsplit('.', 1)[0]          # 'B.D'
    return str(real.parent / f'{bus_dev}.{ep_addr & 0x0F}')


class _UgenTransport:
    '''
    FreeBSD: each endpoint is its own device node and bulk I/O is plain
    read()/write(). No interface claim - opening the endpoint node IS the claim,
    so a reader already held by pcscd fails here with EBUSY, exactly as on Linux.

    Direction comes from the open mode, which is what disambiguates a reader that
    uses the same endpoint number for IN and OUT.
    '''

    def __init__(self, info: dict, timeout_ms: int):
        import fcntl
        self.timeout = timeout_ms
        node = info['node']                                  # /dev/ugenB.D
        self._in = os.open(_ugen_endpoint_path(node, info['ep_in']), os.O_RDONLY)
        try:
            self._out = os.open(_ugen_endpoint_path(node, info['ep_out']), os.O_WRONLY)
        except OSError:
            os.close(self._in)
            raise
        # A CCID reply is variable-length. Without SHORT_XFER a read that returns
        # fewer bytes than requested is an error, so every reply would fail.
        timeout = struct.pack('i', timeout_ms)
        fcntl.ioctl(self._in, _USB_SET_RX_SHORT_XFER, struct.pack('i', 1))
        fcntl.ioctl(self._in, _USB_SET_RX_TIMEOUT, timeout)
        fcntl.ioctl(self._out, _USB_SET_TX_TIMEOUT, timeout)

    def write(self, data: bytes):
        os.write(self._out, bytes(data))

    def read(self, maxlen: int) -> bytes:
        '''
        One CCID message. Zero-length reads are skipped, not returned.

        With SHORT_XFER enabled a zero-length USB packet surfaces here as an
        empty read(), and a freshly-opened endpoint intermittently hands us one
        before the first real reply (observed on FreeBSD 15.1: roughly one open
        in three). A ZLP is not a CCID message - the smallest is a 10-byte
        header - so treating it as data made the first exchange fail at random.
        Wait for real bytes instead, bounded by the same timeout the endpoint has.
        '''

        deadline = time.monotonic() + (self.timeout / 1000.0)
        while True:
            data = os.read(self._in, maxlen)
            if data:
                return data
            if time.monotonic() >= deadline:
                raise CcidNoResponse('reader sent only zero-length packets')

    def close(self):
        for fd in (self._in, self._out):
            try:
                os.close(fd)
            except OSError:
                pass


_TRANSPORTS = {'usbfs': _UsbfsTransport, 'ugen': _UgenTransport}


# --- the CCID protocol layer (identical on every OS) --------------------------

class CcidUsb:
    '''
    Low-level CCID over one reader. Handles the 10-byte CCID message header,
    sequence numbers, and the reader's time-extension responses. The raw USB
    access is delegated to a per-OS transport. Not usually used directly - see
    CcidConnection.
    '''

    def __init__(self, info: dict, timeout_ms: int = 5000):
        if not is_apdu_level(info['ccid']['dwFeatures']):
            raise CcidError(
                f"reader {info.get('name', '?')} is {exchange_level(info['ccid']['dwFeatures'])}"
                "-level; only APDU-level readers are supported")
        transport = _TRANSPORTS.get(info.get('backend', 'usbfs'))
        if transport is None:
            raise CcidError(f"no USB transport for backend {info.get('backend')!r}")
        self.info = info
        self.timeout = timeout_ms
        self._max = info['ccid']['dwMaxCCIDMessageLength']
        self.seq = 0
        self._t = transport(info, timeout_ms)

    def close(self):
        self._t.close()

    def _send(self, msg_type, payload=b'', p1=0, p2=0, p3=0):
        self.seq = (self.seq + 1) & 0xFF
        header = struct.pack('<BIBBBBB', msg_type, len(payload), 0, self.seq, p1, p2, p3)
        self._t.write(header + payload)

    def _recv(self):
        '''
        One RDR_to_PC message, waiting out "time extension" replies. Returns
        (payload_bytes, bStatus). Raises CcidError on a failed command.
        '''

        while True:
            raw = self._t.read(self._max)
            if len(raw) < 10:
                raise CcidError(f'short CCID response: {raw.hex()}')
            _mt, dlen, _slot, _seq, status, error, _chain = struct.unpack('<BIBBBBB', raw[:10])
            cmd_status = (status >> 6) & 0x03
            if cmd_status == 2:
                continue                 # reader still working; keep reading
            if cmd_status == 1:
                exc = CcidMute if error == 0xFE else CcidError
                raise exc(f'CCID command failed: bStatus=0x{status:02X} '
                          f'bError=0x{error:02X} ({_ccid_error(error)})')
            return raw[10:10 + dlen], status

    def _exchange(self, msg_type, payload=b'', p1=0, p2=0, p3=0):
        '''
        Send one PC_to_RDR message and read the reply, retrying ONCE if the
        reader says nothing at all.

        Why the retry: an idle USB device gets SUSPENDED, and the first transfer
        after it resumes can be dropped - the request never reaches the reader,
        so nothing ever comes back. Seen reliably on FreeBSD/ugen (the gadget
        logged no traffic at all for the lost message; the next attempt always
        worked). It is a property of USB suspend/resume, not of one OS, so the
        retry lives here in the shared layer rather than in a transport.

        Only a total silence is retried. A reader that answers with a failure
        status is a real error and propagates immediately.
        '''

        last = None
        for _ in range(2):
            self._send(msg_type, payload, p1, p2, p3)
            try:
                return self._recv()
            except CcidNoResponse as e:
                last = e                 # lost to a suspend/resume; send it again
        raise last

    def power_on(self, mute_retries: int = 2, mute_pause: float = 0.15) -> bytes:
        '''
        PC_to_RDR_IccPowerOn -> the card's ATR (bPowerSelect=0: automatic).

        Retries on ICC mute (bError=0xFE). A contact card whose reader powered it
        down while idle answers the first power-on with mute; re-powering wakes
        it - the transient 0xFE seen on the Circle CCR7115 with the IDPrime card.
        This retry is SAFE only because power-on is idempotent: it always drives
        the card to the same reset state. A command APDU is NOT (see xfr - a
        repeated VERIFY burns PIN tries), which is why the retry lives here on the
        power path alone. It mirrors what the official daemon gets for free from
        pcscd, which power-cycles the card on every fresh connect.

        A genuinely empty slot also reports mute, so the retries cost a short,
        bounded wait (mute_retries * mute_pause) before giving up on no card.
        '''

        for attempt in range(mute_retries + 1):
            try:
                atr, _ = self._exchange(_MSG_ICC_POWER_ON, p1=0x00)
                return atr
            except CcidMute:
                if attempt == mute_retries:
                    raise
                time.sleep(mute_pause)

    def power_off(self):
        self._exchange(_MSG_ICC_POWER_OFF)

    def slot_status(self) -> int:
        ''' bStatus byte; low 2 bits: 0 active, 1 inactive, 2 no card '''

        _, status = self._exchange(_MSG_GET_SLOT_STATUS)
        return status

    def xfr(self, apdu: bytes) -> bytes:
        '''
        One PC_to_RDR_XfrBlock: hand the reader a full APDU, get the card's raw
        response (data + SW). No GET RESPONSE handling here.

        Deliberately does NOT use _exchange's retry. Silence is ambiguous: the
        request may never have reached the card, OR the card may have executed it
        and only the REPLY was lost. Re-sending blindly would risk running an
        APDU twice - and a repeated VERIFY would burn two PIN tries, three of
        which brick a QES card. The idempotent control messages are safe to
        retry; a command APDU is not. A caller who knows a given APDU is safe to
        repeat can retry it itself.
        '''

        self._send(_MSG_XFR_BLOCK, payload=bytes(apdu), p1=0x00)
        resp, _ = self._recv()
        return resp


def _ccid_error(code):
    return {0x00: 'no error', 0xFE: 'ICC mute / no card', 0xFB: 'hardware error',
            0xEF: 'command aborted', 0xF4: 'XFR parity error', 0xE0: 'slot busy',
            0xFD: 'XFR overrun'}.get(code, 'unknown')


# --- ISO-7816 GET RESPONSE handling (what pcscd hides for T=0 APDU readers) --

def transmit_iso7816(xfr, apdu: bytes) -> bytes:
    '''
    Send an APDU and resolve T=0 status words, returning data+SW like a PC/SC
    SCardTransmit would: 61 XX -> issue GET RESPONSE and append; 6C XX -> resend
    with the corrected Le. `xfr` is any callable taking/returning raw bytes
    (CcidUsb.xfr, or a fake in tests).
    '''

    resp = xfr(apdu)
    data = b''
    while len(resp) >= 2:
        sw1, sw2 = resp[-2], resp[-1]
        if sw1 == 0x61:                              # more data available
            data += resp[:-2]
            resp = xfr(bytes([0x00, 0xC0, 0x00, 0x00, sw2]))
            continue
        if sw1 == 0x6C:                              # wrong Le; resend with sw2
            resp = xfr(bytes(apdu[:4]) + bytes([sw2]))
            data = b''
            continue
        return data + resp
    return data + resp


# --- the sc_ffi.SmartCardConnection-compatible adapter -----------------------

class CcidConnection:
    '''
    Context manager exposing get_atr / transmit / transaction over direct CCID,
    matching sc_ffi.SmartCardConnection so the BTrustDriver / PKCS#15 stack runs
    over it unchanged. `transmit` returns data+SW and resolves T=0 GET RESPONSE.
    '''

    def __init__(self, reader_index: int = 0):
        self.reader_index = reader_index
        self._ccid = None
        self._atr = None

    def __enter__(self):
        readers = find_ccid_readers()
        if not readers:
            raise CcidError('no direct-CCID reader found (Linux + usbfs only)')
        if self.reader_index >= len(readers):
            raise CcidError(f'reader index {self.reader_index} out of range '
                            f'({len(readers)} found)')
        self._ccid = CcidUsb(readers[self.reader_index])
        try:
            if self._ccid.slot_status() & 0x03 == 2:
                raise CcidError('no card present in the reader')
            self._atr = self._ccid.power_on()
        except Exception:
            self._ccid.close()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._ccid is not None:
            self._ccid.close()

    def get_atr(self) -> bytes:
        return self._atr

    def transmit(self, apdu: bytes) -> bytes:
        return transmit_iso7816(self._ccid.xfr, bytes(apdu))

    def transaction(self):
        ''' usbfs interface-claim already gives exclusive access; no-op lock '''

        return _NullTransaction()


class _NullTransaction:
    def __enter__(self): return self
    def __exit__(self, *exc): return False
