import sys
from ctypes import *

'''
Basic Type Mappings 

The three PC/SC implementations do NOT agree on integer widths

pcsc-lite (Linux/Alpine/FreeBSD): DWORD = unsigned long, LONG = long
    -> 64-bit on LP64, so c_ulong / c_long are correct.

Windows (LLP64): DWORD = 32-bit; C long is also 32 bits here, so c_ulong
    happens to be right too. SCARDCONTEXT is ULONG_PTR -> pointer-sized.

macOS PCSC.framework: EVERYTHING is 32-bit. Apple's headers say
    DWORD = uint32_t, LONG = int32_t, SCARDCONTEXT/SCARDHANDLE = int32_t.
'''

if sys.platform == 'win32':
    SCARDCONTEXT = c_void_p          # ULONG_PTR
    SCARDHANDLE  = c_void_p
    LONG  = c_long                   # 32-bit under LLP64
    DWORD = c_ulong                  # 32-bit under LLP64
    MAX_BUFFER_SIZE_EXTENDED = 65535
elif sys.platform == 'darwin':
    SCARDCONTEXT = c_int32
    SCARDHANDLE  = c_int32
    LONG  = c_int32
    DWORD = c_uint32
    MAX_BUFFER_SIZE_EXTENDED = 65548 # 4 + 3 + (1<<16) + 3 + 2
else:                                # pcsc-lite: Linux, Alpine, FreeBSD
    SCARDCONTEXT = c_long
    SCARDHANDLE  = c_long
    LONG  = c_long
    DWORD = c_ulong
    MAX_BUFFER_SIZE_EXTENDED = 65548

WORD  = c_ushort
BYTE  = c_ubyte

LPSCARDCONTEXT = POINTER(SCARDCONTEXT)
LPSCARDHANDLE  = POINTER(SCARDHANDLE)
LPDWORD        = POINTER(DWORD)
LPBYTE         = POINTER(BYTE)
LPCBYTE        = POINTER(BYTE)
LPCSTR         = c_char_p
LPSTR          = c_char_p

# --- PC/SC Constants ---
SCARD_S_SUCCESS = 0x00000000
SCARD_SCOPE_USER = 0x0000
SCARD_SHARE_SHARED = 0x0002
SCARD_SHARE_EXCLUSIVE = 0x0001
SCARD_PROTOCOL_T0 = 0x0001
SCARD_PROTOCOL_T1 = 0x0002

SCARD_LEAVE_CARD = 0x0000
SCARD_RESET_CARD = 0x0001
SCARD_UNPOWER_CARD = 0x0002

MAX_ATR_SIZE = 33

# --- PC/SC Error Codes ---
SCARD_F_INTERNAL_ERROR      = 0x80100001
SCARD_E_CANCELLED           = 0x80100002
SCARD_F_COMM_ERROR          = 0x80100013 # IPC to the daemon failed (socket there, no answer)
SCARD_E_INVALID_HANDLE      = 0x80100003
SCARD_E_INVALID_PARAMETER   = 0x80100004
SCARD_E_INSUFFICIENT_BUFFER = 0x80100008
SCARD_E_UNKNOWN_READER      = 0x80100009
SCARD_E_TIMEOUT             = 0x8010000A
SCARD_E_SHARING_VIOLATION   = 0x8010000B
SCARD_E_NO_SMARTCARD        = 0x8010000C
SCARD_E_UNKNOWN_CARD        = 0x8010000D
SCARD_E_PROTO_MISMATCH      = 0x8010000F
SCARD_E_NOT_READY           = 0x80100010
SCARD_E_INVALID_VALUE       = 0x80100011
SCARD_E_READER_UNAVAILABLE  = 0x80100017
SCARD_E_NO_SERVICE          = 0x8010001D
SCARD_E_SERVICE_STOPPED     = 0x8010001E
SCARD_W_REMOVED_CARD        = 0x80100069
SCARD_W_SECURITY_VIOLATION  = 0x8010006A
SCARD_W_WRONG_CHV           = 0x8010006B # Bad PIN
SCARD_W_CHV_BLOCKED         = 0x8010006C # PIN Blocked

# --- PC/SC Reader States (for SCardGetStatusChange) ---
SCARD_STATE_UNAWARE         = 0x0000
SCARD_STATE_IGNORE          = 0x0001
SCARD_STATE_CHANGED         = 0x0002
SCARD_STATE_UNKNOWN         = 0x0004
SCARD_STATE_UNAVAILABLE     = 0x0008
SCARD_STATE_EMPTY           = 0x0010
SCARD_STATE_PRESENT         = 0x0020
SCARD_STATE_ATRMATCH        = 0x0040
SCARD_STATE_EXCLUSIVE       = 0x0080
SCARD_STATE_INUSE           = 0x0100
SCARD_STATE_MUTE            = 0x0200
SCARD_STATE_UNPOWERED       = 0x0400


# --- C-Structures ---

class SCARD_IO_REQUEST(Structure):
    ''' Maps to the C struct required for SCardTransmit '''

    _fields_ = [
        ('dwProtocol', DWORD),
        ('cbPciLength', DWORD)
    ]


class SCARD_READERSTATE(Structure):
    ''' Maps to the C struct required for SCardGetStatusChange '''

    _fields_ = [
        ('szReader', LPCSTR),
        ('pvUserData', c_void_p),
        ('dwCurrentState', DWORD),
        ('dwEventState', DWORD),
        ('cbAtr', DWORD),
        ('rgbAtr', BYTE * MAX_ATR_SIZE)
    ]


# --- Lazy PC/SC library binding ---

# The native library is loaded and bound the first time pcsc() is called

_pcsc = None


class _PCSC:
    ''' Holds the bound SCard* functions and the global PCI request blocks '''
    pass


def pcsc() -> _PCSC:
    ''' Loads winscard/pcsclite once and returns the bound function namespace '''

    global _pcsc
    if _pcsc is not None:
        return _pcsc

    if sys.platform == 'win32':
        # Windows uses __stdcall and the 'A' (ASCII) string-function variants
        lib = WinDLL('winscard.dll')
        list_fn, connect_fn, status_fn = 'SCardListReadersA', 'SCardConnectA', 'SCardStatusA'
    elif sys.platform == 'darwin':
        lib = CDLL('/System/Library/Frameworks/PCSC.framework/PCSC')
        list_fn, connect_fn, status_fn = 'SCardListReaders', 'SCardConnect', 'SCardStatus'
    elif sys.platform.startswith('linux') or sys.platform.startswith('freebsd'):
        # Linux, Alpine, and FreeBSD use the open-source pcsclite daemon
        try:
            lib = CDLL('libpcsclite.so.1')
        except OSError:
            lib = CDLL('libpcsclite.so')
        list_fn, connect_fn, status_fn = 'SCardListReaders', 'SCardConnect', 'SCardStatus'
    else:
        raise NotImplementedError(f'Platform {sys.platform} not supported')

    p = _PCSC()
    p.SCardEstablishContext_fn = lib.SCardEstablishContext
    p.SCardListReaders_fn      = getattr(lib, list_fn)
    p.SCardConnect_fn          = getattr(lib, connect_fn)
    p.SCardStatus_fn           = getattr(lib, status_fn)
    p.SCardTransmit_fn         = lib.SCardTransmit
    p.SCardDisconnect_fn       = lib.SCardDisconnect
    p.SCardReleaseContext_fn   = lib.SCardReleaseContext
    p.SCardBeginTransaction_fn = lib.SCardBeginTransaction
    p.SCardEndTransaction_fn   = lib.SCardEndTransaction

    # Argument and return types (guards against 64-bit pointer truncation)
    p.SCardEstablishContext_fn.argtypes = [DWORD, c_void_p, c_void_p, LPSCARDCONTEXT]
    p.SCardEstablishContext_fn.restype = LONG
    p.SCardListReaders_fn.argtypes = [SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD]
    p.SCardListReaders_fn.restype = LONG
    p.SCardConnect_fn.argtypes = [SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD]
    p.SCardConnect_fn.restype = LONG
    p.SCardTransmit_fn.argtypes = [SCARDHANDLE, POINTER(SCARD_IO_REQUEST), LPCBYTE, DWORD, POINTER(SCARD_IO_REQUEST), LPBYTE, LPDWORD]
    p.SCardTransmit_fn.restype = LONG
    p.SCardDisconnect_fn.argtypes = [SCARDHANDLE, DWORD]
    p.SCardDisconnect_fn.restype = LONG
    p.SCardReleaseContext_fn.argtypes = [SCARDCONTEXT]
    p.SCardReleaseContext_fn.restype = LONG
    p.SCardBeginTransaction_fn.argtypes = [SCARDHANDLE]
    p.SCardBeginTransaction_fn.restype = LONG
    p.SCardEndTransaction_fn.argtypes = [SCARDHANDLE, DWORD]
    p.SCardEndTransaction_fn.restype = LONG
    p.SCardStatus_fn.argtypes = [SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD]
    p.SCardStatus_fn.restype = LONG

    # Global PCI T0/T1 request blocks (required for SCardTransmit)
    p.g_rgSCardT0Pci = SCARD_IO_REQUEST.in_dll(lib, 'g_rgSCardT0Pci')
    p.g_rgSCardT1Pci = SCARD_IO_REQUEST.in_dll(lib, 'g_rgSCardT1Pci')

    _pcsc = p
    return _pcsc
