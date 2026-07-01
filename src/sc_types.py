import sys
from ctypes import *


# --- Basic Type Mappings ---
if sys.platform == 'win32':
    SCARDCONTEXT = c_void_p
    SCARDHANDLE  = c_void_p
    MAX_BUFFER_SIZE_EXTENDED = 65535
else:
    SCARDCONTEXT = c_long
    SCARDHANDLE  = c_long
    MAX_BUFFER_SIZE_EXTENDED = 65548 # 4 + 3 + (1<<16) + 3 + 2

LONG  = c_long
DWORD = c_ulong
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


# --- Load the OS-specific library (Import-Safe) ---

SCardEstablishContext_fn = None
g_rgSCardT0Pci = None
g_rgSCardT1Pci = None

if sys.platform == 'win32':
    # Windows uses __stdcall calling convention
    scard_lib = WinDLL('winscard.dll')
    
    # Map the 'A' (ASCII) variants of Windows string functions
    SCardEstablishContext_fn = scard_lib.SCardEstablishContext
    SCardListReaders_fn      = scard_lib.SCardListReadersA
    SCardConnect_fn          = scard_lib.SCardConnectA
    SCardTransmit_fn         = scard_lib.SCardTransmit
    SCardDisconnect_fn       = scard_lib.SCardDisconnect
    SCardReleaseContext_fn   = scard_lib.SCardReleaseContext
    SCardBeginTransaction_fn = scard_lib.SCardBeginTransaction
    SCardEndTransaction_fn   = scard_lib.SCardEndTransaction
    SCardStatus_fn           = scard_lib.SCardStatusA

elif sys.platform == 'darwin':
    # macOS uses the native PCSC Framework
    scard_lib = CDLL('/System/Library/Frameworks/PCSC.framework/PCSC')
    
    SCardEstablishContext_fn = scard_lib.SCardEstablishContext
    SCardListReaders_fn      = scard_lib.SCardListReaders
    SCardConnect_fn          = scard_lib.SCardConnect
    SCardTransmit_fn         = scard_lib.SCardTransmit
    SCardDisconnect_fn       = scard_lib.SCardDisconnect
    SCardReleaseContext_fn   = scard_lib.SCardReleaseContext
    SCardBeginTransaction_fn = scard_lib.SCardBeginTransaction
    SCardEndTransaction_fn   = scard_lib.SCardEndTransaction
    SCardStatus_fn           = scard_lib.SCardStatus

elif sys.platform.startswith('linux') or sys.platform.startswith('freebsd'):
    # Linux, Alpine, and FreeBSD use the standard open-source pcsclite daemon
    try:
        scard_lib = CDLL('libpcsclite.so.1')
    except OSError:
        scard_lib = CDLL('libpcsclite.so')
        
    SCardEstablishContext_fn = scard_lib.SCardEstablishContext
    SCardListReaders_fn      = scard_lib.SCardListReaders
    SCardConnect_fn          = scard_lib.SCardConnect
    SCardTransmit_fn         = scard_lib.SCardTransmit
    SCardDisconnect_fn       = scard_lib.SCardDisconnect
    SCardReleaseContext_fn   = scard_lib.SCardReleaseContext
    SCardBeginTransaction_fn = scard_lib.SCardBeginTransaction
    SCardEndTransaction_fn   = scard_lib.SCardEndTransaction
    SCardStatus_fn           = scard_lib.SCardStatus
    
else:
    raise NotImplementedError(f'Platform {sys.platform} not supported')


# --- Define Argument and Return Types ---
SCardEstablishContext_fn.argtypes = [DWORD, c_void_p, c_void_p, LPSCARDCONTEXT]
SCardEstablishContext_fn.restype = LONG

SCardListReaders_fn.argtypes = [SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD]
SCardListReaders_fn.restype = LONG

SCardConnect_fn.argtypes = [SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD]
SCardConnect_fn.restype = LONG

SCardTransmit_fn.argtypes = [SCARDHANDLE, POINTER(SCARD_IO_REQUEST), LPCBYTE, DWORD, POINTER(SCARD_IO_REQUEST), LPBYTE, LPDWORD]
SCardTransmit_fn.restype = LONG

SCardDisconnect_fn.argtypes = [SCARDHANDLE, DWORD]
SCardDisconnect_fn.restype = LONG

SCardReleaseContext_fn.argtypes = [SCARDCONTEXT]
SCardReleaseContext_fn.restype = LONG

SCardBeginTransaction_fn.argtypes = [SCARDHANDLE]
SCardBeginTransaction_fn.restype = LONG

SCardEndTransaction_fn.argtypes = [SCARDHANDLE, DWORD]
SCardEndTransaction_fn.restype = LONG

SCardStatus_fn.argtypes = [SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD]
SCardStatus_fn.restype = LONG

# Export the global PCI T0/T1 pointers (required for SCardTransmit)
g_rgSCardT0Pci = SCARD_IO_REQUEST.in_dll(scard_lib, 'g_rgSCardT0Pci')
g_rgSCardT1Pci = SCARD_IO_REQUEST.in_dll(scard_lib, 'g_rgSCardT1Pci')
