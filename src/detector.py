import os, sys, ctypes

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])


#  BISS ATR Mappings 

ATR_MAPPINGS = {
    # GEMALTO
    '3B7F96000080318065B0850300EF120FFE829000': 'GEMALTO',
    '3BFF9600008131804380318065B0850300EF120FFE82900066': 'GEMALTO',
    '3B9F958131FE9F006646530523002571DF000000000005': 'GEMALTO',
    '3B7F96000080318065B085050039120FFE829000': 'GEMALTO',
    '3B7F96000080318065B0855956FB120FFE829000': 'GEMALTO',
    '3BFE9600008031FE4380738400E065B0850400FB8290004E': 'GEMALTO',
    '3B7F96000080318065B085595606120FFE829000': 'GEMALTO',
    
    # BIT4ID
    '3BFF1800008131FE55006B02090603010101434E5310318067': 'BIT4ID',
    '3BFF1800008131FE55006B02090403010101434E5310318065': 'BIT4ID',
    '3BFF1800FF8131FE55006B02090303011101434E531131808C': 'BIT4ID',
    
    # CRYPTOVISION
    '3BF81300008131FE454A434F5076323431B7': 'CRYPTOVISION',
    
    # SIEMENS
    '3BF2180002C10A31FE58C80874': 'SIEMENS',
    
    # IDEMIA
    '3BDD96008131FE4580F9A00000007701080007900070': 'IDEMIA',
    
    # MICROSOFT_VMWARE
    '3B8D0180FBA000000397425446590401CF': 'MICROSOFT_VMWARE',
}

# --- Pure Python PC/SC Wrapper ---

DWORD = ctypes.c_uint32
LPDWORD = ctypes.POINTER(DWORD)

def _get_pcsc_bindings():
    ''' Dynamically loads the correct native PC/SC library based on OS '''

    try:
        if sys.platform == 'win32':
            return ctypes.windll.winscard, ctypes.c_void_p, ctypes.c_void_p, True
        else:
            # POSIX architectures use 32-bit integers for PCSC handles
            ctx_type = ctypes.c_int32
            handle_type = ctypes.c_int32
            
            if sys.platform == 'darwin':
                lib = ctypes.cdll.LoadLibrary('/System/Library/Frameworks/PCSC.framework/PCSC')
                return lib, ctx_type, handle_type, False
            else:
                import ctypes.util
                lib_path = ctypes.util.find_library('pcsclite')
                if not lib_path: return None, ctx_type, handle_type, False
                return ctypes.cdll.LoadLibrary(lib_path), ctx_type, handle_type, False
    except Exception:
        return None, None, None, False


def get_connected_atrs() -> list[str]:
    ''' Query the OS native smart card manager and returns all active ATRs '''

    pcsc, SCARDCONTEXT, SCARDHANDLE, is_win = _get_pcsc_bindings()
    if not pcsc:
        return []

    # Map C function signatures
    SCardEstablishContext = pcsc.SCardEstablishContext
    SCardEstablishContext.argtypes = [DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(SCARDCONTEXT)]
    
    SCardListReaders = pcsc.SCardListReadersA if is_win else pcsc.SCardListReaders
    SCardListReaders.argtypes = [SCARDCONTEXT, ctypes.c_char_p, ctypes.c_char_p, LPDWORD]
    
    SCardConnect = pcsc.SCardConnectA if is_win else pcsc.SCardConnect
    SCardConnect.argtypes = [SCARDCONTEXT, ctypes.c_char_p, DWORD, DWORD, ctypes.POINTER(SCARDHANDLE), LPDWORD]
    
    SCardStatus = pcsc.SCardStatusA if is_win else pcsc.SCardStatus
    SCardStatus.argtypes = [SCARDHANDLE, ctypes.c_char_p, LPDWORD, LPDWORD, LPDWORD, ctypes.POINTER(ctypes.c_ubyte), LPDWORD]
    
    SCardDisconnect = pcsc.SCardDisconnect
    SCardDisconnect.argtypes = [SCARDHANDLE, DWORD]
    
    SCardReleaseContext = pcsc.SCardReleaseContext
    SCardReleaseContext.argtypes = [SCARDCONTEXT]

    atrs = []
    context = SCARDCONTEXT()
    
    # SCARD_SCOPE_SYSTEM = 2
    if SCardEstablishContext(2, None, None, ctypes.byref(context)) != 0:
        return atrs

    try:
        cchReaders = DWORD(0)
        # Fetch buffer size
        if SCardListReaders(context, None, None, ctypes.byref(cchReaders)) == 0:
            readers_buf = ctypes.create_string_buffer(cchReaders.value)
            # Fetch actual readers
            if SCardListReaders(context, None, readers_buf, ctypes.byref(cchReaders)) == 0:
                readers = [r for r in readers_buf.raw.split(b'\x00') if r]
                
                for reader in readers:
                    card = SCARDHANDLE()
                    active_proto = DWORD()
                    # SCARD_SHARE_SHARED = 2, SCARD_PROTOCOL_T0 | T1 = 3
                    if SCardConnect(context, reader, 2, 3, ctypes.byref(card), ctypes.byref(active_proto)) == 0:
                        try:
                            # Pre-allocate buffers for SCardStatus to avoid NULL pointer panics
                            reader_name_buf = ctypes.create_string_buffer(256)
                            reader_name_len = DWORD(256)
                            state = DWORD()
                            protocol = DWORD()
                            atr_len = DWORD(33)
                            atr_buf = (ctypes.c_ubyte * 33)()
                            
                            if SCardStatus(card, reader_name_buf, ctypes.byref(reader_name_len), 
                                           ctypes.byref(state), ctypes.byref(protocol), 
                                           atr_buf, ctypes.byref(atr_len)) == 0:
                                atr_hex = bytes(atr_buf[:atr_len.value]).hex().upper()
                                atrs.append(atr_hex)
                        finally:
                            # SCARD_LEAVE_CARD = 0
                            SCardDisconnect(card, 0)
    finally:
        SCardReleaseContext(context)

    return atrs


def identify_provider(atr: str) -> str:
    ''' Match an ATR to a known hardware provider '''

    return ATR_MAPPINGS.get(atr.upper())


def get_library_path(provider: str) -> str:
    ''' Resolve the PKCS#11 library path based on the Provider and the OS '''
    
    assets_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets')
    
    if sys.platform == 'win32':
        if provider == 'GEMALTO':
            if os.path.exists('C:/Windows/System32/eTPKCS11.dll'): return 'C:/Windows/System32/eTPKCS11.dll'
            return os.path.join(assets_dir, 'IDPrimePKCS11_940.dll')
        elif provider == 'BIT4ID':
            if os.path.exists('C:/WINDOWS/system32/bit4ipki.dll'): return 'C:/WINDOWS/system32/bit4ipki.dll'
        elif provider == 'IDEMIA':
            if os.path.exists('c:/Windows/System32/OcsPKCS11Wrapper.dll'): return 'c:/Windows/System32/OcsPKCS11Wrapper.dll'
        elif provider in ('CRYPTOVISION', 'SIEMENS'):
            return os.path.join(assets_dir, 'cvP11.dll')
            
    elif sys.platform == 'darwin':
        if provider == 'GEMALTO':
            for p in ['/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib', '/Library/Gemalto/libidprimepkcs11.dylib']:
                if os.path.exists(p): return p
        elif provider in ('CRYPTOVISION', 'SIEMENS'):
            if os.path.exists('/Library/cv cryptovision/libcvP11.dylib'): return '/Library/cv cryptovision/libcvP11.dylib'
        elif provider == 'BIT4ID':
            if os.path.exists('/Library/bit4id/pkcs11/libbit4ipki.dylib'): return '/Library/bit4id/pkcs11/libbit4ipki.dylib'
        elif provider == 'IDEMIA':
            if os.path.exists('/Library/AWP/lib/libOcsCryptoki.dylib'): return '/Library/AWP/lib/libOcsCryptoki.dylib'
            
    else: # Linux
        if provider == 'GEMALTO':
            for p in ['/lib/libIDPrimePKCS11.so', '/usr/lib/libIDPrimePKCS11.so', '/usr/lib64/libIDPrimePKCS11.so', 
                      '/lib/libIDPrimePKCS11.so.10', '/usr/lib/libIDPrimePKCS11.so.10', '/usr/lib64/libIDPrimePKCS11.so.10']:
                if os.path.exists(p): return p
        elif provider == 'BIT4ID':
            for p in ['/usr/lib/libbit4ipki.so', '/usr/lib64/libbit4ipki.so']:
                if os.path.exists(p): return p
        elif provider in ('CRYPTOVISION', 'SIEMENS'):
            for p in [os.path.join(assets_dir, 'libcvP11.so'), '/usr/lib/libcvP11.so']:
                if os.path.exists(p): return p

    return None


def auto_detect_library() -> str:
    ''' Detect the active smart card and return its library path '''
    
    for atr in get_connected_atrs():
        provider = identify_provider(atr)
        if provider:
            lib_path = get_library_path(provider)
            if lib_path:
                return lib_path
    return None