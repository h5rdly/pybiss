import os, sys


from . import sc_ffi
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

def get_readers() -> list[str]:
    ''' Names of the connected PC/SC readers (empty if no PC/SC at all) '''

    try:
        hcontext = sc_ffi.establish_context()
    except Exception:
        return []  # library missing, service down, or no reader subsystem

    try:
        return sc_ffi.list_readers(hcontext)
    finally:
        sc_ffi.release_context(hcontext)


def get_connected_atrs(ccid_fallback: bool = False) -> list[str]:
    ''' All active card ATRs (upper hex) '''
    
    if (atrs := _pcsc_atrs()) or not ccid_fallback:
        return atrs
    return _ccid_atrs()


def _pcsc_atrs() -> list[str]:
    ''' ATRs via the OS PC/SC service. [] if PC/SC is unavailable '''

    atrs = []
    try:
        hcontext = sc_ffi.establish_context()
    except Exception:
        return []  # library missing, service down, or no reader subsystem

    try:
        for reader in sc_ffi.list_readers(hcontext):
            try:
                hcard, _ = sc_ffi.connect_card(hcontext, reader)
            except Exception:
                continue  # reader present but empty / in use
            try:
                atrs.append(sc_ffi.get_atr(hcard).hex().upper())
            except Exception:
                pass
            finally:
                sc_ffi.disconnect_card(hcard)
    finally:
        sc_ffi.release_context(hcontext)

    return atrs


def _ccid_atrs() -> list[str]:
    ''' Read ATRs read over USB CCID, no PC/SC daemon '''

    try:
        from . import ccid
    except Exception:
        return []

    atrs = []
    for info in ccid.find_ccid_readers():
        try:
            usb = ccid.CcidUsb(info)
        except Exception:
            continue
        try:
            atrs.append(usb.power_on().hex().upper())
        except Exception:
            pass  # empty slot, mute card, or reader busy
        finally:
            try:
                usb.power_off()
            except Exception:
                pass
            usb.close()

    return atrs


def identify_provider(atr: str) -> str:
    ''' Match an ATR to a known hardware provider '''

    return ATR_MAPPINGS.get(atr.upper())


# PKCS#11 library candidates per (platform, provider) - first existing wins.
_ASSETS = 'assets:'

_PKCS11_CANDIDATES = {
    'win32': {
        'GEMALTO': ['C:/Windows/System32/eTPKCS11.dll'],
        'BIT4ID': ['C:/WINDOWS/system32/bit4ipki.dll'],
        'IDEMIA': ['c:/Windows/System32/OcsPKCS11Wrapper.dll'],
    },
    'darwin': {
        'GEMALTO': ['/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib',
                    '/Library/Gemalto/libidprimepkcs11.dylib'],
        'CRYPTOVISION': ['/Library/cv cryptovision/libcvP11.dylib'],
        'BIT4ID': ['/Library/bit4id/pkcs11/libbit4ipki.dylib'],
        'IDEMIA': ['/Library/AWP/lib/libOcsCryptoki.dylib'],
    },
    'linux': {
        'GEMALTO': ['/lib/libIDPrimePKCS11.so', '/usr/lib/libIDPrimePKCS11.so', '/usr/lib64/libIDPrimePKCS11.so',
                    '/lib/libIDPrimePKCS11.so.10', '/usr/lib/libIDPrimePKCS11.so.10', '/usr/lib64/libIDPrimePKCS11.so.10'],
        'BIT4ID': ['/usr/lib/libbit4ipki.so', '/usr/lib64/libbit4ipki.so'],
        'CRYPTOVISION': [_ASSETS + 'libcvP11.so', '/usr/lib/libcvP11.so'],
    },
}

# Bundled fallbacks returned even when not (yet) on disk - the Windows builds
# ship these in assets
_PKCS11_BUNDLED = {
    'win32': {
        'GEMALTO': 'IDPrimePKCS11_940.dll',
        'CRYPTOVISION': 'cvP11.dll',
    },
}


def get_library_path(provider: str) -> str:
    ''' Resolve the PKCS#11 library path for a provider from the OS candidate table '''

    assets_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets')
    platform = sys.platform if sys.platform in ('win32', 'darwin') else 'linux'
    if provider == 'SIEMENS':
        provider = 'CRYPTOVISION'

    for path in _PKCS11_CANDIDATES.get(platform, {}).get(provider, []):
        if path.startswith(_ASSETS):
            path = os.path.join(assets_dir, path[len(_ASSETS):])
        if os.path.exists(path):
            return path

    bundled = _PKCS11_BUNDLED.get(platform, {}).get(provider)
    return os.path.join(assets_dir, bundled) if bundled else None


def auto_detect_library() -> str:
    ''' Detect the active smart card and return its library path '''
    
    for atr in get_connected_atrs():
        provider = identify_provider(atr)
        if provider:
            lib_path = get_library_path(provider)
            if lib_path:
                return lib_path
    return None