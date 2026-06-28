import sys, hashlib, ctypes
from ctypes import (
    POINTER, c_void_p, c_ubyte, byref, Structure, cast, string_at, c_wchar_p, 
)

if (IS_WINDOWS := sys.platform == 'win32'):
    from ctypes import wintypes, GetLastError
    crypt32 = ctypes.windll.crypt32
    ncrypt = ctypes.windll.ncrypt
    
    # Set proper 64-bit pointer return types and argument types to prevent truncation crashes
    crypt32.CertOpenStore.restype = c_void_p
    crypt32.CertOpenStore.argtypes = [c_void_p, wintypes.DWORD, c_void_p, wintypes.DWORD, c_wchar_p]
    
    crypt32.CertEnumCertificatesInStore.restype = c_void_p
    crypt32.CertEnumCertificatesInStore.argtypes = [c_void_p, c_void_p]
    
    crypt32.CertDuplicateCertificateContext.restype = c_void_p
    crypt32.CertDuplicateCertificateContext.argtypes = [c_void_p]
    
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
    crypt32.CertFreeCertificateContext.argtypes = [c_void_p]
    
    crypt32.CertCloseStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [c_void_p, wintypes.DWORD]
    
    crypt32.CryptAcquireCertificatePrivateKey.restype = wintypes.BOOL
    crypt32.CryptAcquireCertificatePrivateKey.argtypes = [
        c_void_p, wintypes.DWORD, c_void_p, POINTER(c_void_p), POINTER(wintypes.DWORD), POINTER(wintypes.BOOL)
    ]
    
    ncrypt.NCryptSetProperty.restype = wintypes.DWORD
    ncrypt.NCryptSetProperty.argtypes = [c_void_p, c_wchar_p, c_void_p, wintypes.DWORD, wintypes.DWORD]
    
    ncrypt.NCryptSignHash.restype = wintypes.DWORD
    ncrypt.NCryptSignHash.argtypes = [
        c_void_p, c_void_p, c_void_p, wintypes.DWORD, c_void_p, wintypes.DWORD, POINTER(wintypes.DWORD), wintypes.DWORD
    ]
    
    ncrypt.NCryptFreeObject.restype = wintypes.DWORD
    ncrypt.NCryptFreeObject.argtypes = [c_void_p]
else:
    # Dummy definitions to allow the rest of the file to parse safely on Linux CI
    class wintypes:
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int
    def GetLastError(): return 0

# --- MSCAPI Constants ---
CERT_STORE_PROV_SYSTEM = 10
CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16
CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000
CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF

# NCrypt Constants
BCRYPT_PAD_PKCS1 = 2
NCRYPT_PIN_PROPERTY = "SmartCardPin"

# --- C-Structs ---
class CERT_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", c_void_p),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", c_void_p),
        ("hCertStore", c_void_p),
    ]

class BCRYPT_PKCS1_PADDING_INFO(Structure):
    # Using c_wchar_p automatically handles UTF-16LE encoding for Windows APIs
    _fields_ = [("pszAlgId", c_wchar_p)] 


def get_windows_certificates() -> list[dict]:
    ''' Queries the Windows Certificate Store for Smart Card certificates '''
    if not IS_WINDOWS:
        return []

    certs = []
    # c_wchar_p is required for Windows Unicode API variants
    hStore = crypt32.CertOpenStore(
        CERT_STORE_PROV_SYSTEM, 0, None, CERT_SYSTEM_STORE_CURRENT_USER, c_wchar_p("MY")
    )
    if not hStore:
        raise Exception("Failed to open Windows Certificate Store")

    pCertCtx = crypt32.CertEnumCertificatesInStore(hStore, None)
    while pCertCtx:
        cert_ctx = cast(pCertCtx, POINTER(CERT_CONTEXT)).contents
        der_data = string_at(cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded)
        
        # CertEnumCertificatesInStore frees the context on the next loop.
        # We duplicate the context to safely keep a pointer to it in Python.
        dup_ctx = crypt32.CertDuplicateCertificateContext(pCertCtx)
        
        certs.append({
            'der': der_data,
            'windows_ctx': dup_ctx 
        })
        
        pCertCtx = crypt32.CertEnumCertificatesInStore(hStore, pCertCtx)

    crypt32.CertCloseStore(hStore, 0)
    return certs


def free_windows_certificate(cert_ctx_pointer):
    ''' Prevents memory leaks by freeing the duplicated certificate context '''
    if IS_WINDOWS and cert_ctx_pointer:
        crypt32.CertFreeCertificateContext(c_void_p(cert_ctx_pointer))


def sign_payload_windows(cert_ctx_pointer, payload: bytes, pin: str = None, hash_alg: str = "SHA256") -> bytes:
    ''' Native Windows Smart Card Signing (CNG) '''
    if not IS_WINDOWS:
        raise Exception("Windows native signing is not supported on this OS")
        
    hCryptProvOrNCryptKey = c_void_p()
    dwKeySpec = wintypes.DWORD()
    pfCallerFreeProv = wintypes.BOOL()

    # Ask Windows to find the Smart Card Private Key associated with this certificate
    res = crypt32.CryptAcquireCertificatePrivateKey(
        c_void_p(cert_ctx_pointer),
        CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        None,
        byref(hCryptProvOrNCryptKey),
        byref(dwKeySpec),
        byref(pfCallerFreeProv)
    )
    
    if not res:
        raise Exception(f"Failed to acquire private key. Error: {GetLastError()}")

    # dwKeySpec == 0xFFFFFFFF means it's an NCrypt (CNG) key
    if dwKeySpec.value != CERT_NCRYPT_KEY_SPEC:
        if pfCallerFreeProv.value:
            crypt32.CryptReleaseContext(hCryptProvOrNCryptKey, 0)
        raise Exception("Legacy CSP keys are not supported. Please use a modern CNG Smart Card.")

    try:
        # Inject the PIN silently. (If omitted, Windows prompts the user automatically)
        if pin:
            pin_utf16 = pin.encode('utf-16le') + b'\x00\x00'
            status = ncrypt.NCryptSetProperty(
                hCryptProvOrNCryptKey, 
                c_wchar_p(NCRYPT_PIN_PROPERTY), 
                pin_utf16, 
                len(pin_utf16), 
                0
            )
            if status != 0:
                raise Exception(f"Failed to set PIN on CNG key handle: {hex(status & 0xFFFFFFFF)}")

        # Hash the payload natively in Python
        hash_alg_upper = hash_alg.upper()
        if hash_alg_upper == "SHA256":
            digest = hashlib.sha256(payload).digest()
        elif hash_alg_upper == "SHA384":
            digest = hashlib.sha384(payload).digest()
        elif hash_alg_upper == "SHA512":
            digest = hashlib.sha512(payload).digest()
        else:
            raise ValueError(f"Unsupported Hash Algorithm: {hash_alg}")

        # Prepare Padding Info using Python's c_wchar_p to handle strings
        pad_info = BCRYPT_PKCS1_PADDING_INFO()
        pad_info.pszAlgId = hash_alg_upper

        cbSignature = wintypes.DWORD(0)
        
        # 1st Call: NCryptSignHash with a NULL buffer to get the required signature size
        status = ncrypt.NCryptSignHash(
            hCryptProvOrNCryptKey,
            byref(pad_info),
            digest,
            len(digest),
            None,
            0,
            byref(cbSignature),
            BCRYPT_PAD_PKCS1
        )
        if status != 0:
            raise Exception(f"NCryptSignHash failed to get size: {hex(status & 0xFFFFFFFF)}")

        # 2nd Call: Allocate buffer and generate the actual mathematical signature
        sig_buffer = (c_ubyte * cbSignature.value)()
        status = ncrypt.NCryptSignHash(
            hCryptProvOrNCryptKey,
            byref(pad_info),
            digest,
            len(digest),
            sig_buffer,
            cbSignature.value,
            byref(cbSignature),
            BCRYPT_PAD_PKCS1
        )
        if status != 0:
            raise Exception(f"NCryptSignHash failed to sign: {hex(status & 0xFFFFFFFF)}")

        return bytes(sig_buffer)

    finally:
        # Always free the hardware handle
        if pfCallerFreeProv.value:
            ncrypt.NCryptFreeObject(hCryptProvOrNCryptKey)