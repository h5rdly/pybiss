from ctypes import (Structure, POINTER, c_ubyte, c_ulong, c_void_p, c_char_p)

# --- Primitive Types ---
CK_ULONG = c_ulong
CK_BYTE = c_ubyte
CK_BBOOL = c_ubyte
CK_RV = c_ulong
CK_SLOT_ID = c_ulong
CK_SESSION_HANDLE = c_ulong
CK_OBJECT_HANDLE = c_ulong
CK_MECHANISM_TYPE = c_ulong
CK_ATTRIBUTE_TYPE = c_ulong
CK_USER_TYPE = c_ulong
CK_UTF8CHAR = c_ubyte
CK_CHAR = c_ubyte

# --- Constants ---
CKR_OK = 0
CKR_GENERAL_ERROR = 0x00000005
CKU_SO = 0    # Security Officer (for PUK unblock)
CKU_USER = 1  # Standard user login
CKF_SERIAL_SESSION = 4
CKF_RW_SESSION = 2 # Required for writing to the card

# Object Classes
CKO_CERTIFICATE = 1
CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3

# Attributes for Object Templates
CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_LABEL = 0x00000003
CKA_CERTIFICATE_TYPE = 0x00000080
CKA_ID = 0x00000102
CKA_VALUE = 0x00000011
CKA_LABEL = 0x00000003   
CKA_SENSITIVE = 0x00000103
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_SIGN = 0x00000108
CKA_VERIFY = 0x0000010A
CKA_MODULUS = 0x00000120
CKA_MODULUS_BITS = 0x00000121
CKA_PUBLIC_EXPONENT = 0x00000122
CKA_EXTRACTABLE = 0x00000162

CKC_X_509 = 0

# Mechanisms
CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_RSA_PKCS = 0x00000001
CKM_SHA256_RSA_PKCS = 0x00000040

# --- Structures ---
class CK_VERSION(Structure):
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [('major', CK_BYTE), ('minor', CK_BYTE)]

class CK_TOKEN_INFO(Structure):
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ('label', CK_UTF8CHAR * 32),
        ('manufacturerID', CK_UTF8CHAR * 32),
        ('model', CK_UTF8CHAR * 16),
        ('serialNumber', CK_CHAR * 16),
        ('flags', CK_ULONG),
        ('ulMaxSessionCount', CK_ULONG),
        ('ulSessionCount', CK_ULONG),
        ('ulMaxRwSessionCount', CK_ULONG),
        ('ulRwSessionCount', CK_ULONG),
        ('ulMaxPinLen', CK_ULONG),
        ('ulMinPinLen', CK_ULONG),
        ('ulTotalPublicMemory', CK_ULONG),
        ('ulFreePublicMemory', CK_ULONG),
        ('ulTotalPrivateMemory', CK_ULONG),
        ('ulFreePrivateMemory', CK_ULONG),
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
        ('utcTime', CK_CHAR * 16),
    ]

class CK_MECHANISM(Structure):
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ('mechanism', CK_MECHANISM_TYPE),
        ('pParameter', c_void_p),
        ('ulParameterLen', CK_ULONG),
    ]

class CK_ATTRIBUTE(Structure):
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ('type', CK_ATTRIBUTE_TYPE),
        ('pValue', c_void_p),
        ('ulValueLen', CK_ULONG),
    ]