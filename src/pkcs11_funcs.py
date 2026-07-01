import sys
from ctypes import CFUNCTYPE, POINTER, c_void_p, Structure

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from pkcs11_types import (
    CK_RV, CK_ULONG, CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE, CK_ATTRIBUTE, CK_OBJECT_HANDLE,
    CK_MECHANISM, CK_VERSION, CK_SLOT_ID, CK_BBOOL, CK_TOKEN_INFO, CK_UTF8CHAR
)


## --  Function Signatures
C_Initialize_t = CFUNCTYPE(CK_RV, c_void_p)
C_Finalize_t = CFUNCTYPE(CK_RV, c_void_p)
C_GetSlotList_t = CFUNCTYPE(CK_RV, CK_BBOOL, POINTER(CK_SLOT_ID), POINTER(CK_ULONG))
C_GetTokenInfo_t = CFUNCTYPE(CK_RV, CK_SLOT_ID, POINTER(CK_TOKEN_INFO))
C_InitPIN_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_UTF8CHAR), CK_ULONG)
C_SetPIN_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_UTF8CHAR), CK_ULONG, POINTER(CK_UTF8CHAR), CK_ULONG)
C_OpenSession_t = CFUNCTYPE(CK_RV, CK_ULONG, CK_ULONG, c_void_p, c_void_p, POINTER(CK_SESSION_HANDLE))
C_CloseSession_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
C_Login_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, POINTER(CK_BYTE), CK_ULONG)
C_Logout_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
C_CreateObject_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_ATTRIBUTE), CK_ULONG, POINTER(CK_OBJECT_HANDLE))
C_DestroyObject_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
C_GetAttributeValue_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, POINTER(CK_ATTRIBUTE), CK_ULONG)
C_FindObjectsInit_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_ATTRIBUTE), CK_ULONG)
C_FindObjects_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_OBJECT_HANDLE), CK_ULONG, POINTER(CK_ULONG))
C_FindObjectsFinal_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
C_SignInit_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), CK_OBJECT_HANDLE)
C_Sign_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_BYTE), CK_ULONG, POINTER(CK_BYTE), POINTER(CK_ULONG))
C_GenerateKeyPair_t = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_MECHANISM), POINTER(CK_ATTRIBUTE), CK_ULONG, POINTER(CK_ATTRIBUTE), CK_ULONG, POINTER(CK_OBJECT_HANDLE), POINTER(CK_OBJECT_HANDLE))


## -- The strictly memory-aligned struct
class CK_FUNCTION_LIST(Structure):
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = [
        ('version', CK_VERSION),
        ('C_Initialize', C_Initialize_t),
        ('C_Finalize', C_Finalize_t),
        ('C_GetInfo', c_void_p),
        ('C_GetFunctionList', c_void_p),
        ('C_GetSlotList', C_GetSlotList_t),
        ('C_GetSlotInfo', c_void_p),
        ('C_GetTokenInfo', C_GetTokenInfo_t),
        ('C_GetMechanismList', c_void_p),
        ('C_GetMechanismInfo', c_void_p),
        ('C_InitToken', c_void_p),
        ('C_InitPIN', C_InitPIN_t),
        ('C_SetPIN', C_SetPIN_t),
        ('C_OpenSession', C_OpenSession_t),
        ('C_CloseSession', C_CloseSession_t),
        ('C_CloseAllSessions', c_void_p),
        ('C_GetSessionInfo', c_void_p),
        ('C_GetOperationState', c_void_p),
        ('C_SetOperationState', c_void_p),
        ('C_Login', C_Login_t),
        ('C_Logout', C_Logout_t),
        ('C_CreateObject', C_CreateObject_t),
        ('C_CopyObject', c_void_p),
        ('C_DestroyObject', C_DestroyObject_t),
        ('C_GetObjectSize', c_void_p),
        ('C_GetAttributeValue', C_GetAttributeValue_t), 
        ('C_SetAttributeValue', c_void_p),
        ('C_FindObjectsInit', C_FindObjectsInit_t),
        ('C_FindObjects', C_FindObjects_t),
        ('C_FindObjectsFinal', C_FindObjectsFinal_t),
        ('C_EncryptInit', c_void_p),
        ('C_Encrypt', c_void_p),
        ('C_EncryptUpdate', c_void_p),
        ('C_EncryptFinal', c_void_p),
        ('C_DecryptInit', c_void_p),
        ('C_Decrypt', c_void_p),
        ('C_DecryptUpdate', c_void_p),
        ('C_DecryptFinal', c_void_p),
        ('C_DigestInit', c_void_p),
        ('C_Digest', c_void_p),
        ('C_DigestUpdate', c_void_p),
        ('C_DigestKey', c_void_p),
        ('C_DigestFinal', c_void_p),
        ('C_SignInit', C_SignInit_t),
        ('C_Sign', C_Sign_t),
        ('C_SignUpdate', c_void_p),
        ('C_SignFinal', c_void_p),
        ('C_SignRecoverInit', c_void_p),
        ('C_SignRecover', c_void_p),
        ('C_VerifyInit', c_void_p),
        ('C_Verify', c_void_p),
        ('C_VerifyUpdate', c_void_p),
        ('C_VerifyFinal', c_void_p),
        ('C_VerifyRecoverInit', c_void_p),
        ('C_VerifyRecover', c_void_p),
        ('C_DigestEncryptUpdate', c_void_p),
        ('C_DecryptDigestUpdate', c_void_p),
        ('C_SignEncryptUpdate', c_void_p),
        ('C_DecryptVerifyUpdate', c_void_p),
        ('C_GenerateKey', c_void_p),
        ('C_GenerateKeyPair', C_GenerateKeyPair_t),
    ]