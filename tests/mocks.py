import sys
from ctypes import (cast, pointer, string_at, memmove, c_ubyte, c_ulong, POINTER, CFUNCTYPE,
    addressof, c_uint32, c_void_p, create_string_buffer, c_int, 
)


sys.path.append(f"{__file__.replace('\\', '/').rsplit('/', 2)[0]}")

from src.pkcs11_types import (
    CKR_OK, CKR_GENERAL_ERROR, CKA_CLASS, CKA_ID, CKA_VALUE, CKO_CERTIFICATE,
    CKO_PRIVATE_KEY, CKA_LABEL 
)
from src.pkcs11_funcs import (
    CK_FUNCTION_LIST, C_SignInit_t,
    C_Initialize_t, C_OpenSession_t, C_Login_t, C_FindObjectsInit_t, 
    C_FindObjects_t, C_FindObjectsFinal_t, C_GetAttributeValue_t, 
    C_Sign_t, C_GetSlotList_t, C_Logout_t, C_CloseSession_t, C_Finalize_t,
    C_GetTokenInfo_t, C_InitPIN_t, C_SetPIN_t, C_CreateObject_t, C_GenerateKeyPair_t
)
import src.mscapi as mscapi


class FakePkcs11Token:
    ''' A stateful fake representing a hardware token '''

    def __init__(self):

        self.is_initialized = False
        self.session_open = False
        self.logged_in = False
        self.rv_get_function_list = CKR_OK
        
        self.find_index = 0
        self.mock_certs = [{'handle': 777, 'id': b'ID_1', 'der': b'DER_DATA'}]
        
        self.f = CK_FUNCTION_LIST()
        
        # keep strong Python references to the CFUNCTYPE wrappers
        self.cb_C_Initialize = C_Initialize_t(self.mock_C_Initialize)
        self.cb_C_OpenSession = C_OpenSession_t(self.mock_C_OpenSession)
        self.cb_C_Login = C_Login_t(self.mock_C_Login)
        self.cb_C_Logout = C_Logout_t(self.mock_C_Logout)
        self.cb_C_CloseSession = C_CloseSession_t(self.mock_C_CloseSession)
        self.cb_C_Finalize = C_Finalize_t(self.mock_C_Finalize)
        
        self.cb_C_FindObjectsInit = C_FindObjectsInit_t(self.mock_C_FindObjectsInit)
        self.cb_C_FindObjects = C_FindObjects_t(self.mock_C_FindObjects)
        self.cb_C_FindObjectsFinal = C_FindObjectsFinal_t(self.mock_C_FindObjectsFinal)
        
        self.cb_C_GetAttributeValue = C_GetAttributeValue_t(self.mock_C_GetAttributeValue)
        self.cb_C_GetSlotList = C_GetSlotList_t(self.mock_C_GetSlotList)
        
        self.cb_C_SignInit = C_SignInit_t(self.mock_C_SignInit)
        self.cb_C_Sign = C_Sign_t(self.mock_C_Sign)

        # New Administration & Issuance wrappers
        self.cb_C_GetTokenInfo = C_GetTokenInfo_t(self.mock_C_GetTokenInfo)
        self.cb_C_SetPIN = C_SetPIN_t(self.mock_C_SetPIN)
        self.cb_C_InitPIN = C_InitPIN_t(self.mock_C_InitPIN)
        self.cb_C_CreateObject = C_CreateObject_t(self.mock_C_CreateObject)
        self.cb_C_GenerateKeyPair = C_GenerateKeyPair_t(self.mock_C_GenerateKeyPair)

        # Now assign the strongly-referenced callbacks to the struct
        self.f.C_Initialize = self.cb_C_Initialize
        self.f.C_OpenSession = self.cb_C_OpenSession
        self.f.C_Login = self.cb_C_Login
        self.f.C_Logout = self.cb_C_Logout
        self.f.C_CloseSession = self.cb_C_CloseSession
        self.f.C_Finalize = self.cb_C_Finalize
        self.f.C_FindObjectsInit = self.cb_C_FindObjectsInit
        self.f.C_FindObjects = self.cb_C_FindObjects
        self.f.C_FindObjectsFinal = self.cb_C_FindObjectsFinal
        self.f.C_GetAttributeValue = self.cb_C_GetAttributeValue
        self.f.C_GetSlotList = self.cb_C_GetSlotList
        self.f.C_SignInit = self.cb_C_SignInit
        self.f.C_Sign = self.cb_C_Sign
        
        self.f.C_GetTokenInfo = self.cb_C_GetTokenInfo
        self.f.C_SetPIN = self.cb_C_SetPIN
        self.f.C_InitPIN = self.cb_C_InitPIN
        self.f.C_CreateObject = self.cb_C_CreateObject
        self.f.C_GenerateKeyPair = self.cb_C_GenerateKeyPair

    def mock_C_SignInit(self, hSession, pMechanism, hKey):
        return CKR_OK


    def mock_C_GetFunctionList(self, func_list_ptr_ptr):
        ''' Simulates extracting the function list, with the ability to force a failure '''
        
        if self.rv_get_function_list != CKR_OK:
            return self.rv_get_function_list
            
        func_list_ptr_ptr[0] = pointer(self.f)
        return CKR_OK

    def mock_C_Initialize(self, pInitArgs):
        self.is_initialized = True
        return CKR_OK

    def mock_C_Logout(self, hSession):
        self.logged_in = False
        return CKR_OK

    def mock_C_CloseSession(self, hSession):
        self.session_open = False
        return CKR_OK
        
    def mock_C_Finalize(self, pReserved):

        self.is_initialized = False
        return CKR_OK

    def mock_C_FindObjectsInit(self, hSession, pTemplate, ulCount):
        self.find_index = 0
        return CKR_OK

    def mock_C_FindObjectsFinal(self, hSession):

        self.find_index = 0
        return CKR_OK

    def mock_C_SetPIN(self, hSession, pOldPin, ulOldLen, pNewPin, ulNewLen):
        return CKR_OK

    def mock_C_InitPIN(self, hSession, pPin, ulPinLen):
        return CKR_OK
        
    def mock_C_OpenSession(self, slotID, flags, pApplication, Notify, phSession):

        if not self.is_initialized:
            return 0x00000190 # CKR_CRYPTOKI_NOT_INITIALIZED
        self.session_open = True
        phSession[0] = 1234  # Give a fake session handle back to Python
        return CKR_OK

    def mock_C_Login(self, hSession, userType, pPin, ulPinLen):

        if not self.session_open:
            return 0x000000B3 # CKR_SESSION_CLOSED
            
        # Simulate checking the PIN
        pin_entered = string_at(pPin, ulPinLen).decode('utf-8')
        if pin_entered != "1234" and userType != 0: # 0 is CKU_SO (PUK)
            return 0x000000A0 # CKR_PIN_INCORRECT
            
        self.logged_in = True
        return CKR_OK


    def mock_C_FindObjects(self, hSession, phObject, ulMaxObjectCount, pulObjectCount):

        try:
            if self.find_index < len(self.mock_certs):
                pulObjectCount[0] = 1
                phObject[0] = self.mock_certs[self.find_index]['handle']
                self.find_index += 1
            else:
                pulObjectCount[0] = 0
            return CKR_OK
        except Exception as e:
            print(f"\nCRITICAL MOCK ERROR in FindObjects: {e}")
            import traceback; traceback.print_exc()
            return 0x00000005 # CKR_GENERAL_ERROR
            

    def mock_C_GetAttributeValue(self, hSession, hObject, pTemplate, ulCount):

        try:
            cert = next((c for c in self.mock_certs if c['handle'] == hObject), None)
            if not cert:
                return 0x00000082 

            for i in range(ulCount):
                attr_type = pTemplate[i].type
                if attr_type == CKA_ID:
                    data = cert['id']
                elif attr_type == CKA_VALUE:
                    data = cert['der']
                elif attr_type == CKA_LABEL:
                    data = b'Mock Label'
                else:
                    continue 

                if not pTemplate[i].pValue:
                    pTemplate[i].ulValueLen = len(data)
                else:
                    memmove(pTemplate[i].pValue, data, len(data))
                    pTemplate[i].ulValueLen = len(data)
                    
            return CKR_OK
        except Exception as e:
            print(f"\nCRITICAL MOCK ERROR in GetAttributeValue: {e}")
            import traceback; traceback.print_exc()
            return 0x00000005 # CKR_GENERAL_ERROR


    def mock_C_Sign(self, hSession, pData, ulDataLen, pSignature, pulSignatureLen):
        if not pSignature:
            # Step 1: Return the required buffer size
            pulSignatureLen[0] = 256
            return CKR_OK
            
        # Step 2: Fill the provided buffer
        pSignature[0] = 0xAA
        pSignature[1] = 0xBB
        pSignature[2] = 0xCC
        return CKR_OK
        
        
    def mock_C_GetSlotList(self, tokenPresent, pSlotList, pulCount):
        ''' Handles the two-step array allocation natively '''

        available_slots = [42, 99]
        
        if not pSlotList:
            # Step 1: Tell Python how many slots exist so it can allocate memory
            pulCount[0] = len(available_slots)
            return CKR_OK
            
        # Step 2: Fill the Python-allocated memory with our slot IDs
        for i, slot_id in enumerate(available_slots):
            pSlotList[i] = slot_id
            
        return CKR_OK


    def mock_C_GetTokenInfo(self, slotID, pInfo):

        if pInfo:
            fake_serial = b"987654321       "
            pInfo.contents.serialNumber = (c_ubyte * 16)(*fake_serial)
        return CKR_OK

    def mock_C_CreateObject(self, hSession, pTemplate, ulCount, phObject):
        if phObject:
            phObject[0] = 999
        return CKR_OK


    def mock_C_GenerateKeyPair(
        self, hSession, pMechanism, pPubTpl, ulPubCount, pPrivTpl, ulPrivCount, phPubKey, 
        phPrivKey):
        
        if phPubKey: 
            phPubKey[0] = 111
        if phPrivKey: 
            phPrivKey[0] = 222
        return CKR_OK


class MockLoader:

    def __init__(self, lib_path):
        self.token = FakePkcs11Token()
        
        # wrap the mock method in a CFUNCTYPE so it behaves exactly like a 
        # function pointer returned by CDLL.
        C_GetFunctionList_t = CFUNCTYPE(
            c_ulong, 
            POINTER(POINTER(CK_FUNCTION_LIST))
        )
        
        # We must attach it to 'self' so Python's garbage collector doesn't destroy it
        self.mock_c_get_func_list = C_GetFunctionList_t(self.token.mock_C_GetFunctionList)
        

    def __call__(self, lib_path):

        # Create a dummy object to represent the loaded .so/.dll library
        class DummyLibrary:
            pass
            
        lib = DummyLibrary()
        
        # Attach the callable CFUNCTYPE object, NOT the integer from the struct
        lib.C_GetFunctionList = self.mock_c_get_func_list
        return lib


class FakeMSCAPI:
    ''' A stateful fake representing the Windows CNG and Legacy CryptoAPI '''

    def __init__(self):
        self.acquire_should_fail = False
        self.is_legacy_csp = False
        self.set_property_fail = False
        self.enum_count = 0
        
        self.last_pin_bytes = None
        self.contexts_freed = 0
        
        # Allocate raw memory for the fake certificate
        self.mock_cert_data = b'der_certificate_data'
        self.cert_buffer = create_string_buffer(self.mock_cert_data)
        
        # Build the C-Struct and point it at the allocated memory
        self.mock_ctx = mscapi.CERT_CONTEXT()
        self.mock_ctx.cbCertEncoded = len(self.mock_cert_data)
        self.mock_ctx.pbCertEncoded = cast(self.cert_buffer, c_void_p)
        
        # Create strong C-Function Pointers to our Python methods
        self.cb_CertOpenStore = CFUNCTYPE(
            c_void_p, c_uint32, c_uint32, c_void_p, c_uint32, c_void_p
        )(self._CertOpenStore)
        
        self.cb_CertEnumCertificatesInStore = CFUNCTYPE(
            c_void_p, c_void_p, c_void_p
        )(self._CertEnumCertificatesInStore)
        
        self.cb_CertDuplicateCertificateContext = CFUNCTYPE(
            c_void_p, c_void_p
        )(self._CertDuplicateCertificateContext)
        
        self.cb_CertFreeCertificateContext = CFUNCTYPE(
            c_int, c_void_p
        )(self._CertFreeCertificateContext)
        
        self.cb_CertCloseStore = CFUNCTYPE(
            c_int, c_void_p, c_uint32
        )(self._CertCloseStore)
        
        self.cb_CryptAcquireCertificatePrivateKey = CFUNCTYPE(
            c_int, c_void_p, c_uint32, c_void_p, 
            POINTER(c_void_p), POINTER(c_uint32), POINTER(c_int)
        )(self._CryptAcquireCertificatePrivateKey)
        
        self.cb_CryptReleaseContext = CFUNCTYPE(
            c_int, c_void_p, c_uint32
        )(self._CryptReleaseContext)
        
        self.cb_NCryptSetProperty = CFUNCTYPE(
            c_uint32, c_void_p, c_void_p, c_void_p, c_uint32, c_uint32
        )(self._NCryptSetProperty)
        
        self.cb_NCryptSignHash = CFUNCTYPE(
            c_uint32, c_void_p, c_void_p, c_void_p, c_uint32, 
            c_void_p, c_uint32, POINTER(c_uint32), c_uint32
        )(self._NCryptSignHash)
        
        self.cb_NCryptFreeObject = CFUNCTYPE(
            c_uint32, c_void_p
        )(self._NCryptFreeObject)

    def _CertOpenStore(self, prov, enc, hProv, flags, para):
        if prov == 0: return 0 
        return 12345

    def _CertEnumCertificatesInStore(self, hStore, pPrev):
        if self.enum_count == 0:
            self.enum_count += 1
            return addressof(self.mock_ctx)
        return 0

    def _CertDuplicateCertificateContext(self, pCert):
        return 99999

    def _CertFreeCertificateContext(self, pCert):
        self.contexts_freed += 1
        return 1

    def _CertCloseStore(self, hStore, flags):
        return 1

    def _CryptAcquireCertificatePrivateKey(self, pCert, flags, pvReserved, phProv, pdwKeySpec, pfCallerFreeProv):
        if self.acquire_should_fail:
            return 0
        phProv[0] = 55555
        pdwKeySpec[0] = 1 if self.is_legacy_csp else 0xFFFFFFFF
        pfCallerFreeProv[0] = 1
        return 1
        
    def _CryptReleaseContext(self, hProv, flags):
        return 1

    def _NCryptSetProperty(self, hObj, pszProp, pbInput, cbInput, flags):
        if self.set_property_fail:
            return 1
        self.last_pin_bytes = string_at(pbInput, cbInput)
        return 0

    def _NCryptSignHash(self, hProv, pPadInfo, pbHash, cbHash, pbSig, cbSig, pcbResult, flags):
        if not pbSig:
            pcbResult[0] = 256
            return 0
        pcbResult[0] = 256
        return 0

    def _NCryptFreeObject(self, hObj):
        return 0


class DummyWindowsLibrary:
    ''' Simple object to hold function attributes for Windows DLL mocking '''
    pass