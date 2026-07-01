import sys
from ctypes import (
    pointer, byref, sizeof, cast, CDLL, POINTER, c_ubyte, c_ulong, c_void_p, c_char_p
)

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from pkcs11_funcs import CK_FUNCTION_LIST
from pkcs11_types import (
    CK_RV, CKR_OK, CK_SESSION_HANDLE, CKF_SERIAL_SESSION, CKF_RW_SESSION, CK_BYTE, CKU_USER,
    CK_ULONG, CKO_PRIVATE_KEY, CK_ATTRIBUTE, CKA_CLASS, CKA_ID, CK_OBJECT_HANDLE, CK_MECHANISM,
    CKM_SHA256_RSA_PKCS, CKO_CERTIFICATE, CKA_VALUE, CK_BBOOL, CK_SLOT_ID,
    # SPKAC and Admin 
    CKO_PUBLIC_KEY, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKA_VERIFY, CKA_ENCRYPT, CKA_LABEL, CKA_MODULUS_BITS, CKA_TOKEN, CKA_PRIVATE,
    CKA_SIGN, CKA_DECRYPT, CKA_SENSITIVE, CKA_EXTRACTABLE, CKU_SO, CKC_X_509,
    CKA_CERTIFICATE_TYPE, CK_UTF8CHAR, CK_TOKEN_INFO
)
from cert_parser import get_rsa_public_key
from spkac import build_spkac_payload, assemble_final_spkac


LIBCVP11_PATH = f'{__file__.rsplit('/', 2)[0]}/assets/libcvP11.so'


def _pack_template(template_dict):
    ''' Returns the list of memory refs to keep the pointers alive during the C call '''
    
    attrs = (CK_ATTRIBUTE * len(template_dict))()
    refs = [] 
    
    for i, (k, v) in enumerate(template_dict.items()):
        if isinstance(v, int):
            c_val = CK_ULONG(v)
            refs.append(c_val)
            attrs[i] = CK_ATTRIBUTE(k, cast(pointer(c_val), c_void_p), sizeof(c_val))
        elif isinstance(v, bool):
            c_val = CK_BBOOL(1 if v else 0)
            refs.append(c_val)
            attrs[i] = CK_ATTRIBUTE(k, cast(pointer(c_val), c_void_p), sizeof(c_val))
        elif isinstance(v, str):
            val_bytes = v.encode('utf-8')
            c_val = (CK_BYTE * len(val_bytes))(*val_bytes)
            refs.append(c_val)
            attrs[i] = CK_ATTRIBUTE(k, cast(pointer(c_val), c_void_p), len(val_bytes))
        elif isinstance(v, bytes):
            c_val = (CK_BYTE * len(v))(*v)
            refs.append(c_val)
            attrs[i] = CK_ATTRIBUTE(k, cast(pointer(c_val), c_void_p), len(v))
            
    return attrs, refs


def get_token_serial_number(funcs, slot_id: int) -> str:
    ''' Reads the physical serial number of the smart card '''

    funcs.C_Initialize(None)
    try:
        token_info = CK_TOKEN_INFO()
        res = funcs.C_GetTokenInfo(slot_id, byref(token_info))
        if res != CKR_OK:
            raise Exception(f"C_GetTokenInfo failed: {hex(res)}")
        
        # PKCS11 pads serials with spaces
        return bytes(token_info.serialNumber).decode('utf-8', errors='ignore').strip()
    finally:
        funcs.C_Finalize(None)


def change_card_pin(funcs, slot_id: int, old_pin: str, new_pin: str):
    ''' C_SetPIN: Changes user PIN (Does not require login) '''

    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()

    # Open Read/Write session   
    res = funcs.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, byref(session))
    if res != CKR_OK: 
        funcs.C_Finalize(None)
        raise Exception(f"Failed to open session: {hex(res)}")
        
    try:
        old_b, new_b = old_pin.encode('utf-8'), new_pin.encode('utf-8')
        old_arr = (CK_UTF8CHAR * len(old_b))(*old_b)
        new_arr = (CK_UTF8CHAR * len(new_b))(*new_b)
        
        res = funcs.C_SetPIN(session, old_arr, len(old_b), new_arr, len(new_b))
        if res != CKR_OK: raise Exception(f"Failed to change PIN: {hex(res)}")
    finally:
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def unblock_card_pin(funcs, slot_id: int, puk: str, new_pin: str):
    ''' C_InitPIN: SO login using PUK to reset User PIN '''

    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    res = funcs.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, byref(session))
    if res != CKR_OK: 
        funcs.C_Finalize(None)
        raise Exception(f"Failed to open session: {hex(res)}")
        
    try:
        puk_b = puk.encode('utf-8')
        puk_arr = (CK_BYTE * len(puk_b))(*puk_b)
        res = funcs.C_Login(session, CKU_SO, puk_arr, len(puk_b))
        if res != CKR_OK: 
            raise Exception("PUK rejected. Security Officer login failed.")
            
        new_b = new_pin.encode('utf-8')
        new_arr = (CK_UTF8CHAR * len(new_b))(*new_b)
        res = funcs.C_InitPIN(session, new_arr, len(new_b))
        if res != CKR_OK: raise Exception(f"Failed to unblock PIN: {hex(res)}")
    finally:
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def write_certificate(funcs, slot_id: int, pin: str, cert_der: bytes):
    ''' C_CreateObject: Injects a DER-encoded X.509 cert onto the token paired with its keypair '''
        
    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    res = funcs.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, byref(session))
    if res != CKR_OK: 
        funcs.C_Finalize(None)
        raise Exception(f"Failed to open session: {hex(res)}")
        
    try:
        # Parse the RSA public modulus (n) from the certificate DER
        n_val, e_val = get_rsa_public_key(cert_der)
        n_bytes = n_val.to_bytes((n_val.bit_length() + 7) // 8, 'big')
        
        # User login required to create objects
        pin_b = pin.encode('utf-8')
        pin_arr = (CK_BYTE * len(pin_b))(*pin_b)
        res = funcs.C_Login(session, CKU_USER, pin_arr, len(pin_b))
        if res != CKR_OK: raise Exception(f"C_Login failed: {hex(res)}")
        
        # 3. Find the matching Public Key object on the card
        class_val = CK_ULONG(CKO_PUBLIC_KEY)
        n_c_val = (CK_BYTE * len(n_bytes))(*n_bytes)
        
        search_template = (CK_ATTRIBUTE * 2)()
        search_template[0].type, search_template[0].pValue, search_template[0].ulValueLen = CKA_CLASS, cast(byref(class_val), c_void_p), sizeof(CK_ULONG)
        search_template[1].type, search_template[1].pValue, search_template[1].ulValueLen = CKA_MODULUS, cast(byref(n_c_val), c_void_p), len(n_bytes)
        
        funcs.C_FindObjectsInit(session, search_template, 2)
        obj_handle = CK_OBJECT_HANDLE()
        obj_count = CK_ULONG()
        res = funcs.C_FindObjects(session, byref(obj_handle), 1, byref(obj_count))
        funcs.C_FindObjectsFinal(session)
        
        if res != CKR_OK or obj_count.value == 0:
            raise Exception("No matching public key found on card for this certificate. Pairing impossible.")
            
        # Read CKA_ID and CKA_LABEL from the matching public key
        get_template = (CK_ATTRIBUTE * 2)()
        get_template[0].type, get_template[0].pValue, get_template[0].ulValueLen = CKA_ID, None, 0
        get_template[1].type, get_template[1].pValue, get_template[1].ulValueLen = CKA_LABEL, None, 0
        
        res = funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)
        if res != CKR_OK: raise Exception(f"Failed to get sizes for ID/Label: {hex(res)}")
        
        # Safe extraction: Ignore 0xFFFFFFFF (-1) which means CK_UNAVAILABLE_INFORMATION
        id_len = get_template[0].ulValueLen if get_template[0].ulValueLen < 10000 else 0
        label_len = get_template[1].ulValueLen if get_template[1].ulValueLen < 10000 else 0
        
        id_buf = (CK_BYTE * id_len)() if id_len > 0 else None
        label_buf = (CK_BYTE * label_len)() if label_len > 0 else None
        
        get_template[0].pValue = cast(byref(id_buf), c_void_p) if id_buf else None
        get_template[1].pValue = cast(byref(label_buf), c_void_p) if label_buf else None
        
        res = funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)
        if res != CKR_OK: raise Exception(f"Failed to read ID/Label data: {hex(res)}")
        
        # Build and write the grouped certificate object
        template_dict = {
            CKA_CLASS: CKO_CERTIFICATE,
            CKA_CERTIFICATE_TYPE: CKC_X_509,
            CKA_VALUE: cert_der,
            CKA_TOKEN: True,
            CKA_PRIVATE: False
        }
        if id_buf: template_dict[CKA_ID] = bytes(id_buf)
        if label_buf: template_dict[CKA_LABEL] = bytes(label_buf)
        
        attrs, _refs = _pack_template(template_dict)
        cert_handle = CK_OBJECT_HANDLE()
        res = funcs.C_CreateObject(session, attrs, len(template_dict), byref(cert_handle))
        if res != CKR_OK: raise Exception(f"C_CreateObject failed: {hex(res)}")
        
    finally:
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def generate_rsa_keypair(funcs, slot_id: int, pin: str, label: str = "New RSA Key", key_id: bytes = b''):
    ''' C_GenerateKeyPair: Hardware-level generation of 2048-bit RSA keys '''

    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    res = funcs.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, byref(session))
    if res != CKR_OK: 
        funcs.C_Finalize(None)
        raise Exception(f"Failed to open session: {hex(res)}")
        
    try:
        pin_b = pin.encode('utf-8')
        pin_arr = (CK_BYTE * len(pin_b))(*pin_b)
        funcs.C_Login(session, CKU_USER, pin_arr, len(pin_b)) # Fixed: pin_arr
        
        pub_dict = {
            CKA_TOKEN: True,
            CKA_PRIVATE: False,
            CKA_VERIFY: True,
            CKA_ENCRYPT: True,
            CKA_LABEL: label,
            CKA_MODULUS_BITS: 2048,
            CKA_PUBLIC_EXPONENT: b'\x01\x00\x01'   # 65537
        }
        
        priv_dict = {
            CKA_TOKEN: True,
            CKA_PRIVATE: True,
            CKA_SIGN: True,
            CKA_DECRYPT: True,
            CKA_SENSITIVE: True,
            CKA_EXTRACTABLE: False,
            CKA_LABEL: label
        }
        
        # Stamp the matching ID onto both the public and private key
        if key_id:
            pub_dict[CKA_ID] = key_id
            priv_dict[CKA_ID] = key_id
        
        pub_attrs, _pub_refs = _pack_template(pub_dict)
        priv_attrs, _priv_refs = _pack_template(priv_dict)
        
        mechanism = CK_MECHANISM(mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter=None, ulParameterLen=0)
        pub_handle, priv_handle = CK_OBJECT_HANDLE(), CK_OBJECT_HANDLE()
        
        res = funcs.C_GenerateKeyPair(
            session, byref(mechanism),
            pub_attrs, len(pub_dict),
            priv_attrs, len(priv_dict),
            byref(pub_handle), byref(priv_handle)
        )
        if res != CKR_OK: raise Exception(f"Failed to generate keypair: {hex(res)}")
    finally:
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)
        
    return True


def load_pkcs11(lib_path: str, loader=CDLL):
    ''' Loads the DLL and extracts the function table '''

    lib = loader(lib_path)
    
    C_GetFunctionList = lib.C_GetFunctionList
    C_GetFunctionList.argtypes = [POINTER(POINTER(CK_FUNCTION_LIST))]
    C_GetFunctionList.restype = CK_RV
    
    # Pre-allocate an empty struct so the pointer is not NULL during mock testing.
    # The real C library will safely overwrite this pointer address.
    func_list = CK_FUNCTION_LIST()
    func_list_ptr = pointer(func_list)
    
    rv = C_GetFunctionList(byref(func_list_ptr))
    if rv != CKR_OK:
        raise Exception(f'Failed to get function list: {rv}')
        
    return func_list_ptr.contents


def sign_payload(funcs, slot_id: int, pin: str, payload: bytes, key_id: bytes) -> bytes:
    ''' PKCS#11 signing flow '''
    
    # Init & Open Session
    funcs.C_Initialize(None)
    
    session = CK_SESSION_HANDLE()
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    rv = funcs.C_OpenSession(slot_id, flags, None, None, byref(session))
    if rv != CKR_OK:
        raise Exception(f'C_OpenSession failed: {rv}')

    try:
        # Login
        pin_bytes = pin.encode('utf-8')
        pin_array = (CK_BYTE * len(pin_bytes))(*pin_bytes)
        rv = funcs.C_Login(session, CKU_USER, pin_array, len(pin_bytes))
        if rv != CKR_OK:
            raise Exception(f'C_Login failed: {rv}')

        # Find the Private Key (The tricky part: Packing the CKA_ID)
        # We search for: CKA_CLASS == CKO_PRIVATE_KEY AND CKA_ID == key_id
        
        class_val = CK_ULONG(CKO_PRIVATE_KEY)
        id_array = (CK_BYTE * len(key_id))(*key_id)
        
        search_template = (CK_ATTRIBUTE * 2)()
        
        search_template[0].type = CKA_CLASS
        search_template[0].pValue = cast(byref(class_val), c_void_p)
        search_template[0].ulValueLen = sizeof(CK_ULONG)
        
        search_template[1].type = CKA_ID
        search_template[1].pValue = cast(byref(id_array), c_void_p)
        search_template[1].ulValueLen = len(key_id)

        funcs.C_FindObjectsInit(session, search_template, 2)
        
        obj_handle = CK_OBJECT_HANDLE()
        obj_count = CK_ULONG()
        rv = funcs.C_FindObjects(session, byref(obj_handle), 1, byref(obj_count))
        funcs.C_FindObjectsFinal(session)
        
        if rv != CKR_OK or obj_count.value == 0:
            raise Exception('Private key not found on card.')

        # Sign the payload
        mechanism = CK_MECHANISM(mechanism=CKM_SHA256_RSA_PKCS, pParameter=None, ulParameterLen=0)
        
        rv = funcs.C_SignInit(session, byref(mechanism), obj_handle)
        if rv != CKR_OK:
            raise Exception(f'C_SignInit failed: {rv}')

        payload_array = (CK_BYTE * len(payload))(*payload)
        sig_len = CK_ULONG(0)
        
        # Call C_Sign with NULL buffer to get the required length
        rv = funcs.C_Sign(session, payload_array, len(payload), None, byref(sig_len))
        
        # Verify the hardware successfully returned the required size
        if rv != CKR_OK:
            raise Exception(f'Failed to get signature size. RV: 0x{rv:08X}')
        
        # Call C_Sign again with the properly sized buffer
        sig_array = (CK_BYTE * sig_len.value)()
        rv = funcs.C_Sign(session, payload_array, len(payload), sig_array, byref(sig_len))
        if rv != CKR_OK:
            raise Exception(f'C_Sign failed: 0x{rv:08X}')

        return bytes(sig_array)

    finally:
        # Cleanup (Crucial for hardware to not lock up)
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def get_certificates(funcs, slot_id: int, pin: str) -> list[dict]:
    ''' Retrieves all certificates from the token with their CKA_ID and DER values '''
    
    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    
    rv = funcs.C_OpenSession(slot_id, flags, None, None, byref(session))
    if rv != CKR_OK:
        raise Exception(f'C_OpenSession failed: {rv}')

    certs = []
    try:
        pin_bytes = pin.encode('utf-8')
        pin_array = (CK_BYTE * len(pin_bytes))(*pin_bytes)
        rv = funcs.C_Login(session, CKU_USER, pin_array, len(pin_bytes))
        if rv != CKR_OK and rv != 0x00000100:  # 0x100 is CKR_USER_ALREADY_LOGGED_IN
            raise Exception(f'C_Login failed: {rv}')

        # Search for Certificates
        class_val = CK_ULONG(CKO_CERTIFICATE)
        search_template = (CK_ATTRIBUTE * 1)()
        search_template[0].type = CKA_CLASS
        search_template[0].pValue = cast(byref(class_val), c_void_p)
        search_template[0].ulValueLen = sizeof(CK_ULONG)

        funcs.C_FindObjectsInit(session, search_template, 1)

        while True:
            obj_handle = CK_OBJECT_HANDLE()
            obj_count = CK_ULONG()
            rv = funcs.C_FindObjects(session, byref(obj_handle), 1, byref(obj_count))
            
            if rv != CKR_OK or obj_count.value == 0:
                break

            # Define the template
            get_template = (CK_ATTRIBUTE * 2)()
            get_template[0].type = CKA_ID
            get_template[0].pValue = None
            get_template[0].ulValueLen = 0
            
            get_template[1].type = CKA_VALUE
            get_template[1].pValue = None
            get_template[1].ulValueLen = 0

            # Call C_GetAttributeValue to get the required buffer sizes
            rv = funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)
            if rv != CKR_OK:
                raise Exception(f"Failed to get size for cert attributes. RV: 0x{rv:08X}")

            # Allocate and fetch
            id_buf = (CK_BYTE * get_template[0].ulValueLen)()
            val_buf = (CK_BYTE * get_template[1].ulValueLen)()
            
            get_template[0].pValue = cast(byref(id_buf), c_void_p)
            get_template[1].pValue = cast(byref(val_buf), c_void_p)

            rv = funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)
            if rv == CKR_OK:
                certs.append({
                    'id': bytes(id_buf),
                    'der': bytes(val_buf)
                })
                    
        funcs.C_FindObjectsFinal(session)
        return certs

    finally:
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def get_slots(funcs, token_present: bool = True) -> list[int]:
    ''' Returns a list of available slot IDs (connected smart card readers) '''

    funcs.C_Initialize(None)
    try:
        count = CK_ULONG()
        present = CK_BBOOL(1 if token_present else 0)
        
        # Get the number of slots
        rv = funcs.C_GetSlotList(True, None, byref(count))
        if rv != CKR_OK:
            raise Exception(f"Failed to get slot count. RV: 0x{rv:08X}")
            
        # Allocate an array of that size and fetch the slots
        slots = (CK_SLOT_ID * count.value)()
        rv = funcs.C_GetSlotList(present, slots, byref(count))
        if rv != CKR_OK:
            raise Exception(f'C_GetSlotList failed: {rv}')
            
        return [slots[i] for i in range(count.value)]
    finally:
        funcs.C_Finalize(None)


def get_token_info_extended(funcs, slot_id: int) -> dict:
    ''' Returns the full hardware specs for /getInfo '''

    funcs.C_Initialize(None)
    try:
        token_info = CK_TOKEN_INFO()
        res = funcs.C_GetTokenInfo(slot_id, byref(token_info))
        if res != CKR_OK: raise Exception(f"C_GetTokenInfo failed: {hex(res)}")
        
        return {
            "label": bytes(token_info.label).decode('utf-8', errors='ignore').strip(),
            "manufacturerID": bytes(token_info.manufacturerID).decode('utf-8', errors='ignore').strip(),
            "model": bytes(token_info.model).decode('utf-8', errors='ignore').strip(),
            "serialNumber": bytes(token_info.serialNumber).decode('utf-8', errors='ignore').strip(),
            "ulFreePublicMemory": token_info.ulFreePublicMemory,
            "ulTotalPublicMemory": token_info.ulTotalPublicMemory,
            "ulFreePrivateMemory": token_info.ulFreePrivateMemory,
            "ulTotalPrivateMemory": token_info.ulTotalPrivateMemory
        }
    finally:
        funcs.C_Finalize(None)


def delete_object_by_label(funcs, slot_id: int, pin: str, object_class: int, label: str) -> bool:
    ''' C_DestroyObject: Removes all objects of a given class matching a label. Returns True if objects were deleted '''
    
    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    res = funcs.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, byref(session))
    if res != CKR_OK: raise Exception(f"Failed to open session: {hex(res)}")
    
    try:
        pin_bytes = pin.encode('utf-8')
        pin_array = (CK_BYTE * len(pin_bytes))(*pin_bytes)
        res = funcs.C_Login(session, CKU_USER, pin_array, len(pin_bytes))
        if res != CKR_OK and res != 0x00000100: raise Exception(f"C_Login failed: {hex(res)}")

        # Search for objects by Class and Label
        class_val = CK_ULONG(object_class)
        label_bytes = label.encode('utf-8')
        label_arr = (CK_BYTE * len(label_bytes))(*label_bytes)
        
        search_template = (CK_ATTRIBUTE * 2)()
        search_template[0].type, search_template[0].pValue, search_template[0].ulValueLen = CKA_CLASS, cast(byref(class_val), c_void_p), sizeof(CK_ULONG)
        search_template[1].type, search_template[1].pValue, search_template[1].ulValueLen = CKA_LABEL, cast(byref(label_arr), c_void_p), len(label_bytes)
        
        res = funcs.C_FindObjectsInit(session, search_template, 2)
        if res != CKR_OK: raise Exception(f"C_FindObjectsInit failed: {hex(res)}")
        
        deleted_any = False
        while True:
            obj_handle = CK_OBJECT_HANDLE()
            obj_count = CK_ULONG()
            res = funcs.C_FindObjects(session, byref(obj_handle), 1, byref(obj_count))
            
            if res != CKR_OK or obj_count.value == 0:
                break
                
            funcs.C_DestroyObject(session, obj_handle)
            deleted_any = True
            
        funcs.C_FindObjectsFinal(session)
        return deleted_any
        
    finally:
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)


def generate_spkac(funcs, slot_id: int, pin: str, key_id: bytes, challenge: str) -> str:
    ''' 
    Generates an RSA Keypair on the token, extracts the raw public parameters, 
    and produces a signed SPKAC request for a CA portal renewal.
    '''

    # Tell the token to physically generate the RSA keys
    generate_rsa_keypair(funcs, slot_id, pin, label="B-Trust Renewal Key", key_id=key_id)

    funcs.C_Initialize(None)
    session = CK_SESSION_HANDLE()
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    rv = funcs.C_OpenSession(slot_id, flags, None, None, byref(session))
    if rv != CKR_OK: raise Exception(f'C_OpenSession failed: {rv}')

    try:
        pin_bytes = pin.encode('utf-8')
        pin_array = (CK_BYTE * len(pin_bytes))(*pin_bytes)
        funcs.C_Login(session, CKU_USER, pin_array, len(pin_bytes))

        # Find the Public Key we just generated
        class_val = CK_ULONG(CKO_PUBLIC_KEY)
        id_array = (CK_BYTE * len(key_id))(*key_id)
        search_template = (CK_ATTRIBUTE * 2)()
        search_template[0].type, search_template[0].pValue, search_template[0].ulValueLen = CKA_CLASS, cast(byref(class_val), c_void_p), sizeof(CK_ULONG)
        search_template[1].type, search_template[1].pValue, search_template[1].ulValueLen = CKA_ID, cast(byref(id_array), c_void_p), len(key_id)
        
        funcs.C_FindObjectsInit(session, search_template, 2)
        obj_handle = CK_OBJECT_HANDLE()
        obj_count = CK_ULONG()
        funcs.C_FindObjects(session, byref(obj_handle), 1, byref(obj_count))
        funcs.C_FindObjectsFinal(session)
        
        if obj_count.value == 0:
            raise Exception("Failed to locate the newly generated public key on the token.")

        # 3. Extract the Raw Modulus and Exponent
        get_template = (CK_ATTRIBUTE * 2)()
        get_template[0].type, get_template[0].pValue, get_template[0].ulValueLen = CKA_MODULUS, None, 0
        get_template[1].type, get_template[1].pValue, get_template[1].ulValueLen = CKA_PUBLIC_EXPONENT, None, 0
        funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)

        mod_buf = (CK_BYTE * get_template[0].ulValueLen)()
        exp_buf = (CK_BYTE * get_template[1].ulValueLen)()
        get_template[0].pValue = cast(byref(mod_buf), c_void_p)
        get_template[1].pValue = cast(byref(exp_buf), c_void_p)
        funcs.C_GetAttributeValue(session, obj_handle, get_template, 2)

        # Build the To-Be-Signed SPKAC payload in pure Python
        tbs_der = build_spkac_payload(bytes(mod_buf), bytes(exp_buf), challenge)

    finally:
        # Crucial to close this session before calling sign_payload, 
        # because sign_payload opens its own session!
        funcs.C_Logout(session)
        funcs.C_CloseSession(session)
        funcs.C_Finalize(None)

    # Sign the payload using the card
    signature = sign_payload(funcs, slot_id, pin, tbs_der, key_id)

    # Finalize and return the Base64 SPKAC
    return assemble_final_spkac(tbs_der, signature)