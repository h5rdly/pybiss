import base64, sys

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

import detector as detector
import hardware as hardware
import service as service

from config import config
from server import MiniServer
from ui_bridge import get_ui_provider

from pkcs11_types import CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE


# -- Endpoints 

app = MiniServer()


@app.get('/version')
def get_version(req):
    return {
        'version': 'pybiss-1.0.0',
        'httpMethods': 'GET, POST',
        'contentTypes': 'data, digest',
        'signatureTypes': 'signature',
        'selectorAvailable': True,
        'hashAlgorithms': 'SHA1, SHA256, SHA384, SHA512'
    }


@app.get('/status')
def get_status(req):
    atrs = detector.get_connected_atrs()
    lib_path = detector.auto_detect_library()
    return {
        'status': 'ok' if atrs else 'no_cards_detected',
        'readers': atrs,
        'driver': lib_path
    }


@app.get('/getSerialNumber')
def get_serial_number(req):
    
    lib_path = detector.auto_detect_library()
    if not lib_path:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'No supported smart cards detected'}
        
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        if not slots:
            return {'status': 'error', 'reasonCode': 404, 'reasonText': 'No token present'}
            
        serial = hardware.get_token_serial_number(funcs, slots[0])
        # The Java app returns keysize and vendor too, but serial is the most critical
        return {'serialNumber': serial, 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/setPIN')
def set_pin(req):

    data = req.json
    old_pin = data.get('oldPIN')
    new_pin = data.get('newPIN')
    
    if not old_pin or not new_pin:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'Missing PIN data'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        hardware.change_card_pin(funcs, slots[0], old_pin, new_pin)
        return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'PIN successfully changed'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/unblockPIN')
def unblock_pin(req):

    data = req.json
    puk = data.get('puk')
    new_pin = data.get('newPIN')
    
    if not puk or not new_pin:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'Missing PUK or new PIN'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        hardware.unblock_card_pin(funcs, slots[0], puk, new_pin)
        return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'PIN successfully unblocked'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 403, 'reasonText': str(e)}


@app.post('/writeCertSC')
def write_cert_sc(req):

    data = req.json
    cert_b64 = data.get('certificate')
    
    if not cert_b64:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'Missing certificate data'}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        cert_der = base64.b64decode(cert_b64)
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        hardware.write_certificate(funcs, slots[0], pin, cert_der)
        return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'Certificate successfully written to card'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/getInfo')
def get_info(req):
    ''' Diagnostics: Returns full hardware spec sheet '''

    lib_path = detector.auto_detect_library()
    if not lib_path: return {'status': 'error', 'reasonCode': 400, 'reasonText': 'No smart card detected'}
    
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        if not slots: return {'status': 'error', 'reasonCode': 404, 'reasonText': 'No token present'}
        
        info = hardware.get_token_info_extended(funcs, slots[0])
        return {'info': info, 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/genRSAPair')
def gen_rsa_pair(req):

    data = req.json
    label = data.get('label', 'B-Trust Generated Key')
    key_id = data.get('keyId', '').encode('utf-8')
    
    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin: return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        hardware.generate_rsa_keypair(funcs, slots[0], pin, label=label, key_id=key_id)
        return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'RSA Keypair Generated'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/renew')
def renew_cert(req):
    ''' Generates the SPKAC payload required for certificate renewal on B-Trust portals '''
    
    data = req.json
    key_id = data.get('keyId', 'RENEWAL').encode('utf-8')
    challenge = data.get('challenge', '1234')
    
    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin: return {'spkac': None, 'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        spkac_b64 = hardware.generate_spkac(funcs, slots[0], pin, key_id, challenge)
        return {'spkac': spkac_b64, 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
    except Exception as e:
        return {'spkac': None, 'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/delRSAPair')
def del_rsa_pair(req):

    data = req.json
    label = data.get('label')
    if not label: 
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'Missing key label'}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin: 
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        # Must attempt to delete both the Private and Public key objects
        priv_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_PRIVATE_KEY, label)
        pub_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_PUBLIC_KEY, label)
        
        if priv_deleted or pub_deleted:
            return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'Keypair deleted'}
        else:
            return {'status': 'error', 'reasonCode': 404, 'reasonText': 'Keypair not found'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/delCert')
def del_cert(req):

    data = req.json
    label = data.get('label')
    if not label: return {'status': 'error', 'reasonCode': 400, 'reasonText': 'Missing cert label'}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin: return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        cert_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_CERTIFICATE, label)
        if cert_deleted:
            return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'Certificate deleted'}
        else:
            return {'status': 'error', 'reasonCode': 404, 'reasonText': 'Certificate not found'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/getsigner')
def get_signer(req):

    data = req.json
    selector = data.get('selector')
    show_valid_certs = data.get('showValidCerts', True)

    ui_provider = get_ui_provider()
    sign_api = config.get('signAPI', 'PKCS11')
    
    # - Windows Native Store (MSCAPI) Flow 
    if sign_api == 'MSCAPI' and sys.platform == 'win32':
        import mscapi as mscapi
        raw_certs = mscapi.get_windows_certificates()
        try:
            filtered_certs = service.filter_certificates(
                raw_certs, selector=selector, show_valid_certs=show_valid_certs
            )
            if not filtered_certs:
                return {'chain': [], 'status': 'error', 'reasonCode': 404, 'reasonText': 'No matching certificates'}
                
            choice_idx = ui_provider.choose_certificate(filtered_certs)
            if choice_idx == -1:
                return {'chain': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Canceled'}
                
            selected_cert = filtered_certs[choice_idx]
            cert_b64 = base64.b64encode(selected_cert['der']).decode('utf-8')
            return {'chain': [cert_b64], 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
        finally:
            # Free contexts to prevent memory leaks!
            for c in raw_certs:
                mscapi.free_windows_certificate(c['windows_ctx'])
                
    # - PKCS11 (Hardware) Flow  
    lib_path = detector.auto_detect_library()
    if not lib_path:
        raise Exception('No supported smart cards detected')
        
    funcs = hardware.load_pkcs11(lib_path)
    slots = hardware.get_slots(funcs, token_present=True)
    if not slots:
        raise Exception('No token present in smart card reader')
    
    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'chain': [], 'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    all_certs = []
    for slot_id in slots:
        try:
            certs = hardware.get_certificates(funcs, slot_id, pin)
            for c in certs:
                c['slot_id'] = slot_id
                c['pin'] = pin
                all_certs.append(c)
        except Exception:
            continue

    filtered_certs = service.filter_certificates(all_certs, selector=selector, show_valid_certs=show_valid_certs)
    if not filtered_certs:
        return {'chain': [], 'status': 'error', 'reasonCode': 404, 'reasonText': 'No matching certificates'}

    choice_idx = ui_provider.choose_certificate(filtered_certs)
    if choice_idx == -1:
        return {'chain': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Canceled'}

    selected_cert = filtered_certs[choice_idx]
    cert_b64 = base64.b64encode(selected_cert['der']).decode('utf-8')
    
    return {'chain': [cert_b64], 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}


@app.post('/sign')
def sign(req):

    data = req.json
    
    # Extract fields from the raw JSON payload
    contents = data.get('contents', [])
    signed_contents = data.get('signedContents', [])
    signed_contents_cert = data.get('signedContentsCert', [])
    hash_algorithm = data.get('hashAlgorithm', 'SHA256')
    confirm_text = data.get('confirmText', [])
    signer_cert_b64 = data.get('signerCertificateB64')

    # Verification of Server Signature (Pre-flight Security)
    if len(contents) != len(signed_contents) or not contents:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Contents and signature length mismatch/empty'}
        
    try:
        if not signed_contents_cert:
            raise ValueError('Server certificate missing')
        server_cert_der = base64.b64decode(signed_contents_cert[0])
    except Exception:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Invalid server certificate encoding'}

    # Verify each content piece against the server signature
    for i in range(len(contents)):
        try:
            payload = base64.b64decode(contents[i])
            srv_sig = base64.b64decode(signed_contents[i])
        except Exception:
            return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Invalid payload/signature base64 encoding'}
            
        verified = service.verify_server_signature(
            payload=payload,
            signature=srv_sig,
            server_cert_der=server_cert_der,
            hash_alg=hash_algorithm
        )
        if not verified:
            return {'signatures': [], 'status': 'error', 'reasonCode': 403, 'reasonText': 'Server signature verification failed'}

    # Confirm signature request with the user via UI
    ui_provider = get_ui_provider()
    confirm_msg = confirm_text[0] if confirm_text else 'Authorize signature request from banking portal?'
    
    confirmed = ui_provider.confirm_sign(confirm_msg)
    if not confirmed:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'User rejected signature request'}

    # Parse the target signer certificate
    try:
        if not signer_cert_b64:
            raise ValueError('Signer certificate missing')
        signer_cert_der = base64.b64decode(signer_cert_b64)
    except Exception:
         return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Invalid signer certificate encoding'}

    # Route to the correct Cryptographic Engine
    from config import config
    sign_api = config.get('signAPI', 'PKCS11')

    # PATH A: Windows Native Store (MSCAPI / CNG)
    if sign_api == 'MSCAPI' and sys.platform == 'win32':
        import mscapi as mscapi
        raw_certs = mscapi.get_windows_certificates()
        try:
            target_ctx = None
            for c in raw_certs:
                if c['der'] == signer_cert_der:
                    target_ctx = c['windows_ctx']
                    break
                    
            if not target_ctx:
                return {'signatures': [], 'status': 'error', 'reasonCode': 404, 'reasonText': 'Requested signing certificate not found in Windows Store'}
            
            # Prompt PIN just before signing
            pin = ui_provider.prompt_pin()
            if not pin:
                return {'signatures': [], 'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN required'}
                
            generated_signatures = []
            for payload_b64 in contents:
                payload_bytes = base64.b64decode(payload_b64)
                sig = mscapi.sign_payload_windows(
                    cert_ctx_pointer=target_ctx,
                    payload=payload_bytes,
                    pin=pin,
                    hash_alg=hash_algorithm
                )
                generated_signatures.append(base64.b64encode(sig).decode('utf-8'))
                
            return {'signatures': generated_signatures, 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
            
        except Exception as e:
            return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Signing failed: {e}'}
        finally:
            # Always free Windows contexts to prevent memory leaks
            for c in raw_certs:
                mscapi.free_windows_certificate(c['windows_ctx'])

    # PATH B: PKCS#11 Hardware Middleware (Default)
    else:
        lib_path = detector.auto_detect_library()
        if not lib_path:
            return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'No supported smart cards detected'}
            
        try:
            funcs = hardware.load_pkcs11(lib_path)
        except Exception as e:
            return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Failed to load PKCS11 driver: {e}'}

        slots = hardware.get_slots(funcs, token_present=True)
        target_slot = None
        target_cert_id = None
        target_pin = None

        # Prompt user for PIN to search card (Required for some PKCS11 tokens to expose certs)
        pin = ui_provider.prompt_pin()
        if not pin:
            return {'signatures': [], 'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN required'}

        for slot_id in slots:
            try:
                certs = hardware.get_certificates(funcs, slot_id, pin)
                for c in certs:
                    if c['der'] == signer_cert_der:
                        target_slot = slot_id
                        target_cert_id = c['id']
                        target_pin = pin
                        break
                if target_slot is not None:
                    break
            except Exception:
                continue

        if target_slot is None:
            return {'signatures': [], 'status': 'error', 'reasonCode': 404, 'reasonText': 'Requested signing certificate not found on smart card'}

        # Perform PKCS#11 signing
        generated_signatures = []
        for payload_b64 in contents:
            try:
                payload_bytes = base64.b64decode(payload_b64)
                sig = hardware.sign_payload(
                    funcs=funcs,
                    slot_id=target_slot,
                    pin=target_pin,
                    payload=payload_bytes,
                    key_id=target_cert_id
                )
                generated_signatures.append(base64.b64encode(sig).decode('utf-8'))
            except Exception as e:
                return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Signing failed: {e}'}

        return {'signatures': generated_signatures, 'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}


if __name__ == '__main__':

    # Runs the server headlessly via CLI
    # For the full Desktop GUI, run src/dashboard.py instead
    app.run(host='127.0.0.1', port=4843)