import base64, sys

sys.path.append(__file__.rsplit('/', 1)[0])

from src.server import MiniServer
import src.detector as detector
import src.hardware as hardware
import src.service as service
import src.server_ui as ui


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


@app.post('/getsigner')
def get_signer(req):
    data = req.json
    selector = data.get('selector')
    show_valid_certs = data.get('showValidCerts', True)

    lib_path = detector.auto_detect_library()
    if not lib_path:
        raise Exception('No supported smart cards detected')
        
    funcs = hardware.load_pkcs11(lib_path)
    slots = hardware.get_slots(funcs, token_present=True)
    if not slots:
        raise Exception('No token present in smart card reader')
    
    ui_provider = ui.get_ui_provider()
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

    # Verification of Server Signature
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

    # Confirm signature request with the user
    ui_provider = ui.get_ui_provider()
    confirm_msg = confirm_text[0] if confirm_text else 'Authorize signature request from banking portal?'
    
    confirmed = ui_provider.confirm_sign(confirm_msg)
    if not confirmed:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'User rejected signature request'}

    # Locate card PKCS11 library
    lib_path = detector.auto_detect_library()
    if not lib_path:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'No supported smart cards detected'}
        
    try:
        funcs = hardware.load_pkcs11(lib_path)
    except Exception as e:
        return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Failed to load PKCS11 driver: {e}'}

    # Search and identify which slot contains the requested signer certificate
    try:
        if not signer_cert_b64:
            raise ValueError('Signer certificate missing')
        signer_cert_der = base64.b64decode(signer_cert_b64)
    except Exception:
         return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Invalid signer certificate encoding'}

    slots = hardware.get_slots(funcs, token_present=True)
    target_slot = None
    target_cert_id = None
    target_pin = None

    # Prompt user for PIN to search card
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

    ui_provider = ui.get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN canceled'}

    lib_path = detector.auto_detect_library()
    try:
        cert_der = base64.b64decode(cert_b64)
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        
        hardware.write_certificate(funcs, slots[0], pin, cert_der, label="B-Trust Certificate")
        return {'status': 'ok', 'reasonCode': 200, 'reasonText': 'Certificate successfully written to card'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


if __name__ == '__main__':

    app.run(host='127.0.0.1', port=4843)