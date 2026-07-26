import base64, functools, hashlib, os, sys

from . import detector, hardware, service, jws, transport, backends, card_service, card_access
from .cards import BTrustDriver
from .cert_parser import pem_to_der
from .config import config
from .i18n import reason
from .pkcs11_types import CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE
from .server import MiniServer, CORS
from .ui_bridge import get_ui_provider


# -- Endpoints 

app = MiniServer()
# Match the daemon's open CORS (origin '*', no credentials); jwsData is the gate.
CORS(app)


def jws_gated(admin_required: bool = False):
    '''
    Verifies the request's jwsData before the handler run. The verified JWS payload is
    passed to the handler as its second argument.
    '''

    def decorator(handler):
        @functools.wraps(handler)
        def gated(req):
            try:
                payload = jws.verify(req.json.get('jwsData', ''), admin_required=admin_required)
            except jws.JwsError as e:
                return {'status': 'error', 'reasonCode': 403, 'reasonText': str(e)}
            return handler(req, payload)
        return gated
    return decorator


@app.get('/version')
def get_version(req):
    return {
        'version': config.get('bissVersion', '3.46'),
        'httpMethods': 'GET, POST',
        'contentTypes': 'data, digest',
        'signatureTypes': 'signature',
        'selectorAvailable': True,
        'hashAlgorithms': 'SHA256, SHA384, SHA512'
    }


@app.get('/status')
def get_status(req):
    ''' The official daemon answers with the literal JSON string "". Diagnostics live in /getInfo instead '''
    return ''


@app.post('/close')
def close_daemon(req):
    app.request_shutdown()
    # The official daemon returns this bare string despite the JSON content type
    return b'Signing service successfully closed!'


@app.post('/getSerialNumber')
@jws_gated()
def get_serial_number(req, payload):

    lib_path = detector.auto_detect_library()
    if not lib_path:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': 'No supported smart cards detected'}

    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        if not slots:
            return {'status': 'error', 'reasonCode': 404, 'reasonText': 'No token present'}

        serial = hardware.get_token_serial_number(funcs, slots[0])
        provider = next((p for p in map(detector.identify_provider, detector.get_connected_atrs()) if p), None)
        # Recent B-Trust Gemalto cards (940B/940C) carry 3072-bit keys
        key_size = 3072 if provider == 'GEMALTO' else 2048
        return {'cardSerialNumber': serial, 'vendor': provider, 'keySize': key_size,
                'status': 'ok', 'reasonCode': 200, 'reasonText': 'Success'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/setPIN')
@jws_gated()
def set_pin(req, payload):

    # The PINs are never part of the request - the daemon prompts locally
    ui_provider = get_ui_provider()
    old_pin = ui_provider.prompt_pin(label='current PIN')
    new_pin = ui_provider.prompt_pin(label='new PIN') if old_pin else None
    if not old_pin or not new_pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PIN entry canceled'}

    try:
        card_service.change_pin(old_pin, new_pin)
        return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': 'PIN successfully changed'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/setPUK')
@jws_gated()
def set_puk(req, payload):

    ui_provider = get_ui_provider()
    old_puk = ui_provider.prompt_pin(label='current PUK')
    new_puk = ui_provider.prompt_pin(label='new PUK') if old_puk else None
    if not old_puk or not new_puk:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PUK entry canceled'}

    try:
        card_service.change_puk(old_puk, new_puk)
        return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': 'PUK successfully changed'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/unblockPIN')
@jws_gated(admin_required=True)  # unblocking needs the administrative level
def unblock_pin(req, payload):

    ui_provider = get_ui_provider()
    puk = ui_provider.prompt_pin(label='PUK')
    new_pin = ui_provider.prompt_pin(label='new PIN') if puk else None
    if not puk or not new_pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': 'PUK entry canceled'}

    try:
        card_service.unblock_pin(puk, new_pin)
        return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': 'PIN successfully unblocked'}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 403, 'reasonText': str(e)}


CERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'certs')


@app.post('/chainFound')
def chain_found(req):
    ''' Reports whether a full certificate chain exists for a key identifier '''

    key_identifier = (req.json.get('keyIdentifier') or '').strip()
    if not key_identifier:
        return {'chainFound': False, 'status': 'error', 'reasonCode': 400,
                'reasonText': reason('error.request.mandatory-params')}

    found = service.chain_exists_for_key_identifier(
        key_identifier, service.load_ca_certificates(CERTS_DIR)
    )
    return {'chainFound': found, 'status': 'ok', 'reasonCode': 200,
            'reasonText': reason('response.success')}


@app.post('/genSPKAC')
@jws_gated()
def gen_spkac(req, payload):
    '''
    Generates a fresh key pair on the card and returns a signed renewal request.

    NOTE: returns an SPKAC structure under pkcs10Data; the official daemon
    appears to return a PKCS#10 CSR. To be settled against a captured portal
    request before renewal flows are relied on.
    '''

    try:
        key_size = int(payload.get('keySize') or 2048)
    except (TypeError, ValueError):
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.bad-type')}

    key_id = (payload.get('serialNum') or 'btrust-renewal').encode('utf-8')[:16]

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    try:
        funcs = card_access._load_pkcs11()
    except backends.BackendUnavailable:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.no-card-found')}

    try:
        slots = hardware.get_slots(funcs, token_present=True)
        if not slots:
            return {'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.token-not-found')}

        spkac_b64 = hardware.generate_spkac(funcs, slots[0], pin, key_id, challenge='',
                                            key_size_bits=key_size)
        return {'pkcs10Data': spkac_b64, 'status': 'ok', 'reasonCode': 200,
                'reasonText': reason('response.success')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500,
                'reasonText': f"{reason('error.pkcs10.create-failed')}: {e}"}


def _not_implemented(req):
    return {'status': 'error', 'reasonCode': 501, 'reasonText': 'Not implemented in pybiss yet'}

# Endpoints the official daemon exposes that pybiss does not support yet:
#   setNewPUKNewPIN - resets PIN/PUK from factory defaults to server-chosen
#     random values RSA-encrypted back to the CA; only meaningful at issuance.
#   generatePfx / getPfxKeyPair - PKCS#12 needs symmetric crypto (AES/3DES)
#     absent from the standard library.
#   v2/renew - newer renew variant, not yet reverse-engineered.
for _path in ('/generatePfx', '/getPfxKeyPair', '/setNewPUKNewPIN', '/v2/renew'):
    app.post(_path)(_not_implemented)


@app.post('/writeCertSC')
@jws_gated()
def write_cert_sc(req, payload):

    # Real field is pemData (PEM or base64 DER); accept 'certificate' for own clients
    cert_blob = payload.get('pemData') or payload.get('certificate')
    if not cert_blob:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.mandatory-params')}

    try:
        ders = pem_to_der(cert_blob.encode('utf-8') if isinstance(cert_blob, str) else cert_blob)
        cert_der = ders[0] if ders and b'-----BEGIN' in (cert_blob.encode() if isinstance(cert_blob, str) else cert_blob) \
            else base64.b64decode(cert_blob)
    except Exception:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.certificate-not-valid')}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'confirm': None, 'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    try:
        card_service.import_certificate(cert_der, pin)
        return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/getInfo')
@jws_gated()
def get_info(req, payload):
    ''' Full token spec sheet, in the daemon's flat response shape '''

    try:
        info = card_service.token_info()
        provider = next((p for p in map(detector.identify_provider, detector.get_connected_atrs()) if p), '')
        # Flatten to the official C0030ai field names
        return {
            'tokenLabel': info.get('label', ''),
            'cardSerialNumber': info.get('serialNumber', ''),
            'manufacturerId': info.get('manufacturerID', ''),
            'model': info.get('model', ''),
            'producer': provider,
            'freePublicMemory': str(info.get('ulFreePublicMemory', '')),
            'totalPublicMemory': str(info.get('ulTotalPublicMemory', '')),
            'freePrivateMemory': str(info.get('ulFreePrivateMemory', '')),
            'totalPrivateMemory': str(info.get('ulTotalPrivateMemory', '')),
            'cardData': [],
            'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success'),
        }
    except backends.BackendUnavailable:
        return {'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.token-not-found')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/genRSAPair')
@jws_gated()
def gen_rsa_pair(req, payload):

    label = payload.get('label', 'B-Trust Generated Key')
    key_id = (payload.get('serNum') or payload.get('keyId') or 'btrust-key').encode('utf-8')[:16]
    try:
        key_size = int(payload.get('keySize') or 2048)
    except (TypeError, ValueError):
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.bad-type')}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        hardware.generate_rsa_keypair(funcs, slots[0], pin, label=label, key_id=key_id,
                                      key_size_bits=key_size)
        return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500,
                'reasonText': f"{reason('error.keypair.gen-failed')}: {e}"}


@app.post('/renew')
@jws_gated()
def renew_cert(req, payload):
    '''
    Generates a fresh key pair + renewal request for B-Trust portals.

    PARTIAL: the official renew response (C0044aw) also returns pkcs7Data,
    keyPairData and keyPairModule; this returns only the PKCS#10/SPKAC under
    pkcs10Data. To be completed against a captured portal request.
    '''

    try:
        key_size = int(payload.get('keySize') or 2048)
    except (TypeError, ValueError):
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.bad-type')}
    key_id = (payload.get('serNum') or payload.get('keyId') or 'RENEWAL').encode('utf-8')[:16]

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)
        spkac_b64 = hardware.generate_spkac(funcs, slots[0], pin, key_id, challenge='',
                                            key_size_bits=key_size)
        return {'pkcs10Data': spkac_b64, 'status': 'ok', 'reasonCode': 200,
                'reasonText': reason('response.success')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500,
                'reasonText': f"{reason('error.pkcs10.create-failed')}: {e}"}


# NOTE: the exact inner field name for the delete target (label vs id) should
# be confirmed against a captured portal request; 'label' is our own convention.
@app.post('/delRSAPair')
@jws_gated()
def del_rsa_pair(req, payload):

    label = payload.get('label')
    if not label:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.mandatory-params')}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)

        # Must attempt to delete both the Private and Public key objects
        priv_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_PRIVATE_KEY, label)
        pub_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_PUBLIC_KEY, label)

        if priv_deleted or pub_deleted:
            return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}
        return {'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.keypair.not-found')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


@app.post('/delCert')
@jws_gated()
def del_cert(req, payload):

    label = payload.get('label')
    if not label:
        return {'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.request.mandatory-params')}

    ui_provider = get_ui_provider()
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    lib_path = detector.auto_detect_library()
    try:
        funcs = hardware.load_pkcs11(lib_path)
        slots = hardware.get_slots(funcs, token_present=True)

        cert_deleted = hardware.delete_object_by_label(funcs, slots[0], pin, CKO_CERTIFICATE, label)
        if cert_deleted:
            return {'confirm': '0', 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}
        return {'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.no-certs-found')}
    except Exception as e:
        return {'status': 'error', 'reasonCode': 500, 'reasonText': str(e)}


def _aia_resolver():
    ''' Fetches missing issuer certs over AIA, caching into the user config dir. '''

    from . import chain_fetch
    return chain_fetch.make_aia_resolver(config.config_dir / 'ca_cache')


def _select_and_build_chain(filtered_certs, all_ders, ui_provider):
    ''' Shared getsigner tail: let the user choose, then return the full chain '''

    if not filtered_certs:
        return {'chain': [], 'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.no-certs-found')}
    choice_idx = ui_provider.choose_certificate(filtered_certs)
    if choice_idx == -1:
        return {'chain': [], 'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.user-canceled')}
    selected = filtered_certs[choice_idx]
    chain_ders = service.build_certificate_chain(selected['der'], all_ders, resolver=_aia_resolver())
    chain = [base64.b64encode(der).decode('utf-8') for der in chain_ders]
    return {'chain': chain, 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}


def _getsigner_cng(selector, show_valid_certs, ui_provider):
    if sys.platform != 'win32':
        raise backends.BackendUnavailable('CNG is Windows-only')
    from . import mscapi as mscapi
    raw_certs = mscapi.get_windows_certificates()
    try:
        filtered = service.filter_certificates(raw_certs, selector=selector, show_valid_certs=show_valid_certs)
        return _select_and_build_chain(filtered, [c['der'] for c in raw_certs], ui_provider)
    finally:
        for c in raw_certs:
            mscapi.free_windows_certificate(c['windows_ctx'])


def _getsigner_pkcs11(selector, show_valid_certs, ui_provider):
    funcs = card_access._load_pkcs11()
    slots = hardware.get_slots(funcs, token_present=True)
    if not slots:
        raise backends.BackendUnavailable('No token present')

    pin = ui_provider.prompt_pin()
    if not pin:
        return {'chain': [], 'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    all_certs = []
    for slot_id in slots:
        try:
            for c in hardware.get_certificates(funcs, slot_id, pin):
                c['slot_id'] = slot_id
                c['pin'] = pin
                all_certs.append(c)
        except Exception:
            continue

    filtered = service.filter_certificates(all_certs, selector=selector, show_valid_certs=show_valid_certs)
    return _select_and_build_chain(filtered, [c['der'] for c in all_certs], ui_provider)


def _getsigner_apdu(selector, show_valid_certs, ui_provider):
    ''' Read-only certificate discovery over raw APDU (no PIN, safe) '''

    from .cards import BTrustDriver

    try:
        conn_cm = card_access._open_card()
        conn = conn_cm.__enter__()
    except Exception as e:
        raise backends.BackendUnavailable(f'No card reachable over PC/SC or direct CCID: {e}')
    try:
        with conn.transaction():
            driver = BTrustDriver.create(conn)
            all_certs = [c for c in driver.discover_certificates() if c.get('der')]
        filtered = service.filter_certificates(all_certs, selector=selector, show_valid_certs=show_valid_certs)
        return _select_and_build_chain(filtered, [c['der'] for c in all_certs], ui_provider)
    finally:
        conn_cm.__exit__(None, None, None)


_GETSIGNER = {'cng': _getsigner_cng, 'pkcs11': _getsigner_pkcs11, 'apdu': _getsigner_apdu}


@app.post('/getsigner')
def get_signer(req):

    data = req.json
    selector = data.get('selector')
    show_valid_certs = data.get('showValidCerts', True)
    ui_provider = get_ui_provider()

    order = backends.resolve(backends.OP_READ, atr=card_access._detected_atr(), config=config)
    for name in order:
        try:
            return _GETSIGNER[name](selector, show_valid_certs, ui_provider)
        except backends.BackendUnavailable:
            continue
    return {'chain': [], 'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.no-card-found')}


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

    # Confirm signature request with the user via UI. The portal may set
    # confirmText to the literal "hash" to signal that the content itself IS a
    # hash. Otherwise confirmText is a human-readable message shown verbatim. 
    # additionalConfirmText, when present, is shown alongside it. (Unlike the daemon,
    # which skips the dialog when confirmText is absent, we always confirm - safer for
    # a QES token.)
    ui_provider = get_ui_provider()
    additional_confirm = data.get('additionalConfirmText')
    raw_confirm = confirm_text[0] if confirm_text else None

    if raw_confirm and raw_confirm.lower() == 'hash':
        tail = contents[0]
        confirm_msg = ('...' + tail[-20:]) if len(tail) > 20 else tail
    elif raw_confirm:
        confirm_msg = raw_confirm
    else:
        confirm_msg = 'Authorize signature request from banking portal?'

    confirmed = ui_provider.confirm_sign(confirm_msg, additional_confirm)
    if not confirmed:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'User rejected signature request'}

    # Parse the target signer certificate
    try:
        if not signer_cert_b64:
            raise ValueError('Signer certificate missing')
        signer_cert_der = base64.b64decode(signer_cert_b64)
    except Exception:
         return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': 'Invalid signer certificate encoding'}

    # Route to a signing backend per the resolver, falling through on unavailability
    order = backends.resolve(backends.OP_SIGN, atr=card_access._detected_atr(), config=config)
    for name in order:
        try:
            return _SIGN[name](contents, hash_algorithm, signer_cert_der, ui_provider)
        except backends.BackendUnavailable:
            continue
    return {'signatures': [], 'status': 'error', 'reasonCode': 400, 'reasonText': reason('error.no-card-found')}


def _sign_cng(contents, hash_algorithm, signer_cert_der, ui_provider):
    if sys.platform != 'win32':
        raise backends.BackendUnavailable('CNG is Windows-only')
    from . import mscapi as mscapi
    raw_certs = mscapi.get_windows_certificates()
    try:
        target_ctx = next((c['windows_ctx'] for c in raw_certs if c['der'] == signer_cert_der), None)
        if not target_ctx:
            return {'signatures': [], 'status': 'error', 'reasonCode': 404,
                    'reasonText': reason('error.token-not-found')}
        pin = ui_provider.prompt_pin()
        if not pin:
            return {'signatures': [], 'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}
        sigs = []
        for payload_b64 in contents:
            sig = mscapi.sign_payload_windows(cert_ctx_pointer=target_ctx,
                                              payload=base64.b64decode(payload_b64),
                                              pin=pin, hash_alg=hash_algorithm)
            sigs.append(base64.b64encode(sig).decode('utf-8'))
        return {'signatures': sigs, 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}
    except Exception as e:
        return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Signing failed: {e}'}
    finally:
        for c in raw_certs:
            mscapi.free_windows_certificate(c['windows_ctx'])


def _sign_pkcs11(contents, hash_algorithm, signer_cert_der, ui_provider):
    try:
        funcs = card_access._load_pkcs11()
    except backends.BackendUnavailable:
        raise
    except Exception as e:
        return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Failed to load PKCS11 driver: {e}'}

    slots = hardware.get_slots(funcs, token_present=True)
    pin = ui_provider.prompt_pin()
    if not pin:
        return {'signatures': [], 'status': 'error', 'reasonCode': 401, 'reasonText': reason('error.user-canceled')}

    target_slot = target_cert_id = None
    for slot_id in slots:
        try:
            for c in hardware.get_certificates(funcs, slot_id, pin):
                if c['der'] == signer_cert_der:
                    target_slot, target_cert_id = slot_id, c['id']
                    break
            if target_slot is not None:
                break
        except Exception:
            continue

    if target_slot is None:
        return {'signatures': [], 'status': 'error', 'reasonCode': 404, 'reasonText': reason('error.token-not-found')}

    sigs = []
    for payload_b64 in contents:
        try:
            sig = hardware.sign_payload(funcs=funcs, slot_id=target_slot, pin=pin,
                                        payload=base64.b64decode(payload_b64), key_id=target_cert_id)
            sigs.append(base64.b64encode(sig).decode('utf-8'))
        except Exception as e:
            return {'signatures': [], 'status': 'error', 'reasonCode': 500, 'reasonText': f'Signing failed: {e}'}
    return {'signatures': sigs, 'status': 'ok', 'reasonCode': 200, 'reasonText': reason('response.success')}


_APDU_HASH = {
    'SHA256': ('sha256', 0x42),   # (hashlib name, IDPrime algorithm reference)
    'SHA384': ('sha384', 0x52),
    'SHA512': ('sha512', 0x62),
}


def _sign_apdu(contents, hash_algorithm, signer_cert_der, ui_provider):
    ''' Raw-APDU signing for MiniDriver IDPrime cards '''

    algo = (hash_algorithm or 'SHA256').upper().replace('-', '')
    if algo not in _APDU_HASH:
        return {'signatures': [], 'status': 'error', 'reasonCode': 400,
                'reasonText': reason('error.signature-type-not-supported')}
    hash_name, algo_ref = _APDU_HASH[algo]

    try:
        conn_cm = card_access._open_card()
        conn = conn_cm.__enter__()
    except Exception as e:
        raise backends.BackendUnavailable(f'No card reachable over PC/SC or direct CCID: {e}')
    try:
        with conn.transaction():
            driver = BTrustDriver.create(conn)
            certs = driver.discover_certificates()
            target = next((c for c in certs
                           if c.get('der') == signer_cert_der and c.get('key_ref') is not None), None)
            if target is None:
                return {'signatures': [], 'status': 'error', 'reasonCode': 404,
                        'reasonText': reason('error.token-not-found')}

            pin = ui_provider.prompt_pin()
            if not pin:
                return {'signatures': [], 'status': 'error', 'reasonCode': 401,
                        'reasonText': reason('error.user-canceled')}

            # pin_index 1 = user PIN (0x11); otherwise the signature PIN (0x83)
            pin_ref = driver.PIN_REF_USER if target.get('pin_index') in (None, 1) else driver.PIN_REF_SIGNATURE
            try:
                driver.verify_pin(pin, pin_ref=pin_ref)
            except Exception as e:
                return {'signatures': [], 'status': 'error', 'reasonCode': 401, 'reasonText': str(e)}

            sigs = []
            for payload_b64 in contents:
                try:
                    digest = hashlib.new(hash_name, base64.b64decode(payload_b64)).digest()
                    driver.set_security_environment(target['key_ref'], algo_ref=algo_ref)
                    sig = driver.compute_signature(digest)
                    sigs.append(base64.b64encode(sig).decode('utf-8'))
                except Exception as e:
                    return {'signatures': [], 'status': 'error', 'reasonCode': 500,
                            'reasonText': f'Signing failed: {e}'}
            return {'signatures': sigs, 'status': 'ok', 'reasonCode': 200,
                    'reasonText': reason('response.success')}
    finally:
        conn_cm.__exit__(None, None, None)


_SIGN = {'cng': _sign_cng, 'pkcs11': _sign_pkcs11, 'apdu': _sign_apdu}


def serve(https: bool = True):
    '''
    HTTPS on the first free BISS port (53952-55), using a self-signed localhost cert that
    is minted on first run
    '''

    if not https:
        print('Starting pybiss in plain-HTTP mode on 127.0.0.1:4843 (dev / own clients).')
        app.run(host='127.0.0.1', port=4843)
        return

    port = transport.pick_free_port()
    certfile, keyfile = transport.ensure_localhost_cert(CERTS_DIR)
    print(f'Serving HTTPS on the BISS port {port}. If the browser rejects the '
          'certificate, run transport.install_trust_anchor() to trust it.')
    app.run(host='127.0.0.1', port=port, use_ssl=True, certfile=certfile, keyfile=keyfile)


if __name__ == '__main__':

    # Runs the server headlessly via CLI (BISS-compatible HTTPS).
    # For the full Desktop GUI: python -m src.dashboard
    serve(https='--http' not in sys.argv)