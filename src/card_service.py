''' card-management API for the GUI / daemon '''


from . import backends, detector, hardware
from .config import config as _config
from .card_access import _open_card, _detected_atr


# --- engine plumbing --------------------------------------------------------

def _pkcs11_session(cfg):
    ''' (funcs, slot_id) for the detected token; BackendUnavailable if none. '''

    lib = ((cfg or _config).get('pkcs11Path') or '') or detector.auto_detect_library()
    if not lib:
        raise backends.BackendUnavailable('No PKCS#11 library for the detected card')
    funcs = hardware.load_pkcs11(lib)
    slots = hardware.get_slots(funcs, token_present=True)
    if not slots:
        raise backends.BackendUnavailable('No token present in the reader')
    return funcs, slots[0]


def _with_apdu_driver(fn):
    ''' Open a PC/SC (or direct-CCID) card, run fn(driver), guarantee cleanup. '''

    from .cards import BTrustDriver
    try:
        cm = _open_card()
        conn = cm.__enter__()
    except Exception as e:
        raise backends.BackendUnavailable(f'No card reachable over PC/SC or CCID: {e}')
    try:
        with conn.transaction():
            return fn(BTrustDriver.create(conn))
    finally:
        cm.__exit__(None, None, None)


def _dispatch(order, impls, what):
    ''' Try each resolved backend in order '''

    if not order:
        raise backends.BackendUnavailable(f'no backend can {what} for this card')
    last = None
    for name in order:
        impl = impls.get(name)
        if impl is None:
            continue                       # engine can't do this op (capability filtered)
        try:
            return impl()
        except backends.BackendUnavailable as e:
            last = e                        # engine unusable - safe to try the next
            continue
    raise last or backends.BackendUnavailable(f'no usable backend to {what}')


def _order(op, atr, cfg):
    return backends.resolve(op, atr=(atr or _detected_atr()), config=(cfg or _config))


# --- public API -------------------------------------------------------------

def change_pin(old_pin, new_pin, atr=None, cfg=None):
    ''' Change the user PIN via whichever engine the card resolves to. '''

    return _dispatch(_order(backends.OP_PIN, atr, cfg), {
        'apdu':   lambda: _with_apdu_driver(lambda d: d.change_pin(old_pin, new_pin)),
        'pkcs11': lambda: _pkcs11_change_pin(old_pin, new_pin, cfg),
    }, 'change the PIN')


def unblock_pin(puk, new_pin, atr=None, cfg=None):
    ''' Unblock the PIN with the PUK via the resolved engine. '''

    return _dispatch(_order(backends.OP_PIN, atr, cfg), {
        'apdu':   lambda: _with_apdu_driver(lambda d: d.unblock_pin(puk, new_pin)),
        'pkcs11': lambda: _pkcs11_unblock(puk, new_pin, cfg),
    }, 'unblock the PIN')


def change_puk(old_puk, new_puk, atr=None, cfg=None):
    ''' Change the PUK. PKCS#11 only - the raw-APDU driver has no PUK-change
        (it lacks the 'apdu' impl, so _dispatch routes straight to PKCS#11). '''

    return _dispatch(_order(backends.OP_PIN, atr, cfg), {
        'pkcs11': lambda: _pkcs11_change_puk(old_puk, new_puk, cfg),
    }, 'change the PUK')


def read_certificates(pin=None, atr=None, cfg=None):
    ''' List certificates. APDU discovers public certs (no PIN); PKCS#11 logs in. '''

    return _dispatch(_order(backends.OP_READ, atr, cfg), {
        'apdu':   lambda: _with_apdu_driver(lambda d: d.discover_certificates()),
        'pkcs11': lambda: _pkcs11_certs(pin, cfg),
    }, 'read certificates')


def import_certificate(cert_der, pin, atr=None, cfg=None):
    ''' Write a certificate to the card. Only PKCS#11 advertises OP_MANAGE. '''

    return _dispatch(_order(backends.OP_MANAGE, atr, cfg), {
        'pkcs11': lambda: _pkcs11_write_cert(cert_der, pin, cfg),
    }, 'import a certificate')


def token_info(atr=None, cfg=None):
    '''
    A dict of token facts. Informational, so it prefers the richer PKCS#11
    source and falls back to the APDU basics - it is not a security operation.
    '''

    resolved = set(_order(backends.OP_READ, atr, cfg))
    order = [b for b in ('pkcs11', 'apdu') if b in resolved]
    return _dispatch(order, {
        'pkcs11': lambda: _pkcs11_token_info(cfg),
        'apdu':   lambda: _apdu_token_info(atr),
    }, 'read token info')


# --- per-engine implementations ---------------------------------------------

def _pkcs11_change_pin(old, new, cfg):
    funcs, slot = _pkcs11_session(cfg)
    hardware.change_card_pin(funcs, slot_id=slot, old_pin=old, new_pin=new)


def _pkcs11_unblock(puk, new, cfg):
    funcs, slot = _pkcs11_session(cfg)
    hardware.unblock_card_pin(funcs, slot_id=slot, puk=puk, new_pin=new)


def _pkcs11_change_puk(old, new, cfg):
    funcs, slot = _pkcs11_session(cfg)
    hardware.change_card_puk(funcs, slot_id=slot, old_puk=old, new_puk=new)


def _pkcs11_certs(pin, cfg):
    funcs, slot = _pkcs11_session(cfg)
    return hardware.get_certificates(funcs, slot_id=slot, pin=pin)


def _pkcs11_write_cert(cert_der, pin, cfg):
    funcs, slot = _pkcs11_session(cfg)
    hardware.write_certificate(funcs, slot_id=slot, pin=pin, cert_der=cert_der)


def _pkcs11_token_info(cfg):
    funcs, slot = _pkcs11_session(cfg)
    info = dict(hardware.get_token_info_extended(funcs, slot_id=slot))
    info.setdefault('serial', hardware.get_token_serial_number(funcs, slot_id=slot))
    return info


def _apdu_token_info(atr):
    return {'atr': (atr or _detected_atr()), 'engine': 'apdu',
            'note': 'raw-APDU path: detailed token info needs PKCS#11'}
