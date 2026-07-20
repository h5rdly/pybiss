import sys


# --- Operations ---
OP_READ = 'read'       # list / read certificates
OP_SIGN = 'sign'       # produce a signature
OP_PIN = 'pin'         # verify / change / unblock a PIN
OP_MANAGE = 'manage'   # keygen / write / delete on-card objects


# --- Backend capability sets ---
# CNG (Windows cert store + NCrypt): read + sign only - no public API for
#   PIN change/unblock or on-card object management.
# PKCS#11 (vendor middleware): the full set.
# Raw APDU (driver-free PC/SC): read + sign + PIN, but NOT management
#   (keygen / write need proprietary secure messaging we don't implement).
CAPABILITIES = {
    'cng':    frozenset({OP_READ, OP_SIGN}),
    'pkcs11': frozenset({OP_READ, OP_SIGN, OP_PIN, OP_MANAGE}),
    'apdu':   frozenset({OP_READ, OP_SIGN, OP_PIN}),
}

BACKENDS = tuple(CAPABILITIES)


def apdu_whitelist(config=None) -> set:
    ''' The set of ATRs (upper-case hex) the user has physically validated for the raw-APDU path '''

    raw = ''
    if config is not None:
        raw = config.get('apduWhitelist', '') or ''
    return {a.strip().upper() for a in raw.split(',') if a.strip()}


def known_apdu_atrs() -> set:
    '''
    ATRs the raw-APDU driver is explicitly written for: the IDPrime families
    B-Trust issues. Unknown families still need the explicit apduWhitelist opt-in.
    '''

    try:
        from .cards import IDPRIME_ATRS
    except Exception:                    # keep resolve() usable if the driver can't import
        return set()
    return {a.upper() for a in IDPRIME_ATRS}


def _primary(platform: str, sign_api: str) -> str:
    ''' The user-selected primary signing engine '''

    if platform == 'win32' and sign_api == 'MSCAPI':
        return 'cng'
    return 'pkcs11'


def resolve(operation: str, provider: str = None, atr: str = None,
            config=None, platform: str = None) -> list:
    '''
    Returns the ordered list of backends to try for `operation`, given the
    detected card and configuration. 
    '''

    platform = platform or sys.platform
    cfg = config or {}
    sign_api = cfg.get('signAPI', 'PKCS11') if cfg else 'PKCS11'
    primary = _primary(platform, sign_api)

    # Known IDPrime-family cards are auto-trusted; strangers need the config opt-in.
    atr_up = (atr or '').upper()
    whitelisted = atr_up in apdu_whitelist(cfg) or atr_up in known_apdu_atrs()

    if platform == 'win32':
        # Windows - keep the OS engines first, APDU is a fallback
        order = [primary, 'cng' if primary != 'cng' else 'pkcs11', 'apdu']
    else:
        # No CNG off Windows. Prefer validated APDU (driver-free), else PKCS#11.
        order = (['apdu', 'pkcs11'] if whitelisted else ['pkcs11'])

    # APDU only for validated cards
    if not whitelisted:
        order = [b for b in order if b != 'apdu']

    # Capability filter, preserving order and dropping duplicates
    seen = set()
    result = []
    for b in order:
        if b in seen:
            continue
        seen.add(b)
        if operation in CAPABILITIES.get(b, frozenset()):
            result.append(b)
    return result


class BackendUnavailable(Exception):
    ''' Not raised for a valid empty result '''
