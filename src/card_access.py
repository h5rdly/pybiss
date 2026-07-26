from . import backends, detector, hardware


def _detected_atr() -> str:
    ''' First connected card ATR (upper hex), or '' - used to pick a backend '''

    try:
        atrs = detector.get_connected_atrs(ccid_fallback=True)
        return atrs[0].upper() if atrs else ''
    except Exception:
        return ''


def _load_pkcs11():
    ''' Resolve the vendor library and return its PKCS#11 function table. '''

    lib_path = detector.auto_detect_library()
    if not lib_path:
        raise backends.BackendUnavailable('No PKCS#11 library for the detected card')
    return hardware.load_pkcs11(lib_path)


def _pcsc_factory():
    from .sc_ffi import SmartCardConnection
    return SmartCardConnection()


def _ccid_factory():
    from .ccid import CcidConnection
    return CcidConnection()


class CardUnreachable(Exception):
    ''' Neither PC/SC nor direct CCID could reach a card; carries both reasons '''

    def __init__(self, pcsc_error, ccid_error):
        self.pcsc_error, self.ccid_error = pcsc_error, ccid_error
        super().__init__(f'PC/SC: {pcsc_error} | direct CCID: {ccid_error}')


class _CardConnection:
    ''' Open the card over PC/SC, falling back to direct USB CCID '''

    def __init__(self, pcsc_factory=_pcsc_factory, ccid_factory=_ccid_factory):
        self._pcsc_factory, self._ccid_factory = pcsc_factory, ccid_factory
        self._inner = None

    def __enter__(self):
        try:
            inner = self._pcsc_factory()
            conn = inner.__enter__()
        except Exception as pcsc_error:
            try:
                inner = self._ccid_factory()
                conn = inner.__enter__()
            except Exception as ccid_error:
                raise CardUnreachable(pcsc_error, ccid_error) from ccid_error
        self._inner = inner
        return conn

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc) if self._inner is not None else False


def _open_card():
    return _CardConnection()
