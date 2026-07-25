'''
Optionally fetch a good UI font (Hack) at runtime
'''

import hashlib
import io
import os
import sys
import zipfile
import urllib.request
from pathlib import Path


HACK_URL = 'https://github.com/source-foundry/Hack/releases/download/v3.003/Hack-v3.003-ttf.zip'
HACK_SHA256 = '0c2604631b1f055041c68a0e09ae4801acab6c5072ba2db6a822f53c3f8290ac'
HACK_FAMILY = 'Hack'

# The four styles inside the zip (a UI needs at least Regular + Bold).
_MEMBERS = ('ttf/Hack-Regular.ttf', 'ttf/Hack-Bold.ttf',
            'ttf/Hack-Italic.ttf', 'ttf/Hack-BoldItalic.ttf')


def user_font_dir() -> Path:
    ''' Per-user font directory - writable without admin on every platform. '''

    if sys.platform.startswith('win'):
        base = os.environ.get('LOCALAPPDATA') or str(Path.home())
        return Path(base) / 'Microsoft' / 'Windows' / 'Fonts'
    if sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Fonts'
    base = os.environ.get('XDG_DATA_HOME') or str(Path.home() / '.local' / 'share')
    return Path(base) / 'fonts'


def _register_windows(paths):
    ''' Make freshly-dropped TTFs usable THIS session (no logout) - AddFontResourceExW. '''

    import ctypes
    FR_PRIVATE = 0x10
    gdi = ctypes.windll.gdi32
    for p in paths:
        gdi.AddFontResourceExW(ctypes.c_wchar_p(str(p)), FR_PRIVATE, 0)


def hack_available() -> bool:
    ''' Whether the running Tk can already see the Hack family (needs a Tk root). '''

    from tkinter import font as tkfont
    try:
        return HACK_FAMILY.lower() in {f.lower() for f in tkfont.families()}
    except RuntimeError:                       # no default root yet
        return False


def download_hack(url: str = HACK_URL, timeout: float = 60) -> dict:
    '''
    Download + hash-verify the Hack zip, install its four TTFs into the user font
    dir, and on Windows register them for this session
    '''

    with urllib.request.urlopen(url, timeout=timeout) as resp:
        data = resp.read()

    digest = hashlib.sha256(data).hexdigest()
    if digest != HACK_SHA256:
        raise ValueError(f'Hack zip hash mismatch: got {digest}, expected {HACK_SHA256}. '
                         'Upstream may have republished - re-vet before trusting it.')

    dest = user_font_dir()
    dest.mkdir(parents=True, exist_ok=True)
    installed = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for member in _MEMBERS:
            out = dest / Path(member).name
            out.write_bytes(z.read(member))
            installed.append(out)

    session_ready = False
    if sys.platform.startswith('win'):
        try:
            _register_windows(installed)
            session_ready = True
        except Exception:
            session_ready = False
    else:
        # Refresh fontconfig if it is present; Tk may still need a restart.
        import shutil, subprocess
        if shutil.which('fc-cache'):
            subprocess.run(['fc-cache', '-f', str(dest)], capture_output=True)

    return {'family': HACK_FAMILY, 'installed': installed, 'session_ready': session_ready}
