import json, sys, urllib.error, urllib.request
from decimal import Decimal, InvalidOperation
from urllib.parse import quote


VERSION_SERVICE_URL = 'https://store.borica.bg/bg/b-trust/certificates/bissversion?os='


def _os_token() -> str:
    ''' The value btrustbiss sends; the store only checks that it is non-empty. '''

    if sys.platform.startswith('win'):
        return 'windows'
    if sys.platform == 'darwin':
        return 'mac'
    return 'linux'


def _is_newer(latest: str, current: str) -> bool:
    try:
        return Decimal(latest) > Decimal(current)
    except (InvalidOperation, TypeError):
        return False


def check_for_update(current_version: str, *, os_token: str = None, timeout: float = 4) -> dict | None:
    ''' Ask the store for the latest published BISS version '''

    url = VERSION_SERVICE_URL + quote(os_token or _os_token())
    req = urllib.request.Request(url, headers={
        'Accept': 'application/json',
        'User-Agent': f'pybiss/{current_version}',
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode('utf-8', 'replace')
        data = json.loads(body)                 # Content-Type says html, body is json
        latest = str(data['bissVersion'])
    except (urllib.error.URLError, OSError, ValueError, KeyError, TimeoutError):
        return None

    return {
        'latest': latest,
        'download_link': data.get('downloadLink'),
        'is_newer': _is_newer(latest, current_version),
    }


def format_banner(current_version: str, result: dict | None) -> str | None:

    if result is None:
        return None
    if result['is_newer']:
        link = result.get('download_link') or 'https://www.b-trust.bg'
        return (f"A newer B-Trust BISS version is available: {result['latest']} "
                f"(you target {current_version}). See {link}")
    return None


if __name__ == '__main__':
    
    current = sys.argv[1] if len(sys.argv) > 1 else '3.46'
    result = check_for_update(current)
    if result is None:
        sys.exit('check failed (offline, or the store did not answer)')
    print(f"we mirror : {current}")
    print(f"store has : {result['latest']}")
    print(f"download  : {result.get('download_link')}")
    print('NEWER BUILD OUT - go decompile it' if result['is_newer'] else 'we are current')
