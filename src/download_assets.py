import urllib.request
import os, io, hashlib, tarfile
import shutil, subprocess


BISS_DEB_URL = 'https://www.b-trust.bg/attachments/BtrustPrivateFile/24/docs/B-TrustBISS.tar'
BISS_WIN_URL = 'https://www.b-trust.bg/attachments/BtrustPrivateFile/22/docs/BissSetup.exe'

ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'assets')

# Pinned SHA-256 of vetted driver builds. A mismatch means B-Trust published
# a new build - vet it manually before adding its hash here.
KNOWN_DRIVER_SHA256 = {
    # 'libcvP11.so': '<sha256 of vetted build>',
    # 'cvP11.dll': '<sha256 of vetted build>',
}

# NOTE: these downloads fetch and store executable code. Callers should get
# explicit user consent before invoking them.


def _verify_and_write(data: bytes, driver_name: str, output_path: str):
    ''' Writes the driver only if its hash matches a vetted build (when pinned) '''

    digest = hashlib.sha256(data).hexdigest()
    expected = KNOWN_DRIVER_SHA256.get(driver_name)

    if expected is None:
        print(f'[!] No pinned hash for {driver_name} (sha256: {digest}). Vet it before trusting it.')
    elif digest != expected.lower():
        raise Exception(
            f'{driver_name} hash mismatch: got {digest}, expected {expected}. '
            'B-Trust may have published a new build - do not use it unvetted.'
        )

    with open(output_path, 'wb') as f:
        f.write(data)
    print(f'[+] Successfully extracted {output_path}')


def download_linux_driver(url: str = BISS_DEB_URL, driver_name: str = 'libcvP11.so', output_path: str = None):

    output_path = output_path or os.path.join(ASSETS_DIR, driver_name)

    print('Downloading official B-Trust Linux package...')

    with urllib.request.urlopen(url) as response:
        tar_data = response.read()

    # Extract the .deb file from the outer tar archive
    with tarfile.open(fileobj=io.BytesIO(tar_data)) as outer_tar:
        deb_name = [n for n in outer_tar.getnames() if n.endswith('.deb')][0]
        deb_bytes = outer_tar.extractfile(deb_name).read()

    # Parse the .deb (ar archive) in memory to get data.tar.xz
    # Format starts with '!<arch>\n' (8 bytes)
    pos = 8
    data_tar_xz = None
    while pos < len(deb_bytes):
        # Header is 60 bytes: filename(16), time(12), uid(6), gid(6), mode(8), size(10), magic(2)
        header = deb_bytes[pos:pos+60]
        if len(header) < 60:
            break
        name = header[:16].decode('ascii').strip()
        size = int(header[48:58].decode('ascii').strip())
        pos += 60

        if name.startswith('data.tar.xz'):
            data_tar_xz = deb_bytes[pos:pos+size]
            break

        pos += size + (size % 2)  # files align to 2-byte boundaries

    if not data_tar_xz:
        raise Exception('Could not locate data.tar.xz inside the deb package.')

    # Open the data tarball and extract the driver library
    with tarfile.open(fileobj=io.BytesIO(data_tar_xz)) as inner_tar:
        so_member = [m for m in inner_tar.getmembers() if m.name.endswith(driver_name)][0]
        _verify_and_write(inner_tar.extractfile(so_member).read(), driver_name, output_path)


def download_windows_driver(url: str = BISS_WIN_URL, driver_name: str = 'cvP11.dll', output_path: str = None):

    output_path = output_path or os.path.join(ASSETS_DIR, driver_name)
    exe_path = 'BissSetup.exe'
    temp_dir = 'temp_extract'

    print('Downloading official B-Trust Windows installer...')
    urllib.request.urlretrieve(url, exe_path)

    print('Extracting files silently using msiexec...')
    try:
        # /a runs administrative extraction to TARGETDIR
        subprocess.run([
            'msiexec', '/a', exe_path, '/qn', f'TARGETDIR={os.path.abspath(temp_dir)}'
        ], check=True)

        # Search the extracted folder for the dll
        found_dll = None
        for root, _, files in os.walk(temp_dir):
            if driver_name in files:
                found_dll = os.path.join(root, driver_name)
                break

        if found_dll:
            with open(found_dll, 'rb') as f:
                _verify_and_write(f.read(), driver_name, output_path)
        else:
            print(f'[-] Could not find {driver_name} in the installer database.')
    finally:
        # Cleanup temp installer and extracted folders
        if os.path.exists(exe_path):
            os.remove(exe_path)
        shutil.rmtree(temp_dir, ignore_errors=True)
