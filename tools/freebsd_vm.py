'''
FreeBSD test rig for pybiss - pure stdlib, mirrors the CI leg exactly.

The GitHub workflow's FreeBSD job (vmactions/freebsd-vm) is QEMU + SSH under
the hood, so this local VM is the same machine shape as CI, not an
approximation. Same release, same packages, same Xvfb run block.

Typical use:
    python tools/freebsd_vm.py test        # does everything: setup -> boot ->
                                           # provision -> sync repo -> run suite
    python tools/freebsd_vm.py ssh         # interactive shell in the VM
    python tools/freebsd_vm.py stop        # shut the VM down
    python tools/freebsd_vm.py reset       # fresh disk from the pristine base

All artifacts live in ~/.cache/pybiss/freebsd-vm/ (never in the repo). The
downloaded base image stays pristine; the VM runs on an overlay (qemu-img) or
a sparse copy of it, so `reset` is cheap and never re-downloads.

Requirements: qemu-system-x86_64, ssh/ssh-keygen (openssh). KVM is used when
/dev/kvm is accessible, else falls back to TCG (slow but works).
'''

import argparse, hashlib, lzma, os, re, shutil, socket, subprocess, sys, time, urllib.request
from pathlib import Path


# --- Constants mirroring .github/workflows/tests.yml -----------------------
# CI does not pin a release (tracks vmactions' default); keep this matching
# whatever that default currently is so local repro equals the CI leg.
RELEASE = '15.1'
ARCH = 'amd64'
PACKAGES = 'python314 py314-tkinter pcsc-lite xorg-vfbserver dejavu'
# NB: `cd X; Y &` not `cd X && Y &` - with &&, the & backgrounds the WHOLE
# compound (cd included, in a throwaway subshell) and the commands after it
# run from the login directory instead.
TEST_CMD = (
    'cd /root/pybiss; '
    'Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 & XVFB_PID=$!; sleep 2; '
    'cd /root/pybiss && DISPLAY=:99 python3.14 -m unittest discover tests; rc=$?; '
    'kill $XVFB_PID 2>/dev/null; exit $rc'
)

# The BASIC-CLOUDINIT variant, deliberately - but NOT for cloud-init. Probed
# facts from both images on this machine: the plain VM image sends its console
# to VGA only (automated serial login reads zero bytes), while the CLOUDINIT
# variant mirrors the whole boot to the serial port AND runs a getty on ttyu0.
# The cloud-init/NoCloud-over-SMBIOS route itself is a dead end here: FreeBSD
# 14's smbios(4) rejects QEMU's entry point ("Invalid length: Got 101,
# expected 24") even with -machine smbios-entry-point-type=32, so the kernel
# never exposes the ds=nocloud serial. Hence: this image, provisioned by
# scripting its serial console.
IMAGE = f'FreeBSD-{RELEASE}-RELEASE-{ARCH}-BASIC-CLOUDINIT-ufs.qcow2'
BASE_URL = f'https://download.freebsd.org/releases/VM-IMAGES/{RELEASE}-RELEASE/{ARCH}/Latest/'

CACHE = Path.home() / '.cache' / 'pybiss' / 'freebsd-vm'
BASE_IMG = CACHE / f'{IMAGE}.base'       # pristine, never booted
WORK_IMG = CACHE / 'work.qcow2'          # what the VM actually runs on
# The stock image's filesystem is ~6GB and pkg's dependency tree (xorg pulls
# mesa pulls llvm) needs ~3GB more. Growing the qcow2 needs qemu-img; a
# second RAW disk needs only os.truncate - the guest newfs's it and mounts
# it as /usr/local, which is where every package byte goes anyway.
DATA_IMG = CACHE / 'data.raw'            # sparse; becomes /usr/local
DATA_SIZE = 24 << 30
SSH_KEY = CACHE / 'id_ed25519'
PID_FILE = CACHE / 'qemu.pid'
CONSOLE_LOG = CACHE / 'console.log'
PROVISIONED = CACHE / '.provisioned'     # marker: sshd + packages ready

SSH_PORT = 10122
SERIAL_PORT = 10123
REPO = Path(__file__).resolve().parent.parent


def log(msg):
    print(f'[freebsd-vm] {msg}', flush=True)


def run(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


# --- setup: download, verify, decompress, key ------------------------------

def fetch_expected_sha256(filename):
    ''' The release directory publishes CHECKSUM.SHA256 in BSD digest format:
        SHA256 (file) = hex '''

    with urllib.request.urlopen(BASE_URL + 'CHECKSUM.SHA256', timeout=60) as r:
        text = r.read().decode()
    m = re.search(rf'SHA256 \({re.escape(filename)}\) = ([0-9a-f]{{64}})', text)
    if not m:
        sys.exit(f'checksum for {filename} not found in CHECKSUM.SHA256')
    return m.group(1)


def download_and_unpack():
    xz_name = IMAGE + '.xz'
    xz_path = CACHE / xz_name
    if BASE_IMG.exists():
        log(f'base image already present: {BASE_IMG}')
        return

    if not xz_path.exists():
        log(f'downloading {BASE_URL}{xz_name} (several hundred MB)...')
        tmp = xz_path.with_suffix('.part')
        with urllib.request.urlopen(BASE_URL + xz_name, timeout=60) as r, open(tmp, 'wb') as out:
            total = int(r.headers.get('Content-Length', 0))
            done = 0
            while chunk := r.read(1 << 20):
                out.write(chunk)
                done += len(chunk)
                if total:
                    print(f'\r  {done // (1 << 20)} / {total // (1 << 20)} MiB', end='', flush=True)
        print()
        tmp.rename(xz_path)

    log('verifying sha256 against CHECKSUM.SHA256...')
    expected = fetch_expected_sha256(xz_name)
    h = hashlib.sha256()
    with open(xz_path, 'rb') as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    if h.hexdigest() != expected:
        xz_path.unlink()
        sys.exit('checksum MISMATCH - deleted the download, run setup again')
    log('checksum OK')

    log('decompressing (stdlib lzma)...')
    with lzma.open(xz_path) as src, open(BASE_IMG, 'wb') as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    xz_path.unlink()                      # keep only the pristine base
    log(f'base image ready: {BASE_IMG}')


def ensure_key():
    if not SSH_KEY.exists():
        run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'pybiss-freebsd-vm',
             '-f', str(SSH_KEY)], check=True, capture_output=True)
        log(f'generated dedicated SSH key: {SSH_KEY}')


def ensure_data_image(fresh=False):
    if DATA_IMG.exists() and fresh:
        DATA_IMG.unlink()
    if not DATA_IMG.exists():
        with open(DATA_IMG, 'wb') as fh:
            fh.truncate(DATA_SIZE)       # sparse: costs nothing until used
        log(f'data disk created (sparse {DATA_SIZE >> 30}G, guest /usr/local)')


def ensure_work_image(fresh=False):
    ensure_data_image(fresh)
    if WORK_IMG.exists() and not fresh:
        return
    if WORK_IMG.exists():
        WORK_IMG.unlink()
        PROVISIONED.unlink(missing_ok=True)
    if shutil.which('qemu-img'):
        run(['qemu-img', 'create', '-f', 'qcow2', '-b', str(BASE_IMG),
             '-F', 'qcow2', str(WORK_IMG)], check=True, capture_output=True)
        log('work image: qcow2 overlay over the pristine base')
    else:
        # No qemu-img on this host: sparse-copy the base instead (cp keeps
        # holes; shutil.copy would materialise them).
        run(['cp', '--sparse=always', '--reflink=auto', str(BASE_IMG), str(WORK_IMG)],
            check=True)
        log('work image: sparse copy of the base (qemu-img not installed)')


def cmd_setup(args):
    CACHE.mkdir(parents=True, exist_ok=True)
    download_and_unpack()
    ensure_key()
    ensure_work_image()


# --- boot / stop / status ---------------------------------------------------

def vm_pid():
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def usb_passthrough_args(spec):
    '''
    Hand a host USB device to the guest: --usb VID:PID (hex, e.g. 31aa:7001).

    This is how the FreeBSD ugen(4) backend in src/ccid.py gets exercised for
    real: run tests/test_utils/f_ccid.py on the host to conjure a virtual CCID reader on
    dummy_hcd, pass it through here, and FreeBSD attaches it to ugen - no
    physical hardware anywhere in the loop. QEMU must be able to open the node
    (/dev/bus/usb/BBB/DDD) and no host driver may hold it (stop pcscd first).
    '''

    if not spec:
        return []
    try:
        vid, pid = spec.split(':')
        int(vid, 16), int(pid, 16)
    except ValueError:
        sys.exit(f'--usb wants VID:PID in hex, e.g. 31aa:7001 (got {spec!r})')
    return ['-device', 'qemu-xhci,id=xhci',
            '-device', f'usb-host,bus=xhci.0,vendorid=0x{vid},productid=0x{pid}']


def cmd_boot(args):
    if vm_pid():
        log(f'already running (pid {vm_pid()})')
        return
    cmd_setup(args)

    accel = ['-accel', 'kvm'] if os.access('/dev/kvm', os.R_OK | os.W_OK) else ['-accel', 'tcg']
    if accel[1] == 'tcg':
        log('WARNING: /dev/kvm not accessible - falling back to TCG (slow)')

    usb = usb_passthrough_args(getattr(args, 'usb', None))
    if usb:
        log(f'passing host USB device {args.usb} through to the guest')

    qemu = [
        'qemu-system-x86_64', *accel, '-m', '2048', '-smp', '2',
        '-drive', f'file={WORK_IMG},if=virtio,format=qcow2',
        '-drive', f'file={DATA_IMG},if=virtio,format=raw',
        '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
        '-device', 'virtio-net-pci,netdev=n0',
        *usb,
        '-display', 'none',
        # Unprovisioned: expose the serial console on TCP so provision can
        # script the ttyu0 login. Afterwards just log it to a file.
        '-serial', (f'tcp:127.0.0.1:{SERIAL_PORT},server=on,wait=off'
                    if not PROVISIONED.exists() else f'file:{CONSOLE_LOG}'),
        '-pidfile', str(PID_FILE),
        '-daemonize',
    ]
    run(qemu, check=True)
    log(f'booted (ssh forwarded to 127.0.0.1:{SSH_PORT})')


def cmd_stop(args):
    pid = vm_pid()
    if not pid:
        log('not running')
        return
    ssh_run('shutdown -p now', check=False, quiet=True, timeout=20)
    for _ in range(30):
        if not vm_pid():
            log('VM powered off')
            return
        time.sleep(1)
    os.kill(pid, 15)
    log('sent SIGTERM to qemu')


def cmd_status(args):
    pid = vm_pid()
    log(f'running (pid {pid})' if pid else 'not running')
    log(f'base: {"yes" if BASE_IMG.exists() else "no"}   '
        f'work: {"yes" if WORK_IMG.exists() else "no"}   '
        f'provisioned: {"yes" if PROVISIONED.exists() else "no"}')


def cmd_reset(args):
    if vm_pid():
        cmd_stop(args)
    ensure_work_image(fresh=True)
    log('work image recreated from pristine base (re-provision on next test)')


# --- first-boot provisioning over the serial console -------------------------

class SerialConsole:
    ''' Minimal expect-loop over QEMU's TCP serial port. Everything read is
        appended to console.log so a failed provision is diagnosable. '''

    def __init__(self):
        self.sock = socket.create_connection(('127.0.0.1', SERIAL_PORT), timeout=5)
        self.sock.settimeout(1)
        self.log = open(CONSOLE_LOG, 'ab')

    def expect(self, patterns, timeout):
        ''' Wait until any of `patterns` (bytes) appears; returns the match '''

        buf = b''
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = self.sock.recv(4096)
                if not data:
                    time.sleep(0.2)
                    continue
                self.log.write(data)
                self.log.flush()
                buf += data
                buf = buf[-16384:]
                for p in patterns:
                    if p in buf:
                        return p
            except socket.timeout:
                continue
        raise TimeoutError(f'serial console: none of {patterns} within {timeout}s '
                           f'(see {CONSOLE_LOG})')

    def send(self, line):
        self.sock.sendall(line.encode() + b'\r')

    def close(self):
        self.sock.close()
        self.log.close()


def provision_serial():
    '''
    The image ships with sshd running but no authorized keys and root-only
    accounts, so SSH is reachable yet unusable. Root logs into the serial
    console (empty password on stock images); do the minimum there -
    authorized key + PermitRootLogin - then switch to SSH for real work.
    '''

    log('waiting for the login prompt on the serial console...')
    con = SerialConsole()
    try:
        # The prompt pattern must be the FULL prompt: a bare b'root@' also
        # matches sshd's first-boot host-key fingerprints ('root@freebsd
        # (ECDSA)'), which once tricked this into typing shell commands
        # into the login prompt.
        PROMPT = b'root@freebsd:~ #'
        con.sock.sendall(b'\x15\r')        # ^U: discard any half-typed junk
        # A fresh boot shows 'login:'; a session left over from an earlier
        # provision attempt is already sitting at the root prompt.
        got = con.expect([b'login:', PROMPT], timeout=300)
        if got == b'login:':
            con.send('root')
            got = con.expect([b'Password:', PROMPT], timeout=60)
            if got == b'Password:':
                con.send('')               # empty password on stock VM images
                con.expect([PROMPT], timeout=60)
        log('logged in on serial; installing SSH key...')

        pubkey = SSH_KEY.with_suffix('.pub').read_text().strip()
        steps = [
            'mkdir -p /root/.ssh && chmod 700 /root/.ssh',
            f"echo '{pubkey}' > /root/.ssh/authorized_keys",
            'chmod 600 /root/.ssh/authorized_keys',
            # sshd honours the FIRST PermitRootLogin it sees, and the
            # CLOUDINIT image ships its own directives - an appended line
            # silently loses. Replace in place; append only if absent.
            "sed -i '' 's/^#*[[:space:]]*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
            "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config",
            'sysrc sshd_enable=YES',
            'service sshd restart || service sshd start',
        ]
        # One command per line, each awaited on the returning prompt: a joined
        # one-liner overflows the tty's canonical input buffer and is silently
        # truncated mid-command (observed at ~430 chars).
        for step in steps:
            con.send(step)
            con.expect([PROMPT], timeout=60)
        # The tty echoes everything we type, so a plain marker would match its
        # own echo before (and regardless of) execution. The quotes keep the
        # marker out of the typed line; only real output contains it.
        con.send("echo PROVISION''-OK")
        con.expect([b'PROVISION-OK'], timeout=60)
        log('ssh key installed, sshd restarted')
    finally:
        con.close()


def ssh_base():
    return ['ssh', '-i', str(SSH_KEY), '-p', str(SSH_PORT),
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=10', 'root@127.0.0.1']


def ssh_run(command, check=True, quiet=False, timeout=None):
    kwargs = {'timeout': timeout} if timeout else {}
    if quiet:
        kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return run(ssh_base() + [command], check=check, **kwargs)


def wait_for_ssh(timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ssh_run('true', quiet=True, timeout=10)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            time.sleep(3)
    sys.exit('SSH never came up - inspect ' + str(CONSOLE_LOG))


def cmd_provision(args):
    cmd_boot(args)
    if PROVISIONED.exists():
        wait_for_ssh()               # a cold boot needs time to reach sshd
        log('already provisioned')
        return
    provision_serial()
    wait_for_ssh()
    log('formatting the data disk as /usr/local...')
    ssh_run('mount | grep -q "on /usr/local" || ('
            'newfs -U /dev/vtbd1 >/dev/null && '
            "echo '/dev/vtbd1 /usr/local ufs rw 2 2' >> /etc/fstab && "
            'mount /usr/local)')
    log(f'installing packages (mirrors tests.yml): {PACKAGES}')
    # PKG_CACHEDIR: the download cache defaults to /var (on the small root
    # filesystem) - point it at the roomy data disk as well.
    ssh_run('mkdir -p /usr/local/pkg-cache && '
            'env ASSUME_ALWAYS_YES=yes PKG_CACHEDIR=/usr/local/pkg-cache '
            f'sh -c "pkg bootstrap -f && pkg install -y {PACKAGES}"')
    PROVISIONED.touch()
    log('provisioned')


# --- sync + test -------------------------------------------------------------

def cmd_sync(args):
    ''' Ship the working tree (minus junk) into /root/pybiss via tar-over-ssh '''

    log(f'syncing {REPO} -> vm:/root/pybiss')
    tar = subprocess.Popen(
        ['tar', 'czf', '-',
         '--exclude=.git', '--exclude=assets', '--exclude=__pycache__',
         '--exclude=*.pyc', '--exclude=.pytest_cache',
         '-C', str(REPO), '.'],
        stdout=subprocess.PIPE)
    recv = run(ssh_base() + ['rm -rf /root/pybiss && mkdir -p /root/pybiss && '
                             'tar xzf - -C /root/pybiss'],
               stdin=tar.stdout)
    tar.wait()
    if tar.returncode or recv.returncode:
        sys.exit('sync failed')


def cmd_test(args):
    cmd_provision(args)
    cmd_sync(args)
    log('running the suite exactly as the CI leg does...')
    result = ssh_run(TEST_CMD, check=False)
    log(f'suite exit code: {result.returncode}')
    sys.exit(result.returncode)


def cmd_ssh(args):
    os.execvp('ssh', ssh_base() + (args.command or []))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--usb', metavar='VID:PID',
                    help='pass a host USB device through to the guest (hex), e.g. '
                         '31aa:7001 - the f_ccid virtual reader, so the FreeBSD '
                         'ugen backend can be tested with no physical hardware')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name, fn in [('setup', cmd_setup), ('boot', cmd_boot),
                     ('provision', cmd_provision), ('sync', cmd_sync),
                     ('test', cmd_test), ('stop', cmd_stop),
                     ('status', cmd_status), ('reset', cmd_reset)]:
        sub.add_parser(name).set_defaults(fn=fn)
    p_ssh = sub.add_parser('ssh', help='interactive shell (or run a command) in the VM')
    p_ssh.add_argument('command', nargs='*')
    p_ssh.set_defaults(fn=cmd_ssh)

    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
