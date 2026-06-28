import os, time, sys

if sys.platform == 'win32':
    import msvcrt
else:
    import termios
    import tty
    import select

sys.path.append(__file__.rsplit('/', 1)[0])

from src.detector import auto_detect_library
from src.hardware import load_pkcs11, get_slots, get_certificates, sign_payload
from src.cert_parser import get_x509_subject



# --- ANSI Escape Sequences ---
CLEAR_SCREEN = '\033[2J'
CURSOR_HOME = '\033[H'
HIDE_CURSOR = '\033[?25l'
SHOW_CURSOR = '\033[?25h'

COLOR_RESET = '\033[0m'
COLOR_TITLE = '\033[1;36m'   # Bold Cyan
COLOR_SUCCESS = '\033[1;32m' # Bold Green
COLOR_WARNING = '\033[1;33m' # Bold Yellow
COLOR_DANGER = '\033[1;31m'  # Bold Red
COLOR_SELECT = '\033[7m'     # Inverted colors for selection
COLOR_DIM = '\033[2m'        # Dim text for inactive steps


def move_cursor(row: int, col: int) -> str:
    return f'\033[{row};{col}H'


def read_key_nonblocking() -> str:
    ''' Cross-platform non-blocking keystroke reader '''

    if sys.platform == 'win32':
        if msvcrt.kbhit():
            key = msvcrt.getwch()
            if key in ('\x00', '\xe0'): 
                key += msvcrt.getwch()
                if key.endswith('H'): return 'UP'
                if key.endswith('P'): return 'DOWN'
            elif key == '\r': return 'ENTER'
            elif key == '\x08': return 'BACKSPACE'
            elif key in ('q', 'Q', '\x1b'): return 'QUIT'
            elif key in ('y', 'Y'): return 'CONFIRM_YES'
            elif key in ('n', 'N'): return 'CONFIRM_NO'
            return key

        return None
    else:
        rlist, _, _ = select.select([0], [], [], 0.05)
        if rlist:
            seq = os.read(0, 32).decode('utf-8', 'ignore')
            if seq == '\x1b[A': return 'UP'
            if seq == '\x1b[B': return 'DOWN'
            if seq in ('\r', '\n'): return 'ENTER'
            if seq in ('\x7f', '\x08'): return 'BACKSPACE'
            if seq in ('q', 'Q', '\x1b'): return 'QUIT'
            if seq in ('y', 'Y'): return 'CONFIRM_YES'
            if seq in ('n', 'N'): return 'CONFIRM_NO'
            return seq

        return None


def draw_wizard_ui(
    step: int, lib_path: str, slot_id: int, pin_buffer: str, 
    certs: list, parsed_names: list, sel_cert: int, 
    error_msg: str, sig_result: str, base_col: int, text_col: int
):
    ''' Draws the sequential configuration wizard '''

    sys.stdout.write(CLEAR_SCREEN + CURSOR_HOME)
    
    # Header 
    sys.stdout.write(move_cursor(2, base_col) + f'{COLOR_TITLE}╔══════════════════════════════════════════════════════════╗{COLOR_RESET}')
    sys.stdout.write(move_cursor(3, base_col) + f'{COLOR_TITLE}║{COLOR_RESET}               B-Trust Python Agent (TUI)                 {COLOR_TITLE}║{COLOR_RESET}')
    sys.stdout.write(move_cursor(4, base_col) + f'{COLOR_TITLE}╚══════════════════════════════════════════════════════════╝{COLOR_RESET}')
    
    # Hardware Status
    sys.stdout.write(move_cursor(6, text_col) + f'Library : {COLOR_SUCCESS}{lib_path}{COLOR_RESET}')
    sys.stdout.write(move_cursor(7, text_col) + f'Slot ID : {COLOR_SUCCESS}{slot_id}{COLOR_RESET}')
    
    row = 9
    
    # Step 1: PIN Entry
    color = COLOR_TITLE if step == 0 else (COLOR_RESET if step > 0 else COLOR_DIM)
    sys.stdout.write(move_cursor(row, text_col) + f'{color}[Step 1] Enter Token PIN:{COLOR_RESET}')
    row += 1
    
    if step == 0:
        masked_pin = '*' * len(pin_buffer)
        sys.stdout.write(move_cursor(row, text_col) + f'   > {COLOR_SELECT} {masked_pin} {COLOR_RESET}')
        row += 1
    else:
        sys.stdout.write(move_cursor(row, text_col) + f'   [ **** ]')
        row += 1
        
    row += 1

    # Step 2: Certificate Selection
    color = COLOR_TITLE if step == 1 else (COLOR_RESET if step > 1 else COLOR_DIM)
    sys.stdout.write(move_cursor(row, text_col) + f'{color}[Step 2] Select Certificate:{COLOR_RESET}')
    row += 1
    
    if step == 1:
        for i, name in enumerate(parsed_names):
            prefix = ' > ' if i == sel_cert else '   '
            item_color = COLOR_SELECT if i == sel_cert else COLOR_RESET
            sys.stdout.write(move_cursor(row, text_col) + f'{prefix}{item_color}[ {name} ]{COLOR_RESET}')
            row += 1
    elif step > 1:
        sys.stdout.write(move_cursor(row, text_col) + f'   [ {parsed_names[sel_cert]} ]')
        row += 1
        
    row += 1

    # Step 3: Confirmation & Results
    if step == 2:
        sys.stdout.write(move_cursor(row, text_col)   + f'{COLOR_WARNING}╔════════════════════════════════════════════════════════╗{COLOR_RESET}')
        sys.stdout.write(move_cursor(row+1, text_col) + f'{COLOR_WARNING}║ Ready to test signature payload using selected key?    ║{COLOR_RESET}')
        sys.stdout.write(move_cursor(row+2, text_col) + f'{COLOR_WARNING}╚════════════════════════════════════════════════════════╝{COLOR_RESET}')
    elif step == 3:
        sys.stdout.write(move_cursor(row, text_col) + f'{COLOR_SUCCESS}Signature generated successfully!{COLOR_RESET}')
        sys.stdout.write(move_cursor(row+1, text_col) + f'Raw Hex (first 64 chars):')
        sys.stdout.write(move_cursor(row+2, text_col) + f'{COLOR_DIM}{sig_result[:64]}...{COLOR_RESET}')

    # Error Display
    if error_msg:
        sys.stdout.write(move_cursor(21, text_col) + f'{COLOR_DANGER}Error: {error_msg}{COLOR_RESET}')

    # Footer Controls 
    if step == 0:
        sys.stdout.write(move_cursor(23, text_col) + f'{COLOR_SUCCESS}[ ENTER to Submit ]{COLOR_RESET}    {COLOR_WARNING}[ q to QUIT ]{COLOR_RESET}')
    elif step == 1:
        sys.stdout.write(move_cursor(23, text_col) + f'{COLOR_SUCCESS}[ ENTER to Select ]{COLOR_RESET}    {COLOR_WARNING}[ q to QUIT ]{COLOR_RESET}')
    elif step == 2:
        sys.stdout.write(move_cursor(23, text_col) + f'{COLOR_SUCCESS}[ y to Sign ]{COLOR_RESET}    {COLOR_WARNING}[ n to Go Back ]{COLOR_RESET}    [ q to QUIT ]')
    elif step == 3:
        sys.stdout.write(move_cursor(23, text_col) + f'{COLOR_WARNING}[ q to QUIT ]{COLOR_RESET}')
        
    sys.stdout.flush()


def run_tui():

    sys.stdout.write(CLEAR_SCREEN + CURSOR_HOME)
    print(f"{COLOR_TITLE}Scanning for smart cards...{COLOR_RESET}")
    
    # 1. Hardware Detection
    lib_path = auto_detect_library()
    if not lib_path:
        print(f"{COLOR_DANGER}No known smart card detected.{COLOR_RESET}")
        default_dll = '/usr/lib/libcvP11.so' if sys.platform.startswith('linux') else 'cvP11.dll'
        lib_path = input(f'Enter PKCS#11 DLL path [{default_dll}]: ').strip() or default_dll
        if not os.path.exists(lib_path):
            print(f"{COLOR_DANGER}Fatal: Library not found at {lib_path}{COLOR_RESET}")
            return

    try:
        funcs = load_pkcs11(lib_path)
        slots = get_slots(funcs)
        if not slots:
            print(f"{COLOR_DANGER}Fatal: Hardware library loaded, but no smart card slot detected.{COLOR_RESET}")
            return
        active_slot = slots[0]
    except Exception as e:
        print(f"{COLOR_DANGER}Hardware Error: {e}{COLOR_RESET}")
        return

    # Terminal Setup
    fd = sys.stdin.fileno()
    if sys.platform != 'win32':
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
    
    # State Machine
    step = 0
    pin_buffer = ""
    certs = []
    parsed_names = []
    sel_cert = 0
    error_msg = ""
    sig_result = ""
    
    try:
        sys.stdout.write(HIDE_CURSOR)
        
        while True:
            cols, _ = os.get_terminal_size()
            base_col = max(1, (cols - 60) // 2)
            text_col = base_col + 2

            draw_wizard_ui(step, lib_path, active_slot, pin_buffer, certs, parsed_names, sel_cert, error_msg, sig_result, base_col, text_col)
            
            key = read_key_nonblocking()
            if not key:
                if sys.platform != 'win32': time.sleep(0.02)
                continue
                
            error_msg = "" # Clear error on any keystroke

            if key == 'QUIT':
                break
            
            # --- STEP 0: PIN Entry ---
            if step == 0:
                if key == 'BACKSPACE':
                    pin_buffer = pin_buffer[:-1]
                elif key == 'ENTER':
                    if not pin_buffer:
                        error_msg = "PIN cannot be empty."
                        continue
                    try:
                        # Attempt to load certs using the PIN
                        certs = get_certificates(funcs, active_slot, pin_buffer)
                        if not certs:
                            error_msg = "PIN accepted, but no certificates found on card."
                            pin_buffer = ""
                            continue
                            
                        # Parse the X.509 CNs natively via Rust!
                        parsed_names = []
                        for c in certs:
                            try:
                                cn = get_x509_subject(c['der'])
                                parsed_names.append(cn)
                            except Exception:
                                parsed_names.append("Unknown Subject")
                                
                        step = 1
                    except Exception as e:
                        error_msg = f"Hardware Error: {e}"
                        pin_buffer = "" # Clear PIN on failure
                elif len(key) == 1 and key.isprintable():
                    pin_buffer += key
            
            # --- STEP 1: Certificate Selection ---
            elif step == 1:
                if key == 'UP':
                    sel_cert = max(0, sel_cert - 1)
                elif key == 'DOWN':
                    sel_cert = min(len(certs) - 1, sel_cert + 1)
                elif key == 'ENTER':
                    step = 2
                elif key == 'BACKSPACE': # Allow going back to fix PIN
                    step = 0
                    pin_buffer = ""
                    
            # --- STEP 2: Confirmation ---
            elif step == 2:
                if key == 'CONFIRM_NO':
                    step = 1
                elif key == 'CONFIRM_YES':
                    try:
                        payload = b"hello b-trust"
                        key_id = certs[sel_cert]['id']
                        signature = sign_payload(funcs, active_slot, pin_buffer, payload, key_id)
                        sig_result = signature.hex()
                        step = 3
                    except Exception as e:
                        error_msg = f"Signing Failed: {e}"
                        step = 1 # Kick back to selection on failure

    finally:
        # Crucial Terminal Cleanup
        if sys.platform != 'win32':
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.write(move_cursor(24, 1)) 
        sys.stdout.write(CLEAR_SCREEN + CURSOR_HOME)
        sys.stdout.flush()


if __name__ == '__main__':
    
    try:
        run_tui()
    except KeyboardInterrupt:
        sys.stdout.write(SHOW_CURSOR + COLOR_RESET + '\nExited.\n')