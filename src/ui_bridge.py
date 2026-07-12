import sys, queue


from .config import config


_GUI_IS_ACTIVE = False
_UI_PROVIDER_OVERRIDE = None

def set_gui_active(state: bool=True):
    ''' Toggles the active state of the UI routing bridge '''

    global _GUI_IS_ACTIVE
    _GUI_IS_ACTIVE = state


def set_ui_provider(provider=None):

    global _UI_PROVIDER_OVERRIDE
    _UI_PROVIDER_OVERRIDE = provider


ui_task_queue = queue.Queue()


class ThreadSafeUIProxy:
    ''' Used by the background server to ask for user input without crashing Tkinter '''

    def __init__(self, timeout: float = None):
        self.timeout = timeout

    def _ask(self, task_type: str, kwargs: dict, cancel_sentinel):

        res_q = queue.Queue()
        ui_task_queue.put((task_type, kwargs, res_q))
        timeout = self.timeout
        if timeout is None:
            timeout = float(config.get('promptTimeoutSeconds', 180))
        try:
            return res_q.get(timeout=timeout)
        except queue.Empty:
            return cancel_sentinel


    def prompt_pin(self, attempt: int = 1, label: str = 'PIN') -> str:
        return self._ask('prompt_pin', {'attempt': attempt, 'label': label}, None)

    def choose_certificate(self, certs: list[dict]) -> int:
        return self._ask('choose_certificate', {'certs': certs}, -1)

    def confirm_sign(self, text: str, additional_text: str = None) -> bool:
        return self._ask('confirm_sign',
                         {'text': text, 'additional_text': additional_text}, False)


class CLIUserInterface:
    ''' Fallback for headless Linux servers with no desktop environment '''
    
    def prompt_pin(self, attempt: int = 1, label: str = 'PIN') -> str:

        print(f'\n[{label} Prompt] (Attempt {attempt})')
        sys.stdout.write(f'Enter Smart Card {label}: ')
        sys.stdout.flush()
        return sys.stdin.readline().strip()


    def choose_certificate(self, certs: list[dict]) -> int:

        print('\n=== Choose Certificate ===')
        for i, cert in enumerate(certs):
            print(f"[{i}] Subject: {cert.get('subject', 'Unknown')} (Serial: {cert.get('serial', 'N/A')})")
        while True:
            sys.stdout.write(f'Select certificate [0-{len(certs)-1}] (Enter to cancel): ')
            val = sys.stdin.readline().strip()
            if not val: return -1
            try:
                idx = int(val)
                if 0 <= idx < len(certs): return idx
            except ValueError: pass
            print('Invalid selection.')


    def confirm_sign(self, text: str, additional_text: str = None) -> bool:

        print(f'\n=== Confirm Sign Request ===\nMessage: {text}')
        if additional_text: 
            print(f'Details: {additional_text}')
        sys.stdout.write('Do you authorize this signature? (yes/no): ')

        return sys.stdin.readline().strip().lower() in ('y', 'yes')


def get_ui_provider():

    if _UI_PROVIDER_OVERRIDE is not None:
        return _UI_PROVIDER_OVERRIDE

    # Use the Queue proxy if the Dashboard explicitly announced it is running
    if _GUI_IS_ACTIVE:
        return ThreadSafeUIProxy()
    
    # Fallback for headless environments (or running app.py directly)
    return CLIUserInterface()