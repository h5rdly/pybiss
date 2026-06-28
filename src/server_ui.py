import sys, tkinter as tk

sys.path.append(__file__.rsplit('/', 1)[0])

from src.tkinter_mods import (
    Theme, Button, Entry, Frame, Label, Scrollbar, set_dark_titlebar
)


class CLIUserInterface:
    ''' Terminal-based fallback user interface '''

    def prompt_pin(self, attempt: int = 1) -> str:

        print(f'\n[PIN Prompt] (Attempt {attempt})')
        sys.stdout.write('Enter Smart Card PIN: ')
        sys.stdout.flush()
        return sys.stdin.readline().strip()


    def choose_certificate(self, certs: list[dict]) -> int:

        print('\n=== Choose Certificate ===')
        for i, cert in enumerate(certs):
            print(f'[{i}] Subject: {cert.get('subject', 'Unknown')} (Serial: {cert.get('serial', 'N/A')})')
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
        if additional_text: print(f'Details: {additional_text}')
        sys.stdout.write('Do you authorize this signature? (yes/no): ')
        return sys.stdin.readline().strip().lower() in ('y', 'yes')


class DarkUI:

    def _create_modal(self, title: str, width: int, height: int):
        root = tk.Tk()
        root.withdraw()

        dialog = tk.Toplevel(root)
        dialog.title(title)
        dialog.geometry(f'{width}x{height}')
        dialog.configure(bg=Theme.BG)
        
        set_dark_titlebar(dialog) 
        
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'+{x}+{y}')
        
        dialog.transient(root)
        dialog.grab_set()
        dialog.attributes('-topmost', True)
        return root, dialog


    def prompt_pin(self, attempt: int = 1) -> str:

        root, dialog = self._create_modal('Security Verification', 350, 220)
        result = {'pin': None}
        
        msg = 'Enter Smart Card PIN:' if attempt == 1 else f'Incorrect PIN. Try again (Attempt {attempt}):'
        color = Theme.TEXT if attempt == 1 else Theme.DANGER
        
        Label(dialog, text=msg, fg=color).pack(pady=(25, 10))
        
        entry = Entry(dialog, width=220, height=38, show='*')
        entry.pack(pady=10)
        entry.focus()
        
        def on_ok(event=None):
            result['pin'] = entry.get()
            dialog.destroy()
            root.destroy()
            
        def on_cancel(event=None):
            dialog.destroy()
            root.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=20)
        
        Button(btn_frame, 'Unlock', on_ok, width=100).pack(side='left', padx=10)
        Button(btn_frame, 'Cancel', on_cancel, width=100, fg_color=Theme.BG, hover_color=Theme.BORDER).pack(side='right', padx=10)
        
        dialog.bind('<Return>', on_ok)
        dialog.bind('<Escape>', on_cancel)
        dialog.protocol('WM_DELETE_WINDOW', on_cancel)
        
        dialog.wait_window()
        return result['pin']


    def choose_certificate(self, certs: list[dict]) -> int:

        root, dialog = self._create_modal('Select Certificate', 450, 360)
        result = {'index': -1}
        
        Label(dialog, text='Select the certificate to sign with:').pack(pady=(20, 10))
        
        container = Frame(dialog, width=410, height=200)
        container.pack(pady=10, padx=20, fill='both', expand=True)
        
        listbox = tk.Listbox(container.inner, bg=Theme.SURFACE, fg=Theme.TEXT, 
                             selectbackground=Theme.PRIMARY, selectforeground='white', 
                             relief='flat', borderwidth=0, font=('Segoe UI', 10), highlightthickness=0)
        
        scrollbar = Scrollbar(container.inner, command=listbox.yview)
        scrollbar.pack(side='right', fill='y', padx=(0,2))
        listbox.configure(yscrollcommand=scrollbar.set)
        
        for cert in certs:
            listbox.insert('end', f' {cert.get('subject', 'Unknown')} (Serial: {cert.get('serial', '')})')
            
        listbox.pack(side='left', fill='both', expand=True)
        if certs: listbox.selection_set(0)
            
        def on_ok(event=None):
            sel = listbox.curselection()
            if sel: result['index'] = sel[0]
            dialog.destroy()
            root.destroy()
            
        def on_cancel(event=None):
            dialog.destroy()
            root.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=15)
        
        Button(btn_frame, 'Select', on_ok, width=120).pack(side='left', padx=10)
        Button(btn_frame, 'Cancel', on_cancel, width=120, fg_color=Theme.BG, hover_color=Theme.BORDER).pack(side='right', padx=10)
        
        listbox.bind('<Double-1>', on_ok)
        dialog.bind('<Return>', on_ok)
        dialog.bind('<Escape>', on_cancel)
        dialog.protocol('WM_DELETE_WINDOW', on_cancel)
        
        dialog.wait_window()
        return result['index']


    def confirm_sign(self, text: str, additional_text: str = None) -> bool:

        root, dialog = self._create_modal('Authorize Signature', 500, 420)
        result = {'confirmed': False}
        
        Label(dialog, text='Do you authorize this signature?', font=('Segoe UI', 14, 'bold')).pack(pady=(20, 10))
        
        container = Frame(dialog, width=460, height=240)
        container.pack(pady=10, padx=20, fill='both', expand=True)
        
        textbox = tk.Text(container.inner, bg=Theme.SURFACE, fg=Theme.TEXT, 
                          relief='flat', borderwidth=0, font=('Segoe UI', 11), wrap='word', highlightthickness=0)
        
        scrollbar = Scrollbar(container.inner, command=textbox.yview)
        scrollbar.pack(side='right', fill='y', padx=(0,2))
        textbox.configure(yscrollcommand=scrollbar.set)
        
        full_text = f'Message:\n{text}'
        if additional_text: full_text += f'\n\nAdditional Info:\n{additional_text}'
            
        textbox.insert('1.0', full_text)
        textbox.configure(state='disabled')
        textbox.pack(side='left', fill='both', expand=True)
        
        def on_yes():
            result['confirmed'] = True
            dialog.destroy()
            root.destroy()
            
        def on_no():
            dialog.destroy()
            root.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=15)
        
        Button(btn_frame, 'Authorize', on_yes, bg_color='#2FA572', hover_color='#106A43', width=130).pack(side='left', padx=10)
        Button(btn_frame, 'Reject', on_no, bg_color=Theme.DANGER, hover_color=Theme.DANGER_HOVER, width=130).pack(side='right', padx=10)
        
        dialog.protocol('WM_DELETE_WINDOW', on_no)
        dialog.wait_window()
        return result['confirmed']


def get_ui_provider() -> UserInterfaceProvider:

    try:
        root = tk.Tk()
        root.destroy()
        return DarkUI()
    except Exception:
        return CLIUserInterface()