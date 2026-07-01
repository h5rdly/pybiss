import os, sys, logging, tkinter as tk, base64, threading, queue
from tkinter import filedialog

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from tkinter_mods import (
    Theme, Window, Button, Frame, Scrollbar, MessageBox, Toggle, Label, 
    set_dark_titlebar, Toplevel, Textbox, Listbox, Entry
)

from config import config
from locale import _
from app import app as api_server

# The core engine
import detector as detector
import hardware as hardware
from ui_bridge import ui_task_queue, set_gui_active


class DesktopDashboard(Window):

    def __init__(self):

        super().__init__(title="PyBISS Desktop Manager", width=750, height=550)
        
        # Logging
        self._log_file = config.config_dir / 'pybiss.log'
        self._log_file.touch(exist_ok=True) # Ensure the file exists so we don't crash
        self._last_log_size = 0
        logging.basicConfig(
            filename=str(self._log_file),
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        logging.info("PyBISS Desktop Manager starting...")

        # Announce to the routing bridge that the GUI is alive and consuming the queue
        set_gui_active(True)

        # Initialize the renderer with this main window as the master
        self.ui_renderer = ModalRenderer(self)

        self._build_sidebar()
        self._build_main_container()
        
        # Build all the views
        self.views = {}
        self._build_home_view()
        self._build_logs_view()
        self._build_admin_view()
        self._build_settings_view()

        # Start on Home
        self.show_view('home')
        # Start the background log-tailing loop
        self._auto_tail_logs()
        # Start checking the queue
        self._monitor_ui_queue()


    def _monitor_ui_queue(self):

        try:
            task_type, kwargs, result_queue = ui_task_queue.get_nowait()
            
            if task_type == 'prompt_pin':
                res = self.ui_renderer.prompt_pin(**kwargs)
                result_queue.put(res)
            elif task_type == 'choose_certificate':
                res = self.ui_renderer.choose_certificate(**kwargs)
                result_queue.put(res)
            elif task_type == 'confirm_sign':
                res = self.ui_renderer.confirm_sign(**kwargs)
                result_queue.put(res)
        except queue.Empty:
            pass
            
        self.after(100, self._monitor_ui_queue)


    # --- Layout Architecture ---

    def _build_sidebar(self):
        
        self.sidebar = tk.Frame(self, bg='#1E1E1E', width=200)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)

        # App Brand/Logo Area
        brand = tk.Label(self.sidebar, text='PyBISS', font=('Segoe UI', 22, 'bold'), 
                         bg='#1E1E1E', fg=Theme.PRIMARY)
        brand.pack(pady=(25, 35))

        # Navigation Buttons
        self.nav_btns = {}
        nav_items = [
            ('home', f'🏠  {_("dash_title").split()[0]}'), # Grabs just the first word for compactness
            ('logs', f'📄  {_("tray_log_file")}'), 
            ('admin', '🛠️  Administration'),
            ('settings', '⚙️  Settings') # Hardcoded for now, or add to locale.py
        ]
        
        for view_id, text in nav_items:
            btn = tk.Button(self.sidebar, text=text, bg='#1E1E1E', fg=Theme.TEXT, 
                            activebackground=Theme.SURFACE, activeforeground='white',
                            relief='flat', borderwidth=0, font=('Segoe UI', 11, 'bold'), 
                            anchor='w', padx=20, pady=12,
                            command=lambda vid=view_id: self.show_view(vid))
            btn.pack(fill='x', pady=2)
            
            # Hover effect
            btn.bind('<Enter>', lambda e, b=btn: b.configure(bg=Theme.SURFACE) if b['bg'] != Theme.PRIMARY else None)
            btn.bind('<Leave>', lambda e, b=btn: b.configure(bg='#1E1E1E') if b['bg'] != Theme.PRIMARY else None)
            self.nav_btns[view_id] = btn

        # Exit at bottom
        exit_btn = tk.Button(self.sidebar, text='🚪  ' + _('tray_exit'), bg='#1E1E1E', fg=Theme.DANGER, 
                             relief='flat', borderwidth=0, font=('Segoe UI', 11, 'bold'), 
                             anchor='w', padx=20, pady=12, command=self.destroy)
        exit_btn.pack(side='bottom', fill='x', pady=15)

    def _build_main_container(self):
        self.main_container = tk.Frame(self, bg=Theme.BG)
        self.main_container.pack(side='right', fill='both', expand=True)

    def show_view(self, view_id):
        ''' Switches the active tab and highlights the sidebar button '''
        for view in self.views.values():
            view.place_forget()
            
        for btn in self.nav_btns.values():
            btn.configure(bg='#1E1E1E')

        self.views[view_id].place(relx=0, rely=0, relwidth=1, relheight=1)
        self.nav_btns[view_id].configure(bg=Theme.PRIMARY)

    ## -- Views 

    def _build_home_view(self):

        frame = tk.Frame(self.main_container, bg=Theme.BG)
        self.views['home'] = frame

        tk.Label(frame, text=_('dash_title'), font=('Segoe UI', 24, 'bold'), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor='w', padx=35, pady=(35, 5))

        self.status_var = tk.StringVar(value=_('status_ready'))
        tk.Label(frame, textvariable=self.status_var, font=('Segoe UI', 12), 
                 bg=Theme.BG, fg='#2CC985').pack(anchor='w', padx=35, pady=(0, 25))

        btn_frame = tk.Frame(frame, bg=Theme.BG)
        btn_frame.pack(anchor='w', padx=35)
        Button(btn_frame, _('btn_scan'), self.scan_card, width=160).pack(side='left', padx=(0, 15))
        Button(btn_frame, _('btn_read_certs'), self.read_certs, width=160, fg_color=Theme.SURFACE).pack(side='left')

        # Output Area (Refactored using the new Composite Textbox)
        self.output_text = Textbox(frame, width=500, height=280, font=('Consolas', 10))
        self.output_text.pack(pady=25, padx=35, fill='both', expand=True)


    def _build_logs_view(self):

        frame = tk.Frame(self.main_container, bg=Theme.BG)
        self.views['logs'] = frame

        header = tk.Frame(frame, bg=Theme.BG)
        header.pack(fill='x', padx=35, pady=(35, 10))
        tk.Label(header, text='System Logs', font=('Segoe UI', 24, 'bold'), bg=Theme.BG, fg=Theme.TEXT).pack(side='left')
        
        # Manual refresh button, just in case
        Button(header, 'Refresh', self.refresh_logs, width=90, fg_color=Theme.SURFACE).pack(side='right')

        # Refactored using the new Composite Textbox
        self.log_text = Textbox(frame, width=500, height=380, bg='#1E1E1E', fg='#A9B7C6', font=('Consolas', 9))
        self.log_text.pack(pady=10, padx=35, fill='both', expand=True)
        self.log_text.configure(state='disabled')
        
        # Initial log load
        self.refresh_logs()


    def _build_admin_view(self):

        frame = tk.Frame(self.main_container, bg=Theme.BG)
        self.views['admin'] = frame

        tk.Label(frame, text='Card Administration', font=('Segoe UI', 24, 'bold'), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor='w', padx=35, pady=(35, 20))

        # PIN Management Section
        pin_frame = tk.Frame(frame, bg=Theme.BG)
        pin_frame.pack(anchor='w', padx=35, pady=10)
        
        Button(pin_frame, 'Change PIN', self._ui_change_pin, width=160).pack(side='left', padx=(0, 15))
        Button(pin_frame, 'Unblock with PUK', self._ui_unblock_pin, width=160, fg_color=Theme.DANGER, hover_color=Theme.DANGER_HOVER).pack(side='left')

        # Certificate Management Section
        tk.Label(frame, text='Certificate Storage', font=('Segoe UI', 18, 'bold'), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor='w', padx=35, pady=(30, 10))
                 
        cert_frame = tk.Frame(frame, bg=Theme.BG)
        cert_frame.pack(anchor='w', padx=35)
        
        Button(cert_frame, 'Import Certificate', self._ui_import_cert, width=160, fg_color=Theme.SURFACE).pack(side='left')


    def _ui_change_pin(self):
        
        old_pin = get_ui_provider().prompt_pin() # Borrowing the existing modal
        if not old_pin: return
        
        # In a full implementation, you'd want a specific "Enter New PIN" modal here
        new_pin = get_ui_provider().prompt_pin() 
        if not new_pin: return

        try:
            lib_path = config.get('pkcs11Path') or hardware.LIBCVP11_PATH
            funcs = hardware.load_pkcs11(lib_path)
            hardware.change_card_pin(funcs, slot_id=1, old_pin=old_pin, new_pin=new_pin)
            MessageBox.showinfo("Success", "PIN successfully changed.")
        except Exception as e:
            MessageBox.showinfo("Error", f"Failed to change PIN: {e}")


    def _ui_unblock_pin(self):
        
        # d build a custom ThreeFieldsPIN modal in tkinter_mods.py
        # To mimic Java's ThreeFieldsPINController exactly: PUK, New PIN, Confirm New PIN.
        puk = get_ui_provider().prompt_pin() # Pretending this asks for PUK
        if not puk: return
        
        new_pin = get_ui_provider().prompt_pin() 
        if not new_pin: return

        try:
            lib_path = config.get('pkcs11Path') or hardware.LIBCVP11_PATH
            funcs = hardware.load_pkcs11(lib_path)
            hardware.unblock_card_pin(funcs, slot_id=1, puk=puk, new_pin=new_pin)
            MessageBox.showinfo("Success", "Card unblocked successfully.")
        except Exception as e:
            MessageBox.showinfo("Error", f"Failed to unblock card: {e}")
            

    def _ui_import_cert(self):
        
        # Native OS File Dialog
        filepath = filedialog.askopenfilename(
            title="Select Certificate", 
            filetypes=(("DER Certificates", "*.cer *.der *.crt"), ("All Files", "*.*"))
        )
        if not filepath: return
        
        from src.server_ui import get_ui_provider
        pin = get_ui_provider().prompt_pin()
        if not pin: return
        
        try:
            with open(filepath, 'rb') as f:
                cert_data = f.read()
                
            # Strip PEM headers if the user accidentally selected a PEM file
            if b'-----BEGIN' in cert_data:
                import src.crypto_parsing as cp
                cert_data = cp.decode_key_bytes(cert_data)

            lib_path = config.get('pkcs11Path') or hardware.LIBCVP11_PATH
            funcs = hardware.load_pkcs11(lib_path)
            hardware.write_certificate(funcs, slot_id=1, pin=pin, cert_der=cert_data)
            MessageBox.showinfo("Success", "Certificate imported to smart card.")
        except Exception as e:
            MessageBox.showinfo("Error", f"Import failed: {e}")


    def _build_settings_view(self):

        frame = tk.Frame(self.main_container, bg=Theme.BG)
        self.views["settings"] = frame

        tk.Label(frame, text=_("tray_language"), font=("Segoe UI", 20, "bold"), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor="w", padx=35, pady=(35, 20))

        # Language Segmented Control 
        lang_frame = tk.Frame(frame, bg=Theme.BG)
        lang_frame.pack(anchor="w", padx=35)
        
        self.btn_en = Button(lang_frame, "English (EN)", lambda: self.set_lang("en"), width=130)
        self.btn_en.pack(side="left", padx=(0, 5))
        
        self.btn_bg = Button(lang_frame, "Български (BG)", lambda: self.set_lang("bg"), width=130)
        self.btn_bg.pack(side="left")

        # Provider Segmented Control 
        tk.Label(frame, text=_("tray_sign_api"), font=("Segoe UI", 20, "bold"), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor="w", padx=35, pady=(40, 20))

        api_frame = tk.Frame(frame, bg=Theme.BG)
        api_frame.pack(anchor="w", padx=35)
        
        self.btn_p11 = Button(api_frame, "Hardware (PKCS11)", lambda: self.set_api("PKCS11"), width=160)
        self.btn_p11.pack(side="left", padx=(0, 5))
        
        self.btn_p12 = Button(api_frame, "Software (PKCS12)", lambda: self.set_api("PKCS12"), width=160)
        self.btn_p12.pack(side="left")

        # System Settings
        tk.Label(frame, text="System", font=("Segoe UI", 20, "bold"), 
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor="w", padx=35, pady=(40, 20))
                 
        is_boot_on = config.get_bool("osStarted", fallback=True)
        self.toggle_boot = Toggle(frame, text="Launch PyBISS on System Startup", 
                                  is_on=is_boot_on, command=self.save_boot_setting)
        self.toggle_boot.pack(anchor="w", padx=35, pady=(0, 20))

        # Initialize visuals based on config
        self.set_lang(config.get("language", "en"), save=False)
        self.set_api(config.get("signAPI", "PKCS11"), save=False)

        # Factory Reset
        Button(frame, _("tray_default"), self.factory_reset, fg_color=Theme.DANGER, 
                     hover_color=Theme.DANGER_HOVER, width=160).pack(anchor="w", padx=35, pady=(30, 0))


    # --- UI Logic & State ---

    def set_lang(self, lang, save=True):
        if save:
            config.set("language", lang)
            MessageBox.showinfo("Language Changed", "Please restart PyBISS to apply the new language.")
            
        self.btn_en.fg_color = Theme.PRIMARY if lang == "en" else Theme.SURFACE
        self.btn_bg.fg_color = Theme.PRIMARY if lang == "bg" else Theme.SURFACE
        self.btn_en._draw()
        self.btn_bg._draw()


    def set_api(self, api, save=True):

        if save: 
            config.set('signAPI', api)
        self.btn_p11.fg_color = Theme.PRIMARY if api == 'PKCS11' else Theme.SURFACE
        self.btn_p12.fg_color = Theme.PRIMARY if api == 'PKCS12' else Theme.SURFACE
        self.btn_p11._draw()
        self.btn_p12._draw()


    def factory_reset(self):
        
        if MessageBox.askyesno('Factory Reset', 'Are you sure you want to restore default settings?'):
            config.set('language', 'en')
            config.set('signAPI', 'PKCS11')
            config.set('pkcs11Path', '')
            config.set('pfxPath', '')
            self.set_lang('en', save=False)
            self.set_api('PKCS11', save=False)


    def save_boot_setting(self, is_on: bool):
        config.set("osStarted", str(is_on))
        self.log_to_dashboard(f"[*] Run on startup set to: {is_on}")


    # --- Logging Logic ---

    def _auto_tail_logs(self):
        ''' Background loop to continuously update the logs tab '''
        if self._log_file.exists():
            current_size = os.path.getsize(self._log_file)
            # Only read if the file has grown
            if current_size > self._last_log_size:
                with open(self._log_file, 'r', encoding='utf-8') as f:
                    f.seek(self._last_log_size)
                    new_lines = f.read()
                    
                self.log_text.configure(state='normal')
                self.log_text.insert('end', new_lines)
                self.log_text.see('end')
                self.log_text.configure(state='disabled')
                
                self._last_log_size = current_size

        # Check again in 2 seconds
        self.after(2000, self._auto_tail_logs)

    def refresh_logs(self):
        ''' Fully reloads the log file, showing only the last 500 lines to prevent UI lag '''
        
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        
        if self._log_file.exists():
            try:
                with open(self._log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()[-500:] # Grab last 500
                self.log_text.insert('end', ''.join(lines))
                self._last_log_size = os.path.getsize(self._log_file)
            except Exception as e:
                self.log_text.insert('end', f'[!] Error reading logs: {e}\n')
        else:
            self.log_text.insert('end', f'[INFO] Log file not found at {self._log_file}\n')
            
        self.log_text.see('end')
        self.log_text.configure(state='disabled')


    def log_to_dashboard(self, message: str):
        ''' Writes a message exclusively to the dashboard's Home tab text area '''

        self.output_text.insert('end', message + '\n')
        self.output_text.see('end')


    # --- Core Engine Integrations (Home Tab) ---

    def scan_card(self):
        self.output_text.delete('1.0', 'end')
        self.status_var.set(_('status_scanning'))
        self.update_idletasks()
        
        readers = detector.get_readers()
        if not readers:
            self.log_to_dashboard('[-] No smart card readers detected.')
            self.status_var.set(_('status_no_card'))
            return
            
        self.log_to_dashboard(f'[+] Found {len(readers)} reader(s):')
        for r in readers:
            self.log_to_dashboard(f'    - {r}')
            
        try:
            # Load the library first
            lib_path = config.get('pkcs11Path') or hardware.LIBCVP11_PATH
            funcs = hardware.load_pkcs11(lib_path)
            
            serial = hardware.get_token_serial_number(funcs, slot_id=1)
            self.log_to_dashboard(f'[+] Card Serial Number: {serial}')
            self.status_var.set(_('status_connected'))
        except Exception as e:
            self.log_to_dashboard(f'[-] Hardware error: {e}')
            self.status_var.set(_('status_error'))

    def read_certs(self):
        from src.server_ui import get_ui_provider
        
        self.output_text.delete('1.0', 'end')
        self.log_to_dashboard('[*] Attempting to read certificates from card...')
        self.update_idletasks()
        
        # Use the Server UI's modal to ask for a a PIN to read private certificate objects
        pin_modal = get_ui_provider()
        pin = pin_modal.prompt_pin()
        if not pin:
            self.log_to_dashboard('[-] PIN entry cancelled.')
            return

        try:
            lib_path = config.get('pkcs11Path') or hardware.LIBCVP11_PATH
            funcs = hardware.load_pkcs11(lib_path)
            
            certs = hardware.get_certificates(funcs, slot_id=1, pin=pin)
            if not certs:
                self.log_to_dashboard('[-] No certificates found on card.')
                return
                
            self.log_to_dashboard(f'[+] Successfully loaded {len(certs)} certificate(s):\n')
            for idx, cert in enumerate(certs):
                self.log_to_dashboard(f'--- Certificate {idx} ---')
                self.log_to_dashboard(f'ID:     {cert.get("id", b"").hex()}')
                self.log_to_dashboard(f'Length: {len(cert.get("der", b""))} bytes')
                self.log_to_dashboard('-' * 30 + '\n')
                
        except Exception as e:
            self.log_to_dashboard(f'[-] Failed to read certificates: {e}')


class ThreadSafeUIProxy:
    ''' 
    Used by the background server. Instead of creating windows, 
    it drops a task into the queue and waits for the Main Thread to reply.
    '''

    def prompt_pin(self, attempt: int = 1) -> str:
        res_q = queue.Queue()
        ui_task_queue.put(('prompt_pin', {'attempt': attempt}, res_q))
        return res_q.get()

    def choose_certificate(self, certs: list[dict]) -> int:
        res_q = queue.Queue()
        ui_task_queue.put(('choose_certificate', {'certs': certs}, res_q))
        return res_q.get()

    def confirm_sign(self, text: str, additional_text: str = None) -> bool:
        res_q = queue.Queue()
        ui_task_queue.put(('confirm_sign', {'text': text, 'additional_text': additional_text}, res_q))
        return res_q.get()


class ModalRenderer:
    ''' Draws popups attached to the existing Main Window using tkinter_mods Composite Widgets '''

    def __init__(self, master_window):
        self.master = master_window

    def prompt_pin(self, attempt: int = 1) -> str:

        dialog = Toplevel(self.master, title='Security Verification', width=350, height=220)
        result = {'pin': None}
        
        msg = 'Enter Smart Card PIN:' if attempt == 1 else f'Incorrect PIN. Try again (Attempt {attempt}):'
        color = Theme.TEXT if attempt == 1 else Theme.DANGER
        
        Label(dialog, text=msg, fg=color).pack(pady=(25, 10))
        
        entry = Entry(dialog, width=220, height=38, show='*')
        entry.pack(pady=10)
        
        def on_ok(event=None):
            result['pin'] = entry.get()
            dialog.destroy()
            
        def on_cancel(event=None):
            dialog.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=20)
        
        Button(btn_frame, 'Unlock', on_ok, width=100).pack(side='left', padx=10)
        Button(btn_frame, 'Cancel', on_cancel, width=100, fg_color=Theme.BG, hover_color=Theme.BORDER).pack(side='right', padx=10)
        
        dialog.bind('<Return>', on_ok)
        dialog.bind('<Escape>', lambda e: on_cancel())
        dialog.protocol('WM_DELETE_WINDOW', on_cancel)
        
        dialog.show()
        dialog.after(100, entry.focus)
        
        dialog.wait_window()
        return result['pin']


    def choose_certificate(self, certs: list[dict]) -> int:

        dialog = Toplevel(self.master, title='Select Certificate', width=450, height=360)
        result = {'index': -1}
        
        Label(dialog, text='Select the certificate to sign with:').pack(pady=(20, 10))
        
        # Instantiating the new composite Listbox handles the scrolling and formatting seamlessly
        listbox = Listbox(dialog, width=410, height=200)
        listbox.pack(pady=10, padx=20, fill='both', expand=True)
        
        for cert in certs:
            listbox.insert('end', f" {cert.get('subject', 'Unknown')} (Serial: {cert.get('serial', '')})")
            
        if certs: listbox.selection_set(0)
            
        def on_ok(event=None):
            sel = listbox.curselection()
            if sel: result['index'] = sel[0]
            dialog.destroy()
            
        def on_cancel(event=None):
            dialog.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=15)
        
        Button(btn_frame, 'Select', on_ok, width=120).pack(side='left', padx=10)
        Button(btn_frame, 'Cancel', on_cancel, width=120, fg_color=Theme.BG, hover_color=Theme.BORDER).pack(side='right', padx=10)
        
        listbox.bind('<Double-1>', on_ok)
        dialog.bind('<Return>', on_ok)
        dialog.bind('<Escape>', lambda e: on_cancel())
        dialog.protocol('WM_DELETE_WINDOW', on_cancel)
        
        dialog.show()
        dialog.after(100, listbox.focus_set)
        
        dialog.wait_window()
        return result['index']


    def confirm_sign(self, text: str, additional_text: str = None) -> bool:

        dialog = Toplevel(self.master, title='Authorize Signature', width=500, height=420)
        result = {'confirmed': False}
        
        Label(dialog, text='Do you authorize this signature?', font=('Segoe UI', 14, 'bold')).pack(pady=(20, 10))
        
        # Instantiating the new composite Textbox handles the scrolling and formatting seamlessly
        textbox = Textbox(dialog, width=460, height=240, font=('Segoe UI', 11), wrap='word')
        textbox.pack(pady=10, padx=20, fill='both', expand=True)
        
        full_text = f'Message:\n{text}'
        if additional_text: full_text += f'\n\nAdditional Info:\n{additional_text}'
            
        textbox.insert('1.0', full_text)
        textbox.configure(state='disabled')
        
        def on_yes():
            result['confirmed'] = True
            dialog.destroy()
            
        def on_no():
            dialog.destroy()
            
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(pady=15)
        
        # Grab focus to the "Authorize" button by default
        btn_yes = Button(btn_frame, 'Authorize', on_yes, bg_color='#2FA572', hover_color='#106A43', width=130)
        btn_yes.pack(side='left', padx=10)
        Button(btn_frame, 'Reject', on_no, bg_color=Theme.DANGER, hover_color=Theme.DANGER_HOVER, width=130).pack(side='right', padx=10)
        
        # Pressing Enter hits 'Authorize'
        dialog.bind('<Return>', lambda e: on_yes())
        dialog.bind('<Escape>', lambda e: on_no())
        dialog.protocol('WM_DELETE_WINDOW', on_no)
        
        dialog.show()
        dialog.wait_window()

        return result['confirmed']


if __name__ == '__main__':

    # Start the REST API in a background daemon thread
    server_thread = threading.Thread(
        target=lambda: api_server.run(host='127.0.0.1', port=4843), 
        daemon=True
    )
    server_thread.start()

    # Start the native Desktop UI on the main thread (Blocks until closed)
    app = DesktopDashboard()
    app.mainloop()