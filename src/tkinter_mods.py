import sys, tkinter as tk


class Theme:
    BG = '#242424'          # Main Window Background
    SURFACE = '#343638'     # Entry/Frame Background
    TEXT = '#DCE4EE'        # Main Text
    BORDER = '#565B5E'      # Borders
    PRIMARY = '#1F6AA5'     # Button Default
    HOVER = '#144870'       # Button Hover
    DANGER = '#E74C3C'      # Reject Button
    DANGER_HOVER = '#C0392B'
    FONT = ('Segoe UI', 12)


def set_dark_titlebar(window):
    ''' Force the native Windows titlebar into Dark Mode '''

    if sys.platform.startswith('win'):
        try:
            import ctypes
            window.update_idletasks() # Window must exist before getting HWND
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            value = ctypes.c_int(1)
            # DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 11) = 20, (Windows 10) = 19
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), 4)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(value), 4)
        except Exception:
            pass


def draw_rounded_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    ''' The exact bezier-smoothing trick CustomTkinter uses for rounded corners '''

    points = [
        x1+radius, y1, x1+radius, y1, x2-radius, y1, x2-radius, y1,
        x2, y1, x2, y1+radius, x2, y1+radius, x2, y2-radius, x2, y2-radius,
        x2, y2, x2-radius, y2, x2-radius, y2, x1+radius, y2, x1+radius, y2,
        x1, y2, x1, y2-radius, x1, y2-radius, x1, y1+radius, x1, y1+radius,
        x1, y1
    ]
    return canvas.create_polygon(points, **kwargs, smooth=True)



class Label(tk.Label):

    def __init__(self, master, text='', **kwargs):
        # Allow overriding fg, but default to Theme.TEXT
        fg = kwargs.pop('fg', Theme.TEXT)
        font = kwargs.pop('font', Theme.FONT)
        super().__init__(master, text=text, bg=Theme.BG, fg=fg, font=font, **kwargs)


class Window(tk.Tk):
    ''' DPI-aware Tkinter root window that prevents the white flash phenomena on boot '''
    
    def __init__(self, title="App", width=800, height=600):

        # Enable High-DPI awareness on Windows BEFORE window creation
        if sys.platform.startswith('win'):
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                pass
                
        # Enable Mac Dark Mode Titlebar
        if sys.platform == "darwin":
            os.system("defaults write -g NSRequiresAquaSystemAppearance -bool No")

        super().__init__()
        
        # Hide the window immediately to prevent the white flash
        self.withdraw()
        
        self.title(title)
        self.configure(bg=Theme.BG)
        
        # Apply Windows Dark Titlebar
        set_dark_titlebar(self)
        
        # Center the window perfectly based on the new DPI-aware dimensions
        self.geometry(f'{width}x{height}')
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')


    def mainloop(self, *args, **kwargs):
        ''' Reveal the window only after everything is fully rendered '''

        self.deiconify()
        super().mainloop(*args, **kwargs)


class MessageBox:
    
    @classmethod
    def _create_dialog(cls, title: str, message: str, buttons: list) -> bool:
        dialog = tk.Toplevel()
        dialog.title(title)
        dialog.configure(bg=Theme.BG)
        
        # Apply the dark titlebar hack!
        set_dark_titlebar(dialog)
        
        # Center the dialog
        width, height = 400, 200
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
        
        # Make it modal
        dialog.transient()
        dialog.grab_set()
        dialog.attributes('-topmost', True)
        
        # Message Label
        tk.Label(dialog, text=message, bg=Theme.BG, fg=Theme.TEXT, 
                 font=('Segoe UI', 12), wraplength=350, justify='center').pack(expand=True, fill='both', padx=20, pady=20)
        
        result = {'value': False}
        
        # Button Frame
        btn_frame = tk.Frame(dialog, bg=Theme.BG)
        btn_frame.pack(side='bottom', pady=20)
        
        for btn_text, val, is_primary in buttons:
            def on_click(v=val):
                result['value'] = v
                dialog.destroy()
                
            bg_col = Theme.PRIMARY if is_primary else Theme.BG
            hov_col = Theme.HOVER if is_primary else Theme.BORDER
            ModernButton(btn_frame, text=btn_text, command=on_click, width=100, 
                         fg_color=bg_col, hover_color=hov_col).pack(side='left', padx=10)
            
        dialog.wait_window()
        return result['value']

    @classmethod
    def showinfo(cls, title: str, message: str):
        cls._create_dialog(title, message, [('OK', True, True)])

    @classmethod
    def askyesno(cls, title: str, message: str) -> bool:
        return cls._create_dialog(title, message, [
            ('Yes', True, True), 
            ('No', False, False)
        ])


class Scrollbar(tk.Canvas):
    
    def __init__(self, master, command, width=12, **kwargs):

        super().__init__(master, bg=Theme.BG, width=width, highlightthickness=0, **kwargs)
        self.command = command
        self.start_val = 0.0
        self.end_val = 1.0
        self.bind('<Configure>', lambda e: self._draw())
        self.bind('<B1-Motion>', self._on_drag)
        self.bind('<Button-1>', self._on_click)


    def set(self, start, end):

        self.start_val = float(start)
        self.end_val = float(end)
        self._draw()


    def _draw(self):

        self.delete('all')
        h = self.winfo_height()
        w = self.winfo_width()
        y1, y2 = self.start_val * h, self.end_val * h
        if y2 - y1 < 10: y2 = y1 + 10 # Enforce a minimum thumb size
        
        # Draw the rounded track thumb!
        draw_rounded_rect(self, 2, y1+2, w-2, y2-2, (w-4)/2, fill=Theme.BORDER, outline='')

    def _on_click(self, event):
        self._move_to(event.y)

    def _on_drag(self, event):
        self._move_to(event.y)

    def _move_to(self, y):
        h = self.winfo_height()
        thumb_h = (self.end_val - self.start_val) * h
        new_start = (y - thumb_h / 2) / h
        new_start = max(0.0, min(1.0 - (self.end_val - self.start_val), new_start))
        self.command('moveto', str(new_start))


class Button(tk.Canvas):

    def __init__(self, master, text, command, width=120, height=32, 
                 corner_radius=8, fg_color=Theme.PRIMARY, hover_color=Theme.HOVER):
        super().__init__(master, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.command = command
        self.fg_color = fg_color
        self.hover_color = hover_color
        self.corner_radius = corner_radius
        self.rect_id = None
        self.text_id = None
        
        self.bind('<Configure>', self._draw)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
        self.bind('<ButtonRelease-1>', self._on_release)

    def _draw(self, event=None):
        self.delete('all')
        w, h = self.winfo_width(), self.winfo_height()
        self.rect_id = draw_rounded_rect(self, 0, 0, w, h, self.corner_radius, fill=self.fg_color)
        self.text_id = self.create_text(w/2, h/2, text=self.master.tk.call('set', 'text', self.winfo_id()) if not hasattr(self, 'text') else self.text, 
                                        fill=Theme.TEXT, font=('Segoe UI', 11, 'bold'))
        self.text = self.itemcget(self.text_id, 'text') # Store for resize

    def _on_enter(self, event):
        self.itemconfig(self.rect_id, fill=self.hover_color)
        self.config(cursor='hand2')

    def _on_leave(self, event):
        self.itemconfig(self.rect_id, fill=self.fg_color)
        self.config(cursor='arrow')

    def _on_click(self, event):
        self.move(self.text_id, 0, 1) # Subtle click depression

    def _on_release(self, event):
        self.move(self.text_id, 0, -1)
        if 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
            self.command()


class Entry(tk.Frame):

    def __init__(self, master, width=200, height=35, corner_radius=6, show=''):
        super().__init__(master, bg=Theme.BG)
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        
        # Draw Border
        draw_rounded_rect(self.canvas, 1, 1, width-1, height-1, corner_radius, fill=Theme.SURFACE, outline=Theme.BORDER, width=2)
        
        # Inner native entry
        self.entry = tk.Entry(self, bg=Theme.SURFACE, fg=Theme.TEXT, insertbackground='white', 
                              relief='flat', highlightthickness=0, font=Theme.FONT, show=show)
        self.entry.place(relx=0.05, rely=0.1, relwidth=0.9, relheight=0.8)

    def get(self): return self.entry.get()
    def focus(self): self.entry.focus()


class Frame(tk.Frame):

    def __init__(self, master, width=400, height=200, corner_radius=10):
        super().__init__(master, bg=Theme.BG)
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        draw_rounded_rect(self.canvas, 1, 1, width-1, height-1, corner_radius, fill=Theme.SURFACE, outline=Theme.BORDER, width=1)
        
        # A flat frame inside the canvas to hold child widgets (like Listbox/Text)
        self.inner = tk.Frame(self, bg=Theme.SURFACE)
        self.inner.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)