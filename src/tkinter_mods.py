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

        # Zooming/Scaling 
        self.zoom_level = 12 # Default baseline font size
        
        # Windows/Linux bindings
        self.bind('<Control-MouseWheel>', self._on_mousewheel_zoom)
        self.bind('<Control-plus>', self._zoom_in)
        self.bind('<Control-equal>', self._zoom_in)
        self.bind('<Control-minus>', self._zoom_out)
        
        # macOS/Linux specific scroll bindings
        self.bind('<Control-Button-4>', self._zoom_in)
        self.bind('<Control-Button-5>', self._zoom_out)


    def mainloop(self, *args, **kwargs):
        ''' Reveal the window only after everything is fully rendered '''

        self.deiconify()
        super().mainloop(*args, **kwargs)


    def _on_mousewheel_zoom(self, event):
        if event.delta > 0:
            self._zoom_in()
        else:
            self._zoom_out()


    def _zoom_in(self, event=None):
        if self.zoom_level < 24: # Max font size
            self.zoom_level += 1
            self._apply_zoom(self)

    def _zoom_out(self, event=None):
        if self.zoom_level > 8: # Min font size
            self.zoom_level -= 1
            self._apply_zoom(self)


    @property
    def ui_scale(self):
        ''' Convert the baseline font size (12) into a layout multiplier (e.g. 1.5x) '''
        
        return self.zoom_level / 12.0


    def _apply_zoom(self, widget):
        ''' Recursively scales fonts down the widget tree '''

        try:
            # Check if the widget has a font configuration
            current_font = widget.cget("font")
            if current_font:
                # If it's a string font (e.g. "Consolas 10"), split it
                if isinstance(current_font, str):
                    parts = current_font.split()
                    family = parts[0]
                    # Update to our new zoom level
                    widget.configure(font=(family, self.zoom_level))
                # If it's a tuple font (e.g. ('Segoe UI', 12, 'bold'))
                elif isinstance(current_font, tuple):
                    family = current_font[0]
                    modifiers = current_font[2:] if len(current_font) > 2 else ()

                    # keep headers proportionally larger
                    if len(current_font) > 1 and int(current_font[1]) >= 18:
                        widget.configure(font=(family, self.zoom_level + 8, *modifiers))
                    else:
                        widget.configure(font=(family, self.zoom_level, *modifiers))
        
        except Exception:
            pass # Widget doesn't support font attribute (like a raw Frame)

        # Recursively apply to all children
        for child in widget.winfo_children():
            self._apply_zoom(child)

        # Trigger a physical redraw if the widget has one
        if hasattr(widget, '_draw'):
            widget._draw()
        

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
            Button(btn_frame, text=btn_text, command=on_click, width=100, 
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
        
        # Skip drawing if window hasn't assigned layout dimensions yet
        if w <= 1 or h <= 1: return 
        
        s = self.winfo_toplevel().ui_scale
        radius = self.corner_radius * s
        
        self.rect_id = draw_rounded_rect(self, 0, 0, w, h, radius, fill=self.fg_color)
        
        text_str = self.master.tk.call('set', 'text', self.winfo_id()) if not hasattr(self, 'text') else self.text
        self.text_id = self.create_text(w/2, h/2, text=text_str, fill=Theme.TEXT, 
                                        font=('Segoe UI', int(11*s), 'bold'))
        self.text = self.itemcget(self.text_id, 'text')


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


class Checkbox(tk.Frame):
    
    def __init__(self, master, text="", command=None, checked=False):

        super().__init__(master, bg=Theme.BG)
        self.command = command
        self.is_checked = checked
        
        # 24x24 canvas for the box
        self.canvas = tk.Canvas(self, width=24, height=24, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(side="left", padx=(0, 10))
        
        self.label = tk.Label(self, text=text, bg=Theme.BG, fg=Theme.TEXT, font=Theme.FONT)
        self.label.pack(side="left")
        
        # Bind clicks on both the box and the label
        self.canvas.bind("<Button-1>", self.toggle)
        self.label.bind("<Button-1>", self.toggle)
        
        self._draw()

    def _draw(self):

        self.canvas.delete("all")
        s = self.winfo_toplevel().ui_scale 
        self.canvas.configure(width=24*s, height=24*s)
        
        if self.is_checked:
            draw_rounded_rect(self.canvas, 2*s, 2*s, 22*s, 22*s, 6*s, fill=Theme.PRIMARY, outline="")
            self.canvas.create_line(7*s, 12*s, 11*s, 16*s, 17*s, 7*s, fill=Theme.TEXT, width=max(2, 2*s), capstyle=tk.ROUND, joinstyle=tk.ROUND)
        else:
            draw_rounded_rect(self.canvas, 2*s, 2*s, 22*s, 22*s, 6*s, fill=Theme.BG, outline=Theme.BORDER, width=max(2, 2*s))


    def get(self) -> bool:
        return self.is_checked

    def set(self, state: bool):
        self.is_checked = state
        self._draw()


    def toggle(self, event=None):

        self.is_checked = not self.is_checked
        self._draw()
        if self.command:
            self.command(self.is_checked)
            

class Toggle(tk.Frame):
    
    def __init__(self, master, text="", command=None, is_on=False):

        super().__init__(master, bg=Theme.BG)
        self.command = command
        self.is_on = is_on
        
        # 40x20 canvas for the switch track
        self.canvas = tk.Canvas(self, width=44, height=24, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(side="left", padx=(0, 10))
        
        self.label = tk.Label(self, text=text, bg=Theme.BG, fg=Theme.TEXT, font=Theme.FONT)
        self.label.pack(side="left")
        
        self.canvas.bind("<Button-1>", self.toggle)
        self.label.bind("<Button-1>", self.toggle)
        
        self._draw()

    def _draw(self):

        self.canvas.delete("all")
        
        # Grab the current zoom multiplier from the main window
        s = self.winfo_toplevel().ui_scale 
        
        # Dynamically scale the Canvas container
        self.canvas.configure(width=44*s, height=24*s)
        
        # Draw the track
        track_color = Theme.PRIMARY if self.is_on else Theme.SURFACE
        draw_rounded_rect(self.canvas, 2*s, 2*s, 42*s, 22*s, 10*s, fill=track_color, outline="")
        
        # Draw the thumb
        thumb_x = 22*s if self.is_on else 4*s
        self.canvas.create_oval(thumb_x, 4*s, thumb_x + 16*s, 20*s, fill=Theme.TEXT, outline="")


    def toggle(self, event=None):

        self.is_on = not self.is_on
        self._draw() 
        if self.command:
            self.command(self.is_on)
            
    def get(self) -> bool:
        return self.is_on

    def set(self, state: bool):
        self.is_on = state
        self._draw()


class Toplevel(tk.Toplevel):
    ''' DPI-aware popup window that inherits scale from its master and prevents white-flash '''
    
    def __init__(self, master, title="Popup", width=400, height=300):
        super().__init__(master)
        self.withdraw() # Prevent white flash
        
        self.title(title)
        self.configure(bg=Theme.BG)
        set_dark_titlebar(self)
        
        # Inherit UI scale from the parent window
        self.ui_scale = getattr(master, 'ui_scale', 1.0)
        scaled_w = int(width * self.ui_scale)
        scaled_h = int(height * self.ui_scale)
        
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (scaled_w // 2)
        y = (self.winfo_screenheight() // 2) - (scaled_h // 2)
        self.geometry(f'{scaled_w}x{scaled_h}+{x}+{y}')
        
        self.transient(master)
        self.grab_set()
        self.attributes('-topmost', True)


    def show(self):
        ''' Applies zoom and reveals the window flawlessly '''

        if hasattr(self.master, '_apply_zoom'):
            self.master._apply_zoom(self)
        self.deiconify()


class Textbox(Frame):
    ''' Composite widget: Rounded Frame + tk.Text + Custom Scrollbar '''
    
    def __init__(self, master, width=400, height=200, corner_radius=10, **kwargs):
        super().__init__(master, width=width, height=height, corner_radius=corner_radius)
        
        self.scrollbar = Scrollbar(self.inner, command=self._yview)
        self.scrollbar.pack(side='right', fill='y', padx=(0, 2))
        
        text_kwargs = dict(bg=Theme.SURFACE, fg=Theme.TEXT, relief='flat', borderwidth=0, 
                           font=('Consolas', 10), highlightthickness=0)
        text_kwargs.update(kwargs)
        
        self.text = tk.Text(self.inner, yscrollcommand=self.scrollbar.set, **text_kwargs)
        self.text.pack(side='left', fill='both', expand=True)

    # Proxy methods to the native text widget
    def _yview(self, *args): self.text.yview(*args)
    def insert(self, *args, **kwargs): self.text.insert(*args, **kwargs)
    def delete(self, *args, **kwargs): self.text.delete(*args, **kwargs)
    def configure(self, *args, **kwargs): self.text.configure(*args, **kwargs)
    def see(self, *args, **kwargs): self.text.see(*args, **kwargs)


class Listbox(Frame):
    ''' Composite widget: Rounded Frame + tk.Listbox + Custom Scrollbar '''
    
    def __init__(self, master, width=400, height=200, corner_radius=10, **kwargs):
        super().__init__(master, width=width, height=height, corner_radius=corner_radius)
        
        self.scrollbar = Scrollbar(self.inner, command=self._yview)
        self.scrollbar.pack(side='right', fill='y', padx=(0, 2))
        
        list_kwargs = dict(bg=Theme.SURFACE, fg=Theme.TEXT, selectbackground=Theme.PRIMARY, 
                           selectforeground='white', relief='flat', borderwidth=0, 
                           font=('Segoe UI', 10), highlightthickness=0)
        list_kwargs.update(kwargs)
        
        self.listbox = tk.Listbox(self.inner, yscrollcommand=self.scrollbar.set, **list_kwargs)
        self.listbox.pack(side='left', fill='both', expand=True)

    # Proxy methods to the native listbox widget
    def _yview(self, *args): self.listbox.yview(*args)
    def insert(self, *args, **kwargs): self.listbox.insert(*args, **kwargs)
    def curselection(self): return self.listbox.curselection()
    def selection_set(self, *args): self.listbox.selection_set(*args)
    def bind(self, *args, **kwargs): self.listbox.bind(*args, **kwargs)
    def focus_set(self): self.listbox.focus_set()


