import logging, os, sys, tkinter as tk
from tkinter import font as tkfont

if sys.platform.startswith('win'):
    import winreg
else:
    import subprocess


class Theme:
    '''
    The active colour palette, plus LIVE (no-restart) dark/light switching -
    the visual analogue of Font. Widgets just read Theme.BG / Theme.TEXT / ...;
    the dashboard calls Theme.apply(mode) then Theme.apply_live(root, mapping)
    to repaint the whole tree in place.
    '''

    # Every themed colour, keyed identically in both palettes. DANGER stays red
    # in both, so it simply never enters the switch mapping.
    _DARK = {
        'BG':           '#242424',   # window background
        'SURFACE':      '#343638',   # entry / frame background
        'SIDEBAR':      '#1E1E1E',   # nav rail + log console (a recessed panel)
        'TEXT':         '#DCE4EE',   # main text
        'TEXT_MUTED':   '#7A8288',   # secondary / hint text
        'CONSOLE_TEXT': '#A9B7C6',   # log console text
        'BORDER':       '#565B5E',
        'PRIMARY':      '#1F6AA5',   # button default / selected
        'HOVER':        '#144870',
        'SUCCESS':      '#2CC985',   # status-ok text + authorize button
        'SUCCESS_HOVER':'#106A43',
        'DANGER':       '#E74C3C',
        'DANGER_HOVER': '#C0392B',
    }
    _LIGHT = {
        'BG':           '#EBEBEB',
        'SURFACE':      '#FFFFFF',
        'SIDEBAR':      '#DCDCDC',
        'TEXT':         '#1A1A1A',
        'TEXT_MUTED':   '#6A6F75',
        'CONSOLE_TEXT': '#3A3F45',
        'BORDER':       '#B4B8BC',
        'PRIMARY':      '#3B8ED0',
        'HOVER':        '#36719F',
        'SUCCESS':      '#1E9E5E',
        'SUCCESS_HOVER':'#17784A',
        'DANGER':       '#E74C3C',
        'DANGER_HOVER': '#C0392B',
    }
    _PALETTES = {'dark': _DARK, 'light': _LIGHT}
    KEYS = tuple(_DARK)

    MODE = 'dark'
    # Class attributes hold the CURRENT palette so every `Theme.BG` read works
    BG = _DARK['BG']
    SURFACE = _DARK['SURFACE']
    SIDEBAR = _DARK['SIDEBAR']
    TEXT = _DARK['TEXT']
    TEXT_MUTED = _DARK['TEXT_MUTED']
    CONSOLE_TEXT = _DARK['CONSOLE_TEXT']
    BORDER = _DARK['BORDER']
    PRIMARY = _DARK['PRIMARY']
    HOVER = _DARK['HOVER']
    SUCCESS = _DARK['SUCCESS']
    SUCCESS_HOVER = _DARK['SUCCESS_HOVER']
    DANGER = _DARK['DANGER']
    DANGER_HOVER = _DARK['DANGER_HOVER']

    # tk colour OPTIONS and cached-colour ATTRIBUTES that apply_live re-tints
    _COLOR_OPTS = ('bg', 'background', 'fg', 'foreground', 'insertbackground',
                   'highlightbackground', 'highlightcolor',
                   'selectbackground', 'selectforeground',
                   'activebackground', 'activeforeground')
    _COLOR_ATTRS = ('fg_color', 'hover_color')

    @classmethod
    def resolve(cls, mode):
        ''' 'dark'/'light' as given; 'system'/'auto'/None -> the OS setting,
            falling back to dark when the OS can't be read. '''

        if mode in ('dark', 'light'):
            return mode
        return detect_system_theme() or 'dark'

    @classmethod
    def apply(cls, mode):
        '''
        Point the whole UI at a palette. Returns an {old_hex: new_hex} mapping
        (lower-cased keys) of every colour that actually changed, for
        apply_live to repaint already-built widgets.
        '''

        mode = cls.resolve(mode)
        palette = cls._PALETTES[mode]
        mapping = {}
        for key, new in palette.items():
            old = getattr(cls, key, None)
            if old is not None and old.lower() != new.lower():
                mapping[old.lower()] = new
            setattr(cls, key, new)
        cls.MODE = mode
        return mapping

    @classmethod
    def apply_live(cls, widget, mapping):
        '''
        Repaint one widget subtree in place - live, no restart. Remaps any
        colour OPTION or cached colour ATTRIBUTE whose value changed, recurses,
        then redraws canvas widgets (which re-read Theme.* in their _draw).
        '''

        if mapping:
            for opt in cls._COLOR_OPTS:
                try:
                    current = str(widget.cget(opt))
                except (tk.TclError, AttributeError, TypeError):
                    continue                       # widget lacks this option
                new = mapping.get(current.lower())
                if new:
                    try:
                        widget.configure(**{opt: new})
                    except tk.TclError:
                        pass
            for attr in cls._COLOR_ATTRS:
                value = getattr(widget, attr, None)
                if isinstance(value, str) and value.lower() in mapping:
                    setattr(widget, attr, mapping[value.lower()])

        for child in widget.winfo_children():
            cls.apply_live(child, mapping)

        if hasattr(widget, '_draw'):
            try:
                widget._draw()
            except Exception:
                pass                               # a half-built widget must not abort the walk


class Font:
    '''
    All the UI-font logic in one place: the active family, the shared base tuple,
    family resolution, and LIVE (no-restart) family switching across the whole
    widget tree. Widgets just read Font.FAMILY / Font.FONT; the dashboard calls
    Font.resolve() / Font.apply() / Font.apply_live() to change it.
    '''

    FAMILY = 'Segoe UI'       # overridden by apply(); resolve() picks a real one
    FONT = (FAMILY, 12)       # default (family, size) used by Label/Entry/Button

    @classmethod
    def resolve(cls, preferred):
        ''' The configured family if the system has it, else the OS/Tk default UI
            family (what Tk substitutes anyway). Needs a Tk root to exist. '''

        if preferred and preferred.lower() in {f.lower() for f in tkfont.families()}:
            return preferred
        return tkfont.nametofont('TkDefaultFont').actual('family')

    @classmethod
    def apply(cls, family):
        ''' Point the whole UI at a family (updates the base tuple too). '''

        cls.FAMILY = family
        cls.FONT = (family, cls.FONT[1])

    @classmethod
    def apply_live(cls, widget):
        '''
        Swap every widget's font family to cls.FAMILY in place - live, no restart.
        Keeps each font's size/modifiers, then redraws canvas widgets (Button/
        Entry/Textbox rebuild from Font.FAMILY in _draw). A widget on a NAMED
        tkinter Font (the sidebar nav) is handled by reconfiguring that Font.
        '''

        try:
            current = widget.cget('font')
            if current:
                if isinstance(current, str):
                    try:
                        tkfont.nametofont(current).configure(family=cls.FAMILY)
                    except tk.TclError:
                        parts = current.split()                    # "Family size ..."
                        if len(parts) >= 2:
                            widget.configure(font=(cls.FAMILY, *parts[1:]))
                elif isinstance(current, tuple) and len(current) >= 2:
                    widget.configure(font=(cls.FAMILY, *current[1:]))
        except (tk.TclError, ValueError):
            pass                        # no font attr (raw Frame/Canvas), or odd tuple

        for child in widget.winfo_children():
            cls.apply_live(child)

        if hasattr(widget, '_draw'):
            widget._draw()


def detect_system_theme():
    ''' Returns 'dark', 'light', or None (unknown) '''

    try:
        if sys.platform.startswith('win'):
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')
            apps_use_light, _ = winreg.QueryValueEx(key, 'AppsUseLightTheme')
            return 'light' if apps_use_light else 'dark'

        if sys.platform == 'darwin':
            out = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                                 capture_output=True, text=True, timeout=2)
            # The key only exists in Dark mode; absent (empty) means Light.
            return 'dark' if out.stdout.strip() == 'Dark' else 'light'

        # Linux / BSD via the freedesktop / GNOME setting. The timeout is
        # load-bearing: with a DISPLAY but no session bus (Xvfb on CI),
        # gsettings can block forever on D-Bus autolaunch.
        out = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'color-scheme'],
            capture_output=True, text=True, timeout=2)
        val = out.stdout.strip().strip("'").lower()
        if not val:
            return None
        return 'dark' if 'dark' in val else 'light'
    except Exception:
        return None


def _even(n) -> int:
    ''' Floor to the nearest even integer - keeps rounded corners symmetric '''
    return (int(n) // 2) * 2


def scrollbar_thumb_bounds(start: float, end: float, height: float, min_px: int = 10):
    ''' Pixel (y1, y2) bounds of a scrollbar thumb, enforcing a minimum size while
        preserving the proportional start<->end mapping
    '''

    length = (end - start) * height
    if length < min_px and (height - length) != 0:
        factor = (min_px - length) / (height - length)
        start = start - start * factor
        end = end + (1 - end) * factor

    return start * height, end * height


def scrollbar_drag_start(cursor_frac: float, grab_offset: float, thumb_len: float) -> float:
    '''
    New thumb start fraction for a drag that keeps the grabbed point under the
    cursor (rather than snapping the thumb's centre to it), clamped to the track.
    '''

    return max(0.0, min(1.0 - thumb_len, cursor_frac - grab_offset))


# --- Per-monitor DPI ---

_BASE_DPI = 96                 # 96 dpi == 100% scaling
_MDT_EFFECTIVE_DPI = 0         # the value the user set in display settings
_MONITOR_DEFAULTTONEAREST = 2


def get_window_dpi_scale(window) -> float:
    ''' DPI scale factor (1.0 = 100%) of the monitor `window` currently sits on '''

    if sys.platform == 'win32':
        try:
            import ctypes
            from ctypes import wintypes, byref
            # winfo_id() returns the client child HWND; MonitorFromWindow is
            # fine with that - both live on the same monitor.
            hwnd = wintypes.HWND(window.winfo_id())
            hmon = ctypes.windll.user32.MonitorFromWindow(
                hwnd, wintypes.DWORD(_MONITOR_DEFAULTTONEAREST))
            x_dpi, y_dpi = wintypes.UINT(), wintypes.UINT()
            if ctypes.windll.shcore.GetDpiForMonitor(
                    hmon, _MDT_EFFECTIVE_DPI, byref(x_dpi), byref(y_dpi)) == 0:
                return (x_dpi.value + y_dpi.value) / (2 * _BASE_DPI)
        except (OSError, AttributeError):
            pass  # < Windows 8.1 or shcore missing
        return 1.0

    elif sys.platform == 'darwin':
        return 1.0  # Quartz scales Tk windows automatically on Retina

    else:
        # X11 has no per-monitor DPI API (Wayland compositors scale natively)
        try:
            return window.tk.call('tk', 'scaling') / (_BASE_DPI / 72)
        except Exception:
            return 1.0


class DpiTracker:
    ''' Polling instead of WM_DPICHANGED because Tk owns the window procedure and tkinter 
        exposes no hook for raw Windows messages. The probe is injectable for tests
    '''

    poll_interval = 400       # ms between checks
    settle_interval = 1500    # ms pause after a change (user may still be dragging)

    def __init__(self, window, on_change, probe=get_window_dpi_scale):
        self.window = window
        self.on_change = on_change
        self.probe = probe
        self.scale = probe(window)
        window.after(self.poll_interval, self._poll)

    def _poll(self):
        try:
            if not self.window.winfo_exists():
                return                            # window gone - let the loop die
            delay = self.poll_interval
            if self.window.state() != 'iconic':   # skip minimized windows
                new = self.probe(self.window)
                if abs(new - self.scale) > 0.01:
                    old, self.scale = self.scale, new
                    self.on_change(old, new)
                    delay = self.settle_interval
            self.window.after(delay, self._poll)
        except tk.TclError:
            return                                # interpreter shutting down


def set_dark_titlebar(window, dark=None):
    ''' Match the native Windows titlebar to the active theme (dark by default) '''

    if dark is None:
        dark = getattr(Theme, 'MODE', 'dark') == 'dark'

    if sys.platform.startswith('win'):
        try:
            import ctypes
            window.update_idletasks() # Window must exist before getting HWND
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            value = ctypes.c_int(1 if dark else 0)
            # DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 11) = 20, (Windows 10) = 19
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), 4)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(value), 4)
        except Exception:
            pass


def grab_when_viewable(window, attempts=40):
    ''' Take the modal grab as soon as the server will allow it. Strict X11 refuses grabs 
        on unmapped windows, and blocking on wait_visibility() can hang forever - a transient 
        of a hidden master may never map at all
    '''

    try:
        if not window.winfo_exists():
            return
        window.grab_set()
    except tk.TclError:
        if attempts > 0:
            try:
                window.after(25, lambda: grab_when_viewable(window, attempts - 1))
            except tk.TclError:
                pass    # window torn down between the check and the reschedule


def draw_rounded_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    ''' bezier-smoothing for rounded corners '''

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
        font = kwargs.pop('font', Font.FONT)
        super().__init__(master, text=text, bg=Theme.BG, fg=fg, font=font, **kwargs)


class Window(tk.Tk):
    ''' DPI-aware Tkinter root window that prevents the white flash phenomena on boot '''
    
    def __init__(self, title="App"):

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

        # Transparent 1x1 pixel for icon
        self._blank_icon = tk.PhotoImage(width=1, height=1)
        self.iconphoto(True, self._blank_icon)

        # Per-monitor DPI. Point-based fonts already carry the PRIMARY monitor's factor
        # via Tk's own 'tk scaling', so fonts only need the ratio current/startup
        self._startup_dpi_scale = get_window_dpi_scale(self) or 1.0
        self._dpi_scale = self._startup_dpi_scale

        # Open at exactly half the screen in each dimension (a quarter of the
        # area), clamped to a usable minimum and never past the screen edge.
        # Screen dims are device pixels - deliberately NOT multiplied by the DPI
        # factor: doing so inflated the window on HiDPI so the bottom edge sat at
        # the screen bottom. The passed width/height are nominal only now.
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        width = min(max(sw // 2, 640), sw - 80)
        height = min(max(sh // 2, 480), sh - 80)

        # Center the window on screen
        self.geometry(f'{width}x{height}')
        self.update_idletasks()
        x = (sw // 2) - (width // 2)
        y = (sh // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')

        # Zooming/Scaling
        self.zoom_level = 12 # Default baseline font size
        self._zoom_timer = None # Debounce timer
        
        # Windows/Linux bindings
        self.bind('<Control-MouseWheel>', self._on_mousewheel_zoom)
        self.bind('<Control-plus>', self._zoom_in)
        self.bind('<Control-equal>', self._zoom_in)
        self.bind('<Control-minus>', self._zoom_out)
        
        # macOS/Linux specific scroll bindings
        self.bind('<Control-Button-4>', self._zoom_in)
        self.bind('<Control-Button-5>', self._zoom_out)

        # Re-scale when dragged onto a monitor with a different DPI
        DpiTracker(self, self._on_dpi_change)

    def _on_dpi_change(self, old: float, new: float):
        self._dpi_scale = new
        # Keep the same physical size on the new monitor
        w = int(self.winfo_width() * new / old)
        h = int(self.winfo_height() * new / old)
        try:
            self.attributes('-alpha', 0.2)   # mask the mid-resize flicker
        except Exception:
            pass
        self.geometry(f'{w}x{h}')
        self._apply_zoom(self)               # re-scale fonts + canvas widgets
        self.after(80, lambda: self._safe_alpha(1.0))

    def _safe_alpha(self, value):
        try:
            self.attributes('-alpha', value)
        except Exception:
            pass


    def report_callback_exception(self, exc_type, exc_value, exc_tb):
        ''' Tk's default prints callback tracebacks to stderr. Route them into pybiss.log 
            instead so the next one surfaces in the dashboard's own Logs tab.
        '''

        logging.error('Swallowed Tk callback exception',
                      exc_info=(exc_type, exc_value, exc_tb))


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
            self._schedule_zoom()

    def _zoom_out(self, event=None):
        if self.zoom_level > 8: # Min font size
            self.zoom_level -= 1
            self._schedule_zoom()


    def _schedule_zoom(self):
        ''' 
        Debounce: Cancel any pending redraws and schedule a new one
        Ensures the heavy _apply_zoom only runs AFTER the user stops scrolling
        '''

        if self._zoom_timer is not None:
            self.after_cancel(self._zoom_timer)
            
        # Wait 50ms after the last scroll tick to actually redraw
        self._zoom_timer = self.after(50, self._perform_zoom)


    def _perform_zoom(self):
        ''' Trigger recursive redraw '''

        self._zoom_timer = None
        self._apply_zoom(self)


    @property
    def ui_scale(self):
        ''' Layout multiplier for canvas pixel geometry: the user's zoom (Ctrl+scroll)
            times the current monitor's absolute DPI factor. Canvas widgets draw in
            raw pixels, so they need the absolute factor.
        '''
        return (self.zoom_level / 12.0) * getattr(self, '_dpi_scale', 1.0)


    @property
    def _dpi_font_ratio(self):
        ''' DPI-only multiplier for an already point-sized font, e.g. _apply_zoom, where 
            the size is `zoom_level`. Just the ratio vs startup
        '''
        startup = getattr(self, '_startup_dpi_scale', 1.0) or 1.0
        return getattr(self, '_dpi_scale', 1.0) / startup


    @property
    def font_scale(self):
        ''' Multiplier for a fixed-base widget font (e.g. Button's 11pt). Using `ui_scale` 
            for a font double-scales on any display above 100% - Tk already point-scales it once
        '''
        startup = getattr(self, '_startup_dpi_scale', 1.0) or 1.0
        dpi_ratio = getattr(self, '_dpi_scale', 1.0) / startup
        return (self.zoom_level / 12.0) * dpi_ratio


    def _apply_zoom(self, widget):
        ''' Recursively scales fonts down the widget tree '''

        try:
            # Check if the widget has a font configuration
            current_font = widget.cget("font")
            if current_font:
                # If it's a string font (e.g. "Consolas 10"), split it
                fs = self._dpi_font_ratio
                if isinstance(current_font, str):
                    parts = current_font.split()
                    family = parts[0]
                    # Update to our new zoom level
                    widget.configure(font=(family, int(self.zoom_level * fs)))
                # If it's a tuple font (e.g. ('Segoe UI', 12, 'bold'))
                elif isinstance(current_font, tuple):
                    family = current_font[0]
                    modifiers = current_font[2:] if len(current_font) > 2 else ()

                    # keep headers proportionally larger
                    if len(current_font) > 1 and int(current_font[1]) >= 18:
                        widget.configure(font=(family, int((self.zoom_level + 8) * fs), *modifiers))
                    else:
                        widget.configure(font=(family, int(self.zoom_level * fs), *modifiers))
        
        except (tk.TclError, ValueError):
            # TclError: widget has no font attribute (raw Frame/Canvas);
            # ValueError: non-numeric size slot in an exotic font tuple.
            pass

        # Recursively apply to all children
        for child in widget.winfo_children():
            self._apply_zoom(child)

        # Trigger a physical redraw if the widget has one
        if hasattr(widget, '_draw'):
            widget._draw()


    def apply_font_family_live(self):
        ''' Live "Apply Font" across this window - see Font.apply_live. '''
        Font.apply_live(self)
        

class MessageBox:
    
    @classmethod
    def _create_dialog(cls, title: str, message: str, buttons: list) -> bool:
        dialog = tk.Toplevel()
        dialog.title(title)
        dialog.configure(bg=Theme.BG)
        
        set_dark_titlebar(dialog)
        
        # Inherit UI scale from the app root - dialog is masterless, so .master 
        # is the default root. 
        dialog.ui_scale = getattr(dialog.master, 'ui_scale', 1.0)

        # Center the dialog
        width, height = int(400 * dialog.ui_scale), int(200 * dialog.ui_scale)
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')

        # Message Label
        tk.Label(dialog, text=message, bg=Theme.BG, fg=Theme.TEXT, 
                 font=(Font.FAMILY, 12), wraplength=350, justify='center').pack(expand=True, fill='both', padx=20, pady=20)
        
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

        # Make it modal - grab only once the server allows it (grabbing an nmapped toplevel 
        # races the WM and raises on strict X11). 
        dialog.attributes('-topmost', True)
        grab_when_viewable(dialog)

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
        self._grab_offset = 0.0
        self.bind('<Configure>', lambda e: self._draw())
        self.bind('<B1-Motion>', self._on_drag)
        self.bind('<Button-1>', self._on_click)


    def set(self, start, end):

        self.start_val = float(start)
        self.end_val = float(end)
        self._draw()


    def _draw(self):

        self.delete('all')
        h = _even(self.winfo_height())
        w = _even(self.winfo_width())
        y1, y2 = scrollbar_thumb_bounds(self.start_val, self.end_val, h)

        draw_rounded_rect(self, 2, y1+2, w-2, y2-2, (w-4)/2, fill=Theme.BORDER, outline='')

    def _on_click(self, event):
        h = self.winfo_height() or 1
        y1, y2 = scrollbar_thumb_bounds(self.start_val, self.end_val, h)
        frac = event.y / h
        if y1 <= event.y <= y2:
            # Grab the thumb: keep the grabbed point under the cursor while dragging
            self._grab_offset = frac - self.start_val
        else:
            # Click on the track: page-jump, centring the thumb on the cursor
            self._grab_offset = (self.end_val - self.start_val) / 2
        self._apply_drag(event.y)

    def _on_drag(self, event):
        self._apply_drag(event.y)

    def _apply_drag(self, y):
        h = self.winfo_height() or 1
        new_start = scrollbar_drag_start(y / h, self._grab_offset, self.end_val - self.start_val)
        self.command('moveto', str(new_start))


class Button(tk.Canvas):

    def __init__(self, master, text, command, width=120, height=32, 
                 corner_radius=8, fg_color=Theme.PRIMARY, hover_color=Theme.HOVER):
        super().__init__(master, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.command = command
        self.text = text
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
        w, h = _even(self.winfo_width()), _even(self.winfo_height())

        # Skip drawing if window hasn't assigned layout dimensions yet
        if w <= 1 or h <= 1: return
        
        tl = self.winfo_toplevel()
        # getattr fallbacks: a bare-toplevel host renders unscaled buttons
        # instead of NO buttons (an AttributeError here is swallowed by Tk)
        s = getattr(tl, 'ui_scale', 1.0)                  # geometry: absolute factor
        fscale = getattr(tl, 'font_scale', s)             # font: zoom * DPI ratio
        radius = self.corner_radius * s
        font = (Font.FAMILY, int(11*fscale), 'bold')

        needed = tkfont.Font(family=Font.FAMILY, size=int(11*fscale),
                             weight='bold').measure(self.text) + int(24*fscale)
        if needed > w:
            self.config(width=needed)
            w = _even(needed)

        self.rect_id = draw_rounded_rect(self, 0, 0, w, h, radius, fill=self.fg_color)

        self.text_id = self.create_text(w/2, h/2, text=self.text, fill=Theme.TEXT,
                                        font=font)


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

    def __init__(self, master, width=200, height=35, corner_radius=6, show='', placeholder=''):
        super().__init__(master, bg=Theme.BG)
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)

        # Draw Border
        draw_rounded_rect(self.canvas, 1, 1, width-1, height-1, corner_radius, fill=Theme.SURFACE, outline=Theme.BORDER, width=2)

        # Inner native entry
        self.entry = tk.Entry(self, bg=Theme.SURFACE, fg=Theme.TEXT, insertbackground=Theme.TEXT,
                              relief='flat', highlightthickness=0, font=Font.FONT, show=show)
        self.entry.place(relx=0.05, rely=0.1, relwidth=0.9, relheight=0.8)

        self._show = show
        self._placeholder = placeholder
        self._placeholder_active = False
        if placeholder:
            self.entry.bind('<FocusIn>', self._clear_placeholder)
            self.entry.bind('<FocusOut>', self._restore_placeholder)
            self._restore_placeholder()

    def _clear_placeholder(self, event=None):
        if self._placeholder_active:
            self._placeholder_active = False
            self.entry.delete(0, 'end')
            self.entry.configure(fg=Theme.TEXT, show=self._show)

    def _restore_placeholder(self, event=None):
        if not self._placeholder or self.entry.get():
            return
        self._placeholder_active = True
        self.entry.configure(show='', fg=Theme.BORDER)  # unmask so hint isn't asterisks
        self.entry.delete(0, 'end')
        self.entry.insert(0, self._placeholder)

    def get(self):
        return '' if self._placeholder_active else self.entry.get()

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
        
        self.label = tk.Label(self, text=text, bg=Theme.BG, fg=Theme.TEXT, font=Font.FONT)
        self.label.pack(side="left")
        
        # Bind clicks on both the box and the label
        self.canvas.bind("<Button-1>", self.toggle)
        self.label.bind("<Button-1>", self.toggle)
        
        self._draw()

    def _draw(self):

        self.canvas.delete("all")
        s = getattr(self.winfo_toplevel(), 'ui_scale', 1.0)
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
        
        self.label = tk.Label(self, text=text, bg=Theme.BG, fg=Theme.TEXT, font=Font.FONT)
        self.label.pack(side="left")
        
        self.canvas.bind("<Button-1>", self.toggle)
        self.label.bind("<Button-1>", self.toggle)
        
        self._draw()

    def _draw(self):

        self.canvas.delete("all")
        
        # Grab the current zoom multiplier from the main window
        s = getattr(self.winfo_toplevel(), 'ui_scale', 1.0)
        
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
    ''' DPI-aware popup window that inherits scale from its master and prevents white-flash
        Pattern per stdlib tkinter.simpledialog: deiconify -> wait_visibility -> grab_set.
    '''

    def __init__(self, master, title="Popup", width=400, height=300):
        super().__init__(master)
        self.withdraw() # Prevent white flash; stays hidden until show()

        self.title(title)
        self.configure(bg=Theme.BG)
        # Windows-only DWM call; the HWND already exists while withdrawn, and
        # styling it pre-reveal avoids a light->dark titlebar flicker.
        set_dark_titlebar(self)

        # Inherit UI scale from the parent window
        self.ui_scale = getattr(master, 'ui_scale', 1.0)
        scaled_w = int(width * self.ui_scale)
        scaled_h = int(height * self.ui_scale)

        x = (self.winfo_screenwidth() // 2) - (scaled_w // 2)
        y = (self.winfo_screenheight() // 2) - (scaled_h // 2)
        self.geometry(f'{scaled_w}x{scaled_h}+{x}+{y}')

        self.transient(master)  # WM hint only - safe while withdrawn


    def show(self):
        ''' Apply zoom, reveal, and take the modal grab once X11 allows it '''

        if hasattr(self.master, '_apply_zoom'):
            self.master._apply_zoom(self)
        try:
            # Many WMs never map a transient of an unmapped master - and the
            # PIN dialog must still appear when the dashboard is hidden/tray.
            if not self.master.winfo_viewable():
                self.transient('')
        except tk.TclError:
            pass
        self.deiconify()
        self.attributes('-topmost', True)
        grab_when_viewable(self)


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
    def configure(self, *args, **kwargs): return self.text.configure(*args, **kwargs)
    def cget(self, key): return self.text.cget(key)
    def see(self, *args, **kwargs): self.text.see(*args, **kwargs)


class Listbox(Frame):
    ''' Composite widget: Rounded Frame + tk.Listbox + Custom Scrollbar '''
    
    def __init__(self, master, width=400, height=200, corner_radius=10, **kwargs):
        super().__init__(master, width=width, height=height, corner_radius=corner_radius)
        
        self.scrollbar = Scrollbar(self.inner, command=self._yview)
        self.scrollbar.pack(side='right', fill='y', padx=(0, 2))
        
        list_kwargs = dict(bg=Theme.SURFACE, fg=Theme.TEXT, selectbackground=Theme.PRIMARY, 
                           selectforeground='white', relief='flat', borderwidth=0, 
                           font=(Font.FAMILY, 10), highlightthickness=0)
        list_kwargs.update(kwargs)
        
        self.listbox = tk.Listbox(self.inner, yscrollcommand=self.scrollbar.set, **list_kwargs)
        self.listbox.pack(side='left', fill='both', expand=True)

    # Proxy methods to the native listbox widget
    def _yview(self, *args): self.listbox.yview(*args)
    def insert(self, *args, **kwargs): self.listbox.insert(*args, **kwargs)
    def delete(self, *args, **kwargs): self.listbox.delete(*args, **kwargs)
    def configure(self, *args, **kwargs): return self.listbox.configure(*args, **kwargs)
    def cget(self, key): return self.listbox.cget(key)
    def curselection(self): return self.listbox.curselection()
    def selection_set(self, *args): self.listbox.selection_set(*args)
    def bind(self, sequence=None, command=None, add=True):
        # Force add=True: replacing bindings would silently kill internal callbacks
        if not (add is True or add == '+'):
            raise ValueError("Listbox.bind requires add=True (or '+') to preserve internal callbacks")
        return self.listbox.bind(sequence, command, add=True)
    def focus_set(self): self.listbox.focus_set()


