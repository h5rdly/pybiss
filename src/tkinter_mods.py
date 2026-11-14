'''pybiss tkinter_mods: a theme, DPI tracking, rounded widgets, a canvas ListView and a file
dialog over plain tkinter, stdlib only. This ONE file is vendored byte-identical into other
projects (torx: python/torx/gui/tkinter_mods.py, libiso, wasp: wasp/app/tkinter_mods.py) and re-synced with `cp`; `__version__` says
which copy a project carries, so drift is a version diff. Keep it free of anything specific
to one project: an app plugs its own widgets in through the spec registry, never here.

Tk rules learned the hard way (each cost a debugging session; see wasp/README.md "Tk
facts" for the long form):

- after() timers: tkinter names the Tcl command of a callback after id(callable) and
  deletes that command when the timer fires. So (1) keep ONE callable object per timer
  for the widget's life (a fresh bound method per call can reuse an id), and (2) a
  callback that is also called directly must after_cancel() its own pending timer
  first; otherwise a second pending timer fires into a deleted command and Tk prints
  'invalid command name "..._render"'. Cancel every timer in destroy().
- Tk 8.6 on X11 double-scales pixel font sizes on HiDPI: a negative -size goes through
  `tk scaling` (screen mm) and Xft renders at Xft.dpi. Window.adopt_tk_scaling() exists
  for an app that sets `tk scaling` to the real pixels-per-point on purpose.
- Tk draws text left to right in string order: no bidi, shaping or mirroring. The
  python-build-standalone Tk 9 on Linux (what uv installs) has no Xft at all.
- Font sizes are integers; a canvas text item is never narrower than the requested
  size suggests, so round a computed size down, not to nearest.'''
__version__ = '0.6.2'

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
                except tk.TclError, AttributeError, TypeError:
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
        except tk.TclError, ValueError:
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
        except OSError, AttributeError:
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
        self._timer = window.after(self.poll_interval, self._poll)

    def stop(self):
        ''' Cancel the pending check. A window must do this before it is destroyed: the
            timer outlives the widget, and firing afterwards it finds its callback gone
            ("invalid command name") the next time any Tk event loop in the thread runs. '''
        timer, self._timer = self._timer, None
        if timer is not None:
            try:
                self.window.after_cancel(timer)
            except Exception:
                pass

    def _poll(self):
        self._timer = None
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
            self._timer = self.window.after(delay, self._poll)
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
    
    def __init__(self, title="App", zoom_ui=True):
        ''' zoom_ui=False leaves Ctrl+wheel / Ctrl+plus / Ctrl+minus unbound: an app whose
            zoom means "scale the document" (a page viewer) binds them itself. '''

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
        self._blank_icon = tk.PhotoImage(master=self, width=1, height=1)   # ours, not the first root's
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
        
        if zoom_ui:
            # Windows/Linux bindings
            self.bind('<Control-MouseWheel>', self._on_mousewheel_zoom)
            self.bind('<Control-plus>', self._zoom_in)
            self.bind('<Control-equal>', self._zoom_in)
            self.bind('<Control-minus>', self._zoom_out)

            # macOS/Linux specific scroll bindings
            self.bind('<Control-Button-4>', self._zoom_in)
            self.bind('<Control-Button-5>', self._zoom_out)

        # Re-scale when dragged onto a monitor with a different DPI
        self._dpi_tracker = DpiTracker(self, self._on_dpi_change)

    def destroy(self):
        self._dpi_tracker.stop()
        super().destroy()

    def adopt_tk_scaling(self):
        ''' Call right after changing `tk scaling` on purpose (a page viewer sets it to the
            Xft pixels-per-point so that pixel font sizes draw exactly). The new value
            becomes the DPI tracker's baseline, so the chrome keeps its size instead of
            being re-scaled as if the window had moved to another monitor. '''
        self._dpi_tracker.scale = get_window_dpi_scale(self) or self._dpi_tracker.scale

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
        
        except tk.TclError, ValueError:
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
    ''' A rounded-thumb scrollbar that drives any widget's yview/xview through `command`
        ("moveto" fraction); `orient` is 'vertical' (default) or 'horizontal'. '''

    def __init__(self, master, command, width=12, orient='vertical', **kwargs):

        self.horizontal = orient.startswith('h')
        size = {'height': width} if self.horizontal else {'width': width}
        super().__init__(master, bg=Theme.BG, highlightthickness=0, **size, **kwargs)
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


    def _length(self):
        return (self.winfo_width() if self.horizontal else self.winfo_height()) or 1

    def _draw(self):

        self.delete('all')
        h = _even(self.winfo_height())
        w = _even(self.winfo_width())
        if self.horizontal:
            x1, x2 = scrollbar_thumb_bounds(self.start_val, self.end_val, w)
            draw_rounded_rect(self, x1+2, 2, x2-2, h-2, (h-4)/2, fill=Theme.BORDER, outline='')
        else:
            y1, y2 = scrollbar_thumb_bounds(self.start_val, self.end_val, h)
            draw_rounded_rect(self, 2, y1+2, w-2, y2-2, (w-4)/2, fill=Theme.BORDER, outline='')

    def _on_click(self, event):
        length = self._length()
        pos = event.x if self.horizontal else event.y
        a, b = scrollbar_thumb_bounds(self.start_val, self.end_val, length)
        frac = pos / length
        if a <= pos <= b:
            # Grab the thumb: keep the grabbed point under the cursor while dragging
            self._grab_offset = frac - self.start_val
        else:
            # Click on the track: page-jump, centring the thumb on the cursor
            self._grab_offset = (self.end_val - self.start_val) / 2
        self._apply_drag(pos)

    def _on_drag(self, event):
        self._apply_drag(event.x if self.horizontal else event.y)

    def _apply_drag(self, pos):
        length = self._length()
        new_start = scrollbar_drag_start(pos / length, self._grab_offset, self.end_val - self.start_val)
        self.command('moveto', str(new_start))


class Button(tk.Canvas):

    def __init__(self, master, text, command, width=120, height=32, font_size=None, 
                 corner_radius=8, fg_color=Theme.PRIMARY, hover_color=Theme.HOVER):
        super().__init__(master, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.command = command
        self.text = text
        self.font_size = font_size      # points before scaling; None = the button default (11)
        self.fg_color = fg_color
        self.hover_color = hover_color
        self.corner_radius = corner_radius
        self.rect_id = None
        self.text_id = None
        self.enabled = True
        
        self.bind('<Configure>', self._draw)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
        self.bind('<ButtonRelease-1>', self._on_release)
        self._draw()                    # at the requested size; <Configure> redraws at the real one

    def _draw(self, event=None):

        self.delete('all')
        w, h = _even(self.winfo_width()), _even(self.winfo_height())
        if w <= 1 or h <= 1:                       # not laid out yet: the requested size
            w, h = _even(int(self.cget('width'))), _even(int(self.cget('height')))
        if w <= 1 or h <= 1:
            return

        tl = self.winfo_toplevel()
        # getattr fallbacks: a bare-toplevel host renders unscaled buttons
        # instead of NO buttons (an AttributeError here is swallowed by Tk)
        s = getattr(tl, 'ui_scale', 1.0)                  # geometry: absolute factor
        fscale = getattr(tl, 'font_scale', s)             # font: zoom * DPI ratio
        radius = self.corner_radius * s
        font = (Font.FAMILY, int((self.font_size or 11)*fscale), 'bold')

        needed = tkfont.Font(family=Font.FAMILY, size=int((self.font_size or 11)*fscale),
                             weight='bold').measure(self.text) + int(24*fscale)
        if needed > w:
            self.config(width=needed)
            w = _even(needed)

        self.rect_id = draw_rounded_rect(self, 0, 0, w, h, radius, fill=self.fg_color if self.enabled else Theme.SURFACE)

        self.text_id = self.create_text(w/2, h/2, text=self.text, fill=Theme.TEXT if self.enabled else Theme.TEXT_MUTED,
                                        font=font)


    def _on_enter(self, event):
        if self.enabled and self.rect_id:
            self.itemconfig(self.rect_id, fill=self.hover_color)

    def _on_leave(self, event):
        if self.enabled and self.rect_id:
            self.itemconfig(self.rect_id, fill=self.fg_color)

    def _on_click(self, event):
        self.move(self.text_id, 0, 1) # Subtle click depression

    def _on_release(self, event):
        self.move(self.text_id, 0, -1)                     # undo the click depression (_on_click moved +1)
        if not self.enabled:
            return
        # Conventional button: fire only if released inside. Press gives the canvas an
        # implicit pointer grab, so a drag-off-and-release still arrives here with
        # out-of-bounds coords - that is the user cancelling the click. A None event
        # (programmatic / tests) has no coords and counts as inside.
        inside = event is None or (0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height())
        if self.rect_id:                                   # pointer still over -> hover, else resting
            self.itemconfig(self.rect_id, fill=self.hover_color if inside else self.fg_color)
        if inside and self.command:
            self.command()

    def set_enabled(self, enabled: bool):
        ''' A disabled button is drawn flat on the surface colour and ignores clicks. '''
        self.enabled = bool(enabled)
        self._draw()


class Entry(tk.Frame):

    def __init__(self, master, width=200, height=35, corner_radius=6, show='', placeholder=''):
        super().__init__(master, bg=Theme.BG)
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self.corner_radius = corner_radius

        # Draw Border (again whenever the canvas is resized: an entry packed with fill='x'
        # grows with its window, and the border has to follow)
        self._draw_border(width, height)
        self.canvas.bind('<Configure>', lambda e: self._draw_border(e.width, e.height))

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

    def _draw(self):
        ''' Theme.apply_live: repaint the border in the new colours '''
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        if w <= 1 or h <= 1:                       # not laid out yet: the requested size
            w, h = int(self.canvas.cget('width')), int(self.canvas.cget('height'))
        self._draw_border(w, h)

    def _draw_border(self, width, height):
        self.canvas.delete('border')
        draw_rounded_rect(self.canvas, 1, 1, width - 1, height - 1, self.corner_radius,
                          fill=Theme.SURFACE, outline=Theme.BORDER, width=2, tags='border')

    def get(self) -> str:
        ''' The text, or '' while the placeholder shows. '''
        return '' if self._placeholder_active else self.entry.get()

    def set(self, text: str):
        ''' Replace the text; an empty text brings the placeholder back. '''
        self._clear_placeholder()
        self.entry.delete(0, 'end')
        self.entry.insert(0, text)
        if not text:
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

    def focus(self): self.entry.focus()


class ProgressBar(tk.Canvas):
    ''' A rounded track with a filled part and an optional centred text ("1.2 GB / 4.3 GB"). '''

    def __init__(self, master, width=300, height=20, corner_radius=6):
        super().__init__(master, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.fraction = 0.0
        self.text = ''
        self.corner_radius = corner_radius
        self.bind('<Configure>', self._draw)

    def set(self, fraction, text=None):
        self.fraction = min(1.0, max(0.0, float(fraction)))
        if text is not None:
            self.text = text
        self._draw()

    def get(self):
        return self.fraction

    def _draw(self, event=None):
        self.delete('all')
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 1 or h <= 1:
            w, h = int(self.cget('width')), int(self.cget('height'))
        s = getattr(self.winfo_toplevel(), 'ui_scale', 1.0)
        r = self.corner_radius * s
        draw_rounded_rect(self, 1, 1, w - 1, h - 1, r, fill=Theme.SURFACE, outline=Theme.BORDER, width=1)
        fill_w = int((w - 2) * self.fraction)
        if fill_w > 2 * r:
            draw_rounded_rect(self, 1, 1, 1 + fill_w, h - 1, r, fill=Theme.PRIMARY, outline='')
        elif fill_w > 0:
            self.create_rectangle(1, 1, 1 + fill_w, h - 1, fill=Theme.PRIMARY, outline='')
        if self.text:
            fs = getattr(self.winfo_toplevel(), 'font_scale', 1.0)
            self.create_text(w / 2, h / 2, text=self.text, fill=Theme.TEXT, font=(Font.FAMILY, int(10 * fs)))


class Dropdown(tk.Canvas):
    ''' A combo box: the current value on a rounded surface with a chevron; a click opens a
    borderless list beneath it; choosing calls ``command(value)``. ``set_items`` replaces the
    choices and keeps the current value when it is still among them. '''

    def __init__(self, master, items=(), command=None, width=200, height=32, corner_radius=6, placeholder=''):
        super().__init__(master, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.items = list(items)
        self.value = self.items[0] if self.items else None
        self.command = command
        self.placeholder = placeholder
        self.corner_radius = corner_radius
        self._popup = None
        self.bind('<Configure>', self._draw)
        self.bind('<Button-1>', self.open)
        self.bind('<Enter>', lambda e: self._draw(hover=True))
        self.bind('<Leave>', lambda e: self._draw())

    def get(self):
        return self.value

    def set(self, value, notify=False):
        self.value = value if value in self.items else None
        self._draw()
        if notify and self.command:
            self.command(self.value)

    def set_items(self, items, notify=True):
        ''' Replace the choices; the value stays when still listed, else becomes the first. '''
        self.items = list(items)
        old = self.value
        self.value = old if old in self.items else (self.items[0] if self.items else None)
        self._draw()
        if notify and self.value != old and self.command:
            self.command(self.value)

    def _draw(self, event=None, hover=False):
        self.delete('all')
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 1 or h <= 1:
            w, h = int(self.cget('width')), int(self.cget('height'))
        s = getattr(self.winfo_toplevel(), 'ui_scale', 1.0)
        fs = getattr(self.winfo_toplevel(), 'font_scale', 1.0)
        draw_rounded_rect(self, 1, 1, w - 1, h - 1, self.corner_radius * s, fill=Theme.SURFACE,
                          outline=Theme.PRIMARY if hover else Theme.BORDER, width=1)
        text = self.value if self.value is not None else self.placeholder
        f = tkfont.Font(family=Font.FAMILY, size=int(11 * fs))
        text = listview_elide(str(text), max(10, w - int(40 * s)), f.measure)
        self.create_text(int(12 * s), h / 2, text=text, anchor='w', font=f,
                         fill=Theme.TEXT if self.value is not None else Theme.TEXT_MUTED)
        cx, cy = w - int(16 * s), h / 2
        self.create_line(cx - 5 * s, cy - 2 * s, cx, cy + 3 * s, cx + 5 * s, cy - 2 * s,
                         fill=Theme.TEXT_MUTED, width=max(1, int(2 * s)))

    def open(self, event=None):
        if self._popup or not self.items:
            return
        fs = getattr(self.winfo_toplevel(), 'font_scale', 1.0)
        pop = self._popup = tk.Toplevel(self)
        pop.overrideredirect(True)
        pop.configure(bg=Theme.BORDER)
        lb = tk.Listbox(pop, bg=Theme.SURFACE, fg=Theme.TEXT, selectbackground=Theme.PRIMARY,
                        selectforeground=Theme.TEXT, relief='flat', borderwidth=0, highlightthickness=0,
                        activestyle='none', font=(Font.FAMILY, int(11 * fs)), height=min(8, len(self.items)))
        lb.pack(fill='both', expand=True, padx=1, pady=1)
        for it in self.items:
            lb.insert('end', it)
        if self.value in self.items:
            lb.selection_set(self.items.index(self.value))
        x, y = self.winfo_rootx(), self.winfo_rooty() + self.winfo_height()
        pop.geometry('%dx%d+%d+%d' % (max(self.winfo_width(), 100), lb.winfo_reqheight() + 2, x, y))
        lb.bind('<ButtonRelease-1>', lambda e: self._choose(lb))
        lb.bind('<Return>', lambda e: self._choose(lb))
        lb.bind('<Escape>', lambda e: self.close())
        lb.bind('<FocusOut>', lambda e: self.close())
        lb.focus_set()

    def _choose(self, lb):
        sel = lb.curselection()
        self.close()
        if sel:
            self.set(self.items[sel[0]], notify=True)

    def close(self):
        if self._popup:
            try:
                self._popup.destroy()
            except tk.TclError:
                pass
            self._popup = None


class Frame(tk.Frame):

    def __init__(self, master, width=400, height=200, corner_radius=10):

        super().__init__(master, bg=Theme.BG)
        self.corner_radius = corner_radius
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.BG, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self.canvas.bind('<Configure>', lambda e: self._draw())

        # A flat frame inside the canvas to hold child widgets (like Listbox/Text)
        self.inner = tk.Frame(self, bg=Theme.SURFACE)
        self.inner.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        self._draw()

    def _draw(self):
        ''' The rounded border at the canvas's real size, in the current palette (a subclass that
        proxies ``configure`` to its text widget, like Textbox, is retinted here on a theme switch). '''
        c = self.canvas
        w, h = c.winfo_width(), c.winfo_height()
        if w <= 1 or h <= 1:
            w, h = int(c.cget('width')), int(c.cget('height'))
        c.delete('all')
        tk.Frame.configure(self, bg=Theme.BG)
        c.configure(bg=Theme.BG)
        self.inner.configure(bg=Theme.SURFACE)
        draw_rounded_rect(c, 1, 1, w - 1, h - 1, self.corner_radius, fill=Theme.SURFACE, outline=Theme.BORDER, width=1)


def points_to_px(widget):
    ''' Device pixels per typographic point for the screen this widget is on (Tk's own
        `tk scaling`, which already includes the monitor DPI); a page viewer multiplies its
        point geometry by this and by its zoom, never by `Window.ui_scale`. '''
    try:
        return float(widget.winfo_fpixels('1p'))
    except tk.TclError:
        return 96.0 / 72.0


class Viewport(tk.Frame):
    '''
    A canvas with both Scrollbars and the usual scroll gestures wired: mouse wheel and
    Button-4/5 scroll vertically, Shift+wheel and Button-6/7 horizontally, Page Up/Down,
    Home/End and the arrow keys when the canvas has focus (a click gives it focus).
    The app draws on ``.canvas`` and calls ``set_content_size(w, h)``; ``on_scroll``,
    when given, is called with no arguments after every scroll (for lazy rendering).
    '''

    wheel_step = 3          # scroll units per wheel notch (Tk's default)

    def __init__(self, master, bg=None, on_scroll=None, bar_width=12, **kwargs):

        super().__init__(master, bg=Theme.BG, **kwargs)
        self.on_scroll = on_scroll
        self.canvas = tk.Canvas(self, bg=bg or Theme.SURFACE, highlightthickness=0,
                                xscrollcommand=self._xset, yscrollcommand=self._yset)
        self.vbar = Scrollbar(self, self.canvas.yview, width=bar_width)
        self.hbar = Scrollbar(self, self.canvas.xview, width=bar_width, orient='horizontal')
        self.canvas.grid(row=0, column=0, sticky='nsew')
        self.vbar.grid(row=0, column=1, sticky='ns')
        self.hbar.grid(row=1, column=0, sticky='ew')
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        c = self.canvas
        c.bind('<Button-1>', lambda e: c.focus_set(), add='+')
        c.bind('<MouseWheel>', self._wheel)
        c.bind('<Shift-MouseWheel>', lambda e: self._wheel(e, horizontal=True))
        c.bind('<Button-4>', lambda e: self._scroll('y', -self.wheel_step))
        c.bind('<Button-5>', lambda e: self._scroll('y', self.wheel_step))
        c.bind('<Shift-Button-4>', lambda e: self._scroll('x', -self.wheel_step))
        c.bind('<Shift-Button-5>', lambda e: self._scroll('x', self.wheel_step))
        try:
            c.bind('<Button-6>', lambda e: self._scroll('x', -self.wheel_step))   # X11 horizontal wheel; Tk 9 only
            c.bind('<Button-7>', lambda e: self._scroll('x', self.wheel_step))
        except tk.TclError:
            pass                                                                 # Tk 8.6: "bad button number"
        c.bind('<Prior>', lambda e: self._scroll('y', -1, 'pages'))
        c.bind('<Next>', lambda e: self._scroll('y', 1, 'pages'))
        c.bind('<Home>', lambda e: self._moveto('y', 0.0))
        c.bind('<End>', lambda e: self._moveto('y', 1.0))
        c.bind('<Up>', lambda e: self._scroll('y', -1))
        c.bind('<Down>', lambda e: self._scroll('y', 1))
        c.bind('<Left>', lambda e: self._scroll('x', -1))
        c.bind('<Right>', lambda e: self._scroll('x', 1))
        c.bind('<Configure>', lambda e: self._notify())

    # -- scrolling -----------------------------------------------------------
    def _wheel(self, event, horizontal=False):
        # Windows: multiples of 120 per notch; macOS: small signed counts
        delta = event.delta
        steps = -int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
        self._scroll('x' if horizontal else 'y', steps * self.wheel_step)
        return 'break'

    def _scroll(self, axis, amount, what='units'):
        if amount == 0:
            return 'break'
        view = self.canvas.xview if axis == 'x' else self.canvas.yview
        view('scroll', int(amount), what)
        self._notify()
        return 'break'

    def _moveto(self, axis, frac):
        view = self.canvas.xview if axis == 'x' else self.canvas.yview
        view('moveto', str(frac))
        self._notify()
        return 'break'

    def _xset(self, a, b):
        self.hbar.set(a, b)
        self._notify()

    def _yset(self, a, b):
        self.vbar.set(a, b)
        self._notify()

    def _notify(self):
        if self.on_scroll is not None:
            try:
                self.on_scroll()
            except tk.TclError:
                pass

    # -- content -------------------------------------------------------------
    def set_content_size(self, width, height):
        ''' The scrollable extent in canvas pixels. '''
        self.canvas.configure(scrollregion=(0, 0, int(width), int(height)))
        self.canvas.configure(xscrollincrement=20, yscrollincrement=20)

    def visible_box(self):
        ''' (x0, y0, x1, y1) of the viewport in canvas coordinates. '''
        c = self.canvas
        x0 = c.canvasx(0)
        y0 = c.canvasy(0)
        return x0, y0, x0 + c.winfo_width(), y0 + c.winfo_height()

    def _draw(self):
        ''' Theme.apply_live hook: the chrome follows the palette; the canvas keeps its own bg. '''
        tk.Frame.configure(self, bg=Theme.BG)


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




# --- ListView: a canvas-drawn, virtualised table/list ---
#
# The row behaviour of CTkListbox (hover, rounded selection, shift ranges, see/move) without
# a widget per row: one Canvas draws only the rows in view, so ten thousand rows cost the
# same as thirty. Columns, a sortable header and progress cells are what a torrent list
# needs and what tk.Listbox / ttk.Treeview cannot draw. The geometry lives in pure functions
# (tested without a display); the widget is the thin Tk skin over them.

def listview_column_layout(widths, total, min_w=40, gap=0, stretch_floor=0.0):
    ''' Pixel (x, w) per column for `widths` (int = fixed px, 0 = stretch to share the
        leftover). Stretch columns never go under `min_w`; fixed ones keep their width,
        unless `stretch_floor` (a fraction of the usable width) is given: then the stretch
        columns are guaranteed that share and the fixed ones shrink in proportion when the
        widget is too narrow for everything (a name column must not vanish). '''

    n = len(widths)
    if n == 0:
        return []
    widths = list(widths)
    stretch = [i for i, w in enumerate(widths) if w <= 0]
    usable = total - gap * (n - 1)
    fixed = sum(w for w in widths if w > 0)
    if stretch and stretch_floor > 0 and fixed > 0:
        floor = max(min_w, int(usable * stretch_floor)) * len(stretch)
        if fixed + floor > usable:
            scale = max(0, usable - floor) / fixed
            widths = [max(1, int(w * scale)) if w > 0 else w for w in widths]
            fixed = sum(w for w in widths if w > 0)
    leftover = usable - fixed
    share = max(min_w, leftover // len(stretch)) if stretch else 0
    out, x = [], 0
    for i, w in enumerate(widths):
        w = share if i in stretch else w
        out.append((x, w))
        x += w + gap
    return out


def listview_visible_range(scroll_px, viewport_h, row_h, n):
    ''' [first, last) rows intersecting a viewport that starts `scroll_px` into the content '''

    if n <= 0 or row_h <= 0 or viewport_h <= 0:
        return 0, 0
    first = max(0, int(scroll_px) // row_h)
    last = min(n, (int(scroll_px) + int(viewport_h) - 1) // row_h + 1)
    return first, max(first, last)


def listview_row_at(y, scroll_px, top, row_h, n, bottom=None):
    ''' Row index under viewport pixel `y` (rows start at `top`, the viewport ends at
        `bottom` when given), or None off the rows '''

    if row_h <= 0 or y < top or (bottom is not None and y >= bottom):
        return None
    i = (int(y) - top + int(scroll_px)) // row_h
    return i if 0 <= i < n else None


def listview_clamp_scroll(scroll_px, content_h, viewport_h):
    return max(0, min(int(scroll_px), max(0, content_h - viewport_h)))


def listview_scroll_fraction(scroll_px, content_h, viewport_h):
    ''' (start, end) in 0..1 for a scrollbar's set(); the whole track when it all fits '''

    if content_h <= viewport_h or content_h <= 0:
        return 0.0, 1.0
    start = scroll_px / content_h
    return start, min(1.0, start + viewport_h / content_h)


def listview_sort_key(value):
    ''' Orders None last, then numbers before text, text case-insensitively; never raises
        on mixed columns (a torrent list has "?" next to numbers) '''

    if value is None:
        return (2, 0, '')
    if isinstance(value, bool):
        return (0, int(value), '')
    if isinstance(value, (int, float)):
        return (0, value, '')
    return (1, 0, str(value).casefold())


def listview_sorted(indices, rows, key, reverse=False):
    ''' Row indices in display order by `key` (a row's `_sort[key]` beats its `key`) '''

    def k(i):
        r = rows[i]
        sort = r.get('_sort') if isinstance(r, dict) else None
        v = sort.get(key, r.get(key)) if sort else r.get(key)
        return listview_sort_key(v)
    return sorted(indices, key=k, reverse=reverse)


def listview_range(anchor, index):
    ''' The inclusive index range a shift-click selects '''

    lo, hi = (anchor, index) if anchor <= index else (index, anchor)
    return range(lo, hi + 1)


def listview_elide(text, max_w, measure, ellipsis='…'):
    ''' Cut `text` to fit `max_w` pixels under `measure(str) -> px`, ending in an ellipsis;
        binary search so a long cell costs log(len) measures '''

    if measure(text) <= max_w:
        return text
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if measure(text[:mid] + ellipsis) <= max_w:
            lo = mid
        else:
            hi = mid - 1
    if lo > 0:
        return text[:lo] + ellipsis
    return ellipsis if measure(ellipsis) <= max_w else ''


def listview_border_at(x, layout, tolerance=4):
    ''' Index i of the border between visible columns i and i+1 that `x` (relative to the
        first column's left edge) is on, else None. The border sits in the middle of the
        gap between the two. '''

    for i in range(len(layout) - 1):
        edge = (layout[i][0] + layout[i][1] + layout[i + 1][0]) / 2
        if abs(x - edge) <= tolerance:
            return i
    return None


def listview_drag_widths(widths, actual, i, delta, min_w):
    ''' New widths after the border between columns i and i+1 moved by `delta` (positive =
        right). `widths` are the set widths (0 = stretch), `actual` what each column
        currently occupies, all in one unit. The border follows the pointer: two fixed
        neighbours trade width; next to a stretch column only the fixed one changes and
        the stretch column absorbs it, never going under `min_w`. '''

    out = list(widths)
    left, right = widths[i], widths[i + 1]
    if left > 0 and right > 0:
        d = max(min_w - left, min(delta, right - min_w))
        out[i], out[i + 1] = left + d, right - d
    elif left > 0:                      # right neighbour stretches
        d = max(min_w - left, min(delta, actual[i + 1] - min_w))
        out[i] = left + d
    elif right > 0:                     # left neighbour stretches
        d = min(right - min_w, max(delta, min_w - actual[i]))
        out[i + 1] = right - d
    return out


def listview_drop_index(x, layout):
    ''' Where a column dropped at `x` lands: the visible index it is inserted before
        (len(layout) = after the last), by the columns' midpoints. '''

    for i, (cx, cw) in enumerate(layout):
        if x < cx + cw / 2:
            return i
    return len(layout)


def listview_move_key(order, hidden, key, to):
    ''' `order` with `key` moved to position `to` among the other visible columns (so it
        sits before the one currently at that index, or last when `to` is past the end).
        Hidden columns keep their places relative to their neighbours. '''

    visible = [k for k in order if k not in hidden and k != key]
    rest = [k for k in order if k != key]
    if to >= len(visible):
        at = (rest.index(visible[-1]) + 1) if visible else len(rest)
    else:
        at = rest.index(visible[max(0, to)])
    return rest[:at] + [key] + rest[at:]


def listview_merge_state(columns, state):
    ''' (order, widths, hidden) for the column definitions `columns` given a saved `state`
        (a list of {'key', 'width', 'hidden'}; anything malformed is ignored). Saved columns
        keep their saved order and width; definitions the state does not know appear after
        the nearest preceding definition that is placed; keys the definitions no longer
        have are dropped; a 'required' column is never hidden; and at least one column
        stays visible. '''

    keys = [c['key'] for c in columns]
    by = {c['key']: c for c in columns}
    order, widths, hidden = [], {k: by[k]['width'] for k in keys}, set()
    for e in state if isinstance(state, (list, tuple)) else ():
        if not isinstance(e, dict) or e.get('key') not in by or e['key'] in order:
            continue
        k = e['key']
        order.append(k)
        w = e.get('width')
        # a stretch column stays one; a fixed one takes any sane saved width
        if isinstance(w, (int, float)) and not isinstance(w, bool) and by[k]['width'] > 0 and 1 <= w <= 500:
            widths[k] = w
        if e.get('hidden') and not by[k].get('required'):
            hidden.add(k)
    for i, k in enumerate(keys):
        if k in order:
            continue
        before = [p for p in keys[:i] if p in order]
        order.insert(order.index(before[-1]) + 1 if before else 0, k)
    if all(k in hidden for k in order):
        hidden.discard(order[0])
    return order, widths, hidden


class ListView(tk.Frame):
    '''
    Columns: [(key, title, width, align)] or with a 5th 'kind' of 'text' (default) or
    'progress' (value 0..1 or None; a row's `<key>_text` replaces the percentage label, and
    shows alone when the value is None). width is in CHARACTERS of the list font (like
    tk.Listbox), 0 = stretch, so the layout follows the font on any DPI; row height
    defaults to 1.7 line heights of that font. Rows are dicts (display values by
    key; an optional '_sort' dict gives sort values; an 'id' key keeps the selection across
    set_rows). Plain strings may be inserted for single-column lists ({'text': s}).

    Selection API mirrors tk.Listbox / CTkListbox: insert, delete, get, size, curselection,
    select / deselect / selection_set / selection_clear, see, move_up, move_down; plus
    set_rows (replace everything, keep selection by id), sort(key), nearest(y). Events:
    <<ListboxSelect>> on any selection change, <<ListboxActivate>> on double-click / Return;
    `command(selected)` is called with the selected item (or list when multiple).
    Right-click handlers bind on the widget and use nearest(event.y).

    Columns are the user's to arrange: drag a header border to resize (the two neighbours
    trade width; double-click fits the left one to its content), drag a header title to
    reorder, right-click the header to hide or show columns or reset them. A plain click on
    a title still sorts. A column tuple may end with a dict of extras: {'required': True}
    keeps it out of the hide menu. column_state() / set_column_state() save and restore the
    arrangement (widths in characters, so it survives zoom and DPI changes); after every
    change the user makes `columns_command(state)` is called and <<ListViewColumns>> fires.
    '''

    def __init__(self, master, columns=None, rows=None, row_height=None, header=True,
                 multiple=True, command=None, width=400, height=200, corner_radius=8,
                 hover=True, font_size=10, stretch_floor=0.3,
                 columns_command=None):
        super().__init__(master, bg=Theme.BG)
        self.columns = [self._norm_column(c) for c in (columns or [('text', '', 0, 'w')])]
        self.row_height = row_height
        self.show_header = header and any(c['title'] for c in self.columns)
        self.multiple = multiple
        self.command = command
        self.hover = hover
        self.font_size = font_size
        # share of the width the stretch column(s) keep when the widget is narrow
        self.stretch_floor = stretch_floor
        self.corner_radius = corner_radius
        self.pad = 4
        self._rows = []            # display dicts
        self._items = []           # what the caller inserted (returned by get)
        self._order = []           # display order -> row index
        self._selected = set()     # row indices
        self._anchor = None        # for shift ranges and keyboard moves
        self._hover = None         # display position under the mouse
        self._scroll = 0           # px into the content
        self._sort_key = None
        self._sort_reverse = False
        self._layout = ()
        self._last_geometry = None
        self._view = []            # the visible columns, in display order, as drawn
        self._x0 = 0               # canvas x of the first column
        self._char_w = 1
        self._press = None         # a header gesture in progress
        self._drop = None          # visible index a dragged column would land before
        self.column_menu = True    # right-click on the header offers hide / show / reset
        self.columns_command = columns_command
        self._init_columns()

        self.scrollbar = Scrollbar(self, command=self.yview)
        self.scrollbar.pack(side='right', fill='y', padx=(0, 2))
        self.canvas = tk.Canvas(self, width=width, height=height, bg=Theme.SURFACE,
                                highlightthickness=0, takefocus=1)
        self.canvas.pack(side='left', fill='both', expand=True)

        c = self.canvas
        c.bind('<Configure>', lambda e: self._draw())
        c.bind('<Button-1>', self._on_click)
        c.bind('<B1-Motion>', self._on_drag)
        c.bind('<ButtonRelease-1>', self._on_release)
        c.bind('<Button-3>', self._on_header_menu)
        c.bind('<Double-Button-1>', self._on_double)
        c.bind('<Motion>', self._on_motion)
        c.bind('<Leave>', self._on_leave)
        c.bind('<MouseWheel>', self._on_wheel)          # Windows / macOS
        c.bind('<Button-4>', lambda e: self._scroll_by(-3))   # X11
        c.bind('<Button-5>', lambda e: self._scroll_by(3))
        for key in ('Up', 'Down', 'Home', 'End', 'Prior', 'Next', 'Return', 'space'):
            c.bind(f'<KeyPress-{key}>', self._on_key)
        c.bind('<Control-a>', lambda e: self.select('all'))

        if rows:
            self.set_rows(rows)

    # ---- columns / rows

    @staticmethod
    def _norm_column(c):
        if isinstance(c, dict):
            d = dict(c)
        else:
            extras = [x for x in c if isinstance(x, dict)]
            c = [x for x in c if not isinstance(x, dict)]
            key, title, width, align = (list(c) + ['w'])[:4]
            d = {'key': key, 'title': title, 'width': width, 'align': align}
            if len(c) > 4:
                d['kind'] = c[4]
            for x in extras:
                d.update(x)
        d.setdefault('kind', 'text')
        d.setdefault('align', 'w')
        d.setdefault('title', '')
        d.setdefault('width', 0)
        return d

    @staticmethod
    def _as_row(item):
        return item if isinstance(item, dict) else {'text': '' if item is None else str(item)}

    # ---- column arrangement

    def _init_columns(self):
        self._col_order = [c['key'] for c in self.columns]
        self._col_width = {c['key']: c['width'] for c in self.columns}
        self._col_hidden = set()
        self._user_sized = False

    def _view_columns(self):
        ''' The visible column definitions in display order, each with its current width.
            When the stretch column is hidden the last visible one takes the spare width. '''
        by = {c['key']: c for c in self.columns}
        cols = [dict(by[k], width=self._col_width[k]) for k in self._col_order if k not in self._col_hidden]
        had_stretch = any(c['width'] <= 0 for c in self.columns)
        if cols and had_stretch and not any(c['width'] <= 0 for c in cols):
            cols[-1] = dict(cols[-1], width=0)
        return cols

    def column_state(self):
        ''' The arrangement to save: [{'key', 'width' (characters, 0 = stretch), 'hidden'}]
            in display order. '''
        return [{'key': k, 'width': self._col_width[k], 'hidden': k in self._col_hidden} for k in self._col_order]

    def set_column_state(self, state):
        ''' Restore a saved arrangement; unknown, missing and malformed entries are handled
            (see listview_merge_state). Fires no event. '''
        order, widths, hidden = listview_merge_state(self.columns, state)
        defaults = {c['key']: c['width'] for c in self.columns}
        self._col_order, self._col_width, self._col_hidden = order, widths, hidden
        self._user_sized = widths != defaults
        self._draw()

    def reset_columns(self):
        self._init_columns()
        self._columns_changed()

    def set_column_hidden(self, key, hidden=True):
        col = next((c for c in self.columns if c['key'] == key), None)
        if col is None or (hidden and col.get('required')):
            return
        if hidden:
            if len(self._col_order) - len(self._col_hidden | {key}) < 1:
                return                      # never hide the last visible column
            self._col_hidden.add(key)
        else:
            self._col_hidden.discard(key)
        self._columns_changed()

    def move_column(self, key, to):
        ''' Put column `key` at position `to` among the other visible columns. '''
        if key not in self._col_order:
            return
        new = listview_move_key(self._col_order, self._col_hidden, key, to)
        if new != self._col_order:
            self._col_order = new
            self._columns_changed()

    def fit_column(self, key):
        ''' Size a fixed column to its title and content. '''
        col = next((c for c in self.columns if c['key'] == key), None)
        if col is None or col['width'] <= 0 or col.get('kind') == 'progress':
            return
        m = self._metrics()
        measure = m['font'].measure
        widest = measure(col['title'] + ' ▲')
        for row in self._rows[:2000]:
            v = row.get(key)
            if v is not None:
                widest = max(widest, measure(str(v)))
        self._col_width[key] = max(4, -(-(widest + 12) // m['char_w']))
        self._user_sized = True
        self._columns_changed()

    def _columns_changed(self):
        self._draw()
        if self.columns_command:
            self.columns_command(self.column_state())
        try:
            self.canvas.event_generate('<<ListViewColumns>>')
        except tk.TclError:
            pass

    def header_menu_entries(self):
        ''' What the header's right-click menu offers: (label, checked, enabled, command);
            a None label is a separator. '''
        visible = len(self._col_order) - len(self._col_hidden)
        by = {c['key']: c for c in self.columns}
        out = []
        for k in self._col_order:
            shown = k not in self._col_hidden
            can = not by[k].get('required') and (not shown or visible > 1)
            out.append((by[k]['title'] or k, shown, can, lambda k=k, shown=shown: self.set_column_hidden(k, shown)))
        out.append((None, False, False, None))
        out.append(('Reset columns', False, True, self.reset_columns))
        return out

    def set_rows(self, items, keep_selection=True):
        ''' Replace every row; a selection survives by the rows' `id` values. '''

        keep = {self._rows[i].get('id') for i in self._selected} - {None} if keep_selection else set()
        self._items = list(items)
        self._rows = [self._as_row(x) for x in self._items]
        self._selected = {i for i, r in enumerate(self._rows) if r.get('id') in keep}
        if self._anchor is not None and self._anchor >= len(self._rows):
            self._anchor = None
        self._hover = None
        self._resort()
        self._draw()

    def insert(self, index, item, **_ignored):
        ''' `index`: int position or 'end'; returns the row's index. '''

        if str(index).lower() == 'end' or index >= len(self._rows):
            index = len(self._rows)
        self._items.insert(index, item)
        self._rows.insert(index, self._as_row(item))
        self._selected = {i + 1 if i >= index else i for i in self._selected}
        if self._anchor is not None and self._anchor >= index:
            self._anchor += 1
        self._resort()
        self._draw()
        return index

    def delete(self, index, last=None):
        ''' delete(i), delete(first, last) inclusive, or delete('all') '''

        if str(index).lower() == 'all':
            self._items, self._rows, self._selected, self._anchor = [], [], set(), None
            self._resort()
            self._draw()
            return
        first = int(index)
        last = first if last is None else (len(self._rows) - 1 if str(last).lower() == 'end' else int(last))
        if first < 0 or first >= len(self._rows):
            return
        last = min(last, len(self._rows) - 1)
        gone = last - first + 1
        del self._items[first:last + 1]
        del self._rows[first:last + 1]
        self._selected = {i - gone if i > last else i for i in self._selected if not first <= i <= last}
        if self._anchor is not None:
            self._anchor = None if first <= self._anchor <= last else (self._anchor - gone if self._anchor > last else self._anchor)
        self._resort()
        self._draw()

    def size(self):
        return len(self._rows)

    def get(self, index=None):
        ''' get(i) -> that item; get('all') -> every item in display order;
            get() -> the selected item (list when multiple), or None. '''

        if index is None:
            sel = self.curselection()
            if self.multiple:
                return [self._items[i] for i in sel]
            return self._items[sel[0]] if sel else None
        if str(index).lower() == 'all':
            return [self._items[i] for i in self._order]
        return self._items[int(index)]

    def item(self, index, **values):
        ''' Update fields of one row in place and redraw (a rate column ticking). '''

        self._rows[index].update(values)
        if isinstance(self._items[index], dict):
            self._items[index].update(values)
        self._draw()

    # ---- ordering

    def sort(self, key, reverse=None):
        ''' Sort by column `key`; `reverse=None` toggles when already sorted by it. '''

        if reverse is None:
            reverse = not self._sort_reverse if key == self._sort_key else False
        self._sort_key, self._sort_reverse = key, reverse
        self._resort()
        self._draw()

    def _resort(self):
        idx = range(len(self._rows))
        self._order = listview_sorted(idx, self._rows, self._sort_key, self._sort_reverse) if self._sort_key else list(idx)
        self._pos = {row: pos for pos, row in enumerate(self._order)}

    def move_up(self, index):
        if 0 < index < len(self._rows) and self._sort_key is None:
            self._swap(index, index - 1)

    def move_down(self, index):
        if 0 <= index < len(self._rows) - 1 and self._sort_key is None:
            self._swap(index, index + 1)

    def _swap(self, a, b):
        self._items[a], self._items[b] = self._items[b], self._items[a]
        self._rows[a], self._rows[b] = self._rows[b], self._rows[a]
        swap = {a: b, b: a}
        self._selected = {swap.get(i, i) for i in self._selected}
        if self._anchor in swap:
            self._anchor = swap[self._anchor]
        self._resort()
        self.see(b)
        self._draw()

    # ---- selection

    def curselection(self):
        ''' Selected row indices, in display order. '''
        return tuple(i for i in self._order if i in self._selected)

    def select(self, index, extend=False, toggle=False):
        ''' select(i) replaces the selection; extend=True adds a shift range from the
            anchor; toggle=True flips one row (ctrl-click). select('all') / select(None). '''

        n = len(self._rows)
        if index is None:
            new = set()
        elif str(index).lower() == 'all':
            new = set(range(n)) if self.multiple else set(self._selected)
        else:
            index = int(index)
            if not 0 <= index < n:
                return
            if toggle and self.multiple:
                new = set(self._selected) ^ {index}
                self._anchor = index
            elif extend and self.multiple and self._anchor is not None:
                a, b = self._pos.get(self._anchor, 0), self._pos[index]
                new = {self._order[p] for p in listview_range(a, b)}
            else:
                new = {index}
                self._anchor = index
        self._set_selection(new)

    def selection_set(self, first, last=None):
        first = int(first)
        last = first if last is None else int(last)
        new = set(self._selected) | set(range(first, last + 1)) if self.multiple else {first}
        self._set_selection({i for i in new if 0 <= i < len(self._rows)})

    def selection_clear(self, first=0, last='end'):
        last = len(self._rows) - 1 if str(last).lower() == 'end' else int(last)
        self._set_selection({i for i in self._selected if not int(first) <= i <= last})

    def deselect(self, index):
        if str(index).lower() == 'all':
            self._set_selection(set())
        else:
            self._set_selection(self._selected - {int(index)})

    def activate(self, index):
        self.select(-1 if str(index).lower() == 'end' else index)

    def _set_selection(self, new):
        if new == self._selected:
            return
        self._selected = new
        self._draw()
        try:
            self.canvas.event_generate('<<ListboxSelect>>')
        except tk.TclError:
            pass
        if self.command:
            self.command(self.get())

    # ---- geometry

    def _scale(self):
        tl = self.winfo_toplevel()
        s = getattr(tl, 'ui_scale', 1.0)
        return s, getattr(tl, 'font_scale', s)

    def _metrics(self):
        s, fs = self._scale()
        font = tkfont.Font(family=Font.FAMILY, size=int(self.font_size * fs))
        line = font.metrics('linespace')
        # rows follow the font (the display's real DPI), unless a pixel height was given
        row_h = max(1, int(self.row_height * s)) if self.row_height else max(1, int(line * 1.7))
        head_h = (int((self.row_height - 2) * s) if self.row_height else int(line * 1.5)) if self.show_header else 0
        pad = int(self.pad * s)
        # an unmapped canvas (withdrawn window, before the first layout pass) reports 1x1;
        # the requested size is what it will get, so geometry questions answer sensibly
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 1:
            w = self.canvas.winfo_reqwidth()
        if h <= 1:
            h = self.canvas.winfo_reqheight()
        top = pad + head_h
        return dict(s=s, fs=fs, row_h=row_h, head_h=head_h, pad=pad, w=w, h=h, top=top,
                    view_h=max(0, h - top - pad), content_h=row_h * len(self._rows),
                    font=font, char_w=max(1, font.measure('0')))

    def nearest(self, y):
        ''' Row index at canvas pixel `y` (None between/after rows or on the header). '''
        m = self._metrics()
        pos = listview_row_at(y, self._scroll, m['top'], m['row_h'], len(self._rows), m['top'] + m['view_h'])
        return None if pos is None else self._order[pos]

    def see(self, index):
        ''' Scroll so row `index` is in view (nothing moves when it already is). '''
        if not 0 <= int(index) < len(self._rows):
            return
        m = self._metrics()
        y = self._pos[int(index)] * m['row_h']
        if y < self._scroll:
            self._scroll = y
        elif y + m['row_h'] > self._scroll + m['view_h']:
            self._scroll = y + m['row_h'] - m['view_h']
        self._scroll = listview_clamp_scroll(self._scroll, m['content_h'], m['view_h'])
        self._draw()

    def yview(self, *args):
        ''' The scrollbar/tk protocol: yview('moveto', f) / yview('scroll', n, 'units'|'pages') '''
        m = self._metrics()
        if args and args[0] == 'moveto':
            self._scroll = int(float(args[1]) * m['content_h'])
        elif args and args[0] == 'scroll':
            n = int(args[1])
            self._scroll += n * (m['view_h'] if len(args) > 2 and args[2] == 'pages' else m['row_h'])
        self._scroll = listview_clamp_scroll(self._scroll, m['content_h'], m['view_h'])
        self._draw()

    def _scroll_by(self, rows):
        self.yview('scroll', rows, 'units')

    # ---- drawing

    def _draw(self, event=None):
        c = self.canvas
        c.delete('all')
        m = self._metrics()
        if m['w'] <= 1 or m['h'] <= 1:
            return
        s, fs, pad, row_h, top = m['s'], m['fs'], m['pad'], m['row_h'], m['top']
        w, h = _even(m['w']), _even(m['h'])
        c.configure(bg=Theme.SURFACE)
        self._scroll = listview_clamp_scroll(self._scroll, m['content_h'], m['view_h'])
        radius = self.corner_radius * s
        draw_rounded_rect(c, 1, 1, w - 1, h - 1, radius, fill=Theme.SURFACE, outline=Theme.BORDER, width=1)

        font = (Font.FAMILY, int(self.font_size * fs))
        bold = (Font.FAMILY, int(self.font_size * fs), 'bold')
        measure = m['font'].measure
        inner_w = w - 2 * pad - 2
        gap = int(6 * s)
        # column widths are characters of the list font, so they scale with it on any DPI
        char_w = m['char_w']
        cols = self._view = self._view_columns()
        # once the user has sized columns by hand their widths stand, so the stretch floor
        # drops to the bare minimum: fixed columns then shrink only when the widget is too
        # narrow to hold them at all
        self._layout = listview_column_layout([int(col['width'] * char_w) for col in cols], inner_w, min_w=3 * char_w, gap=gap,
                                              stretch_floor=1e-6 if self._user_sized else self.stretch_floor)
        x0 = self._x0 = pad + 1
        self._char_w = char_w

        # header (fixed)
        if self.show_header:
            hy = pad
            c.create_rectangle(x0, hy, x0 + inner_w, hy + m['head_h'], fill=Theme.SURFACE, outline='')
            p = self._press
            dragging = p['key'] if p and p['kind'] == 'title' and p['moved'] else None
            for n, (col, (cx, cw)) in enumerate(zip(cols, self._layout)):
                title = col['title']
                if col['key'] == self._sort_key:
                    title += ' ▼' if self._sort_reverse else ' ▲'
                colour = Theme.PRIMARY if col['key'] == dragging else Theme.TEXT_MUTED
                self._cell_text(c, title, x0 + cx, hy + m['head_h'] / 2, cw, col['align'], bold, colour, measure)
                if n + 1 < len(cols):               # a tick where the border can be grabbed
                    bx = x0 + (cx + cw + self._layout[n + 1][0]) / 2
                    c.create_line(bx, hy + m['head_h'] * 0.25, bx, hy + m['head_h'] * 0.75, fill=Theme.BORDER)
            c.create_line(x0, hy + m['head_h'] - 1, x0 + inner_w, hy + m['head_h'] - 1, fill=Theme.BORDER)
            if dragging is not None and self._drop is not None:
                if self._drop < len(self._layout):
                    mx = x0 + self._layout[self._drop][0] - gap / 2
                else:
                    mx = x0 + self._layout[-1][0] + self._layout[-1][1] + gap / 2
                c.create_line(mx, hy, mx, hy + m['head_h'], fill=Theme.PRIMARY, width=max(2, int(2 * s)))

        # rows in view only
        first, last = listview_visible_range(self._scroll, m['view_h'], row_h, len(self._rows))
        for pos in range(first, last):
            i = self._order[pos]
            row = self._rows[i]
            y = top + pos * row_h - self._scroll
            if i in self._selected:
                draw_rounded_rect(c, x0, y + 1, x0 + inner_w, y + row_h - 1, 6 * s, fill=Theme.PRIMARY, outline='')
                fg = 'white'
            elif self.hover and pos == self._hover:
                draw_rounded_rect(c, x0, y + 1, x0 + inner_w, y + row_h - 1, 6 * s, fill=Theme.HOVER, outline='')
                fg = Theme.TEXT
            else:
                fg = row.get('fg', Theme.TEXT)
            for col, (cx, cw) in zip(cols, self._layout):
                value = row.get(col['key'])
                if col['kind'] == 'progress':
                    self._cell_progress(c, value, row.get(col['key'] + '_text'), x0 + cx, y, cw, row_h, s, font, fg,
                                        i in self._selected, measure)
                else:
                    text = '' if value is None else str(value)
                    self._cell_text(c, text, x0 + cx, y + row_h / 2, cw, col['align'], font, fg, measure)

        # bottom pad hides rows scrolled half out at the bottom; the header hides the top
        c.create_rectangle(2, h - pad, w - 2, h - 1, fill=Theme.SURFACE, outline='')
        if self.show_header:
            c.create_rectangle(2, 2, w - 2, pad - 1 if pad > 2 else 2, fill=Theme.SURFACE, outline='')
        self.scrollbar.set(*listview_scroll_fraction(self._scroll, m['content_h'], m['view_h']))

    def _cell_text(self, c, text, x, cy, cw, align, font, fg, measure):
        text = listview_elide(text, max(0, cw - 8), measure)
        if align == 'e':
            c.create_text(x + cw - 4, cy, text=text, anchor='e', fill=fg, font=font)
        elif align in ('center', 'c'):
            c.create_text(x + cw / 2, cy, text=text, anchor='center', fill=fg, font=font)
        else:
            c.create_text(x + 4, cy, text=text, anchor='w', fill=fg, font=font)

    def _cell_progress(self, c, value, text, x, y, cw, row_h, s, font, fg, selected, measure):
        ''' A bar for value 0..1 with `text` over it (default the percentage), elided to the
        cell like any text; a row with no value but a text (`<key>_text`) shows the text
        alone, e.g. "metadata…". '''
        small = (font[0], max(6, font[1] - 2))
        label_fg = fg if not selected else 'white'
        if text is not None:
            text = listview_elide(text, max(0, cw - 8), measure)   # the list font: conservative for the smaller one
        if value is None:
            if text:
                c.create_text(x + cw / 2, y + row_h / 2, text=text, anchor='center', fill=label_fg, font=small)
            return
        frac = max(0.0, min(1.0, float(value)))
        bar_h = max(4, int(row_h * 0.45))
        y1 = y + (row_h - bar_h) / 2
        x1, x2 = x + 4, x + cw - 4
        track = Theme.BORDER if not selected else Theme.HOVER
        fill = Theme.SUCCESS if frac >= 1.0 else (Theme.TEXT if selected else Theme.PRIMARY)
        draw_rounded_rect(c, x1, y1, x2, y1 + bar_h, bar_h / 2, fill=track, outline='')
        if frac > 0:
            draw_rounded_rect(c, x1, y1, x1 + max(bar_h, (x2 - x1) * frac), y1 + bar_h, bar_h / 2, fill=fill, outline='')
        # on a selected row the fill is the text colour and the label straddles the fill's
        # edge, so it is drawn white over a one-pixel dark shadow to read on both sides
        label = text if text is not None else f'{frac * 100:.0f}%'
        if selected:
            c.create_text(x + cw / 2 + 1, y + row_h / 2 + 1, text=label, anchor='center', fill=Theme.SURFACE, font=small)
        c.create_text(x + cw / 2, y + row_h / 2, text=label, anchor='center', fill=label_fg, font=small)

    # ---- input

    def _in_header(self, event):
        m = self._metrics()
        return self.show_header and m['pad'] <= event.y < m['top']

    def _header_hit(self, event):
        ''' Key of the column whose title is under the pointer, else None. '''
        if not self._in_header(event):
            return None
        for col, (cx, cw) in zip(self._view, self._layout):
            if self._x0 + cx <= event.x < self._x0 + cx + cw:
                return col['key']
        return None

    def _border_hit(self, event):
        ''' Visible index of the column whose right border is under the pointer, else None. '''
        if not self._in_header(event):
            return None
        return listview_border_at(event.x - self._x0, self._layout, tolerance=max(4, self._char_w // 3))

    def _on_click(self, event):
        self.canvas.focus_set()
        self._press = None
        if self._in_header(event):
            # a press in the header starts a gesture; what it was is known on release:
            # a border drag resizes, a title drag reorders, a still click sorts
            b = self._border_hit(event)
            if b is not None:
                cw = self._char_w
                self._press = {'kind': 'border', 'index': b, 'x': event.x,
                               'keys': [c['key'] for c in self._view],
                               'widths': [c['width'] for c in self._view],
                               'actual': [w / cw for _, w in self._layout], 'moved': False}
            else:
                key = self._header_hit(event)
                if key is not None:
                    self._press = {'kind': 'title', 'key': key, 'x': event.x, 'moved': False}
            return
        i = self.nearest(event.y)
        if i is None:
            if not (event.state & 0x4):
                self.select(None)
            return
        if event.state & 0x1:          # shift
            self.select(i, extend=True)
        elif event.state & 0x4:        # control
            self.select(i, toggle=True)
        else:
            self.select(i)

    def _on_drag(self, event):
        p = self._press
        if p is None:
            return
        dx = event.x - p['x']
        if p['kind'] == 'border':
            if dx:
                p['moved'] = True
            new = listview_drag_widths(p['widths'], p['actual'], p['index'], dx / self._char_w, 4)
            for key, old, w in zip(p['keys'], p['widths'], new):
                if old > 0:             # whichever column is stretching keeps its set width
                    self._col_width[key] = round(w, 2)
            self._user_sized = True
            self._draw()
        elif abs(dx) > max(6, self._char_w // 2) or p['moved']:
            p['moved'] = True
            self._drop = listview_drop_index(event.x - self._x0, self._layout)
            self.canvas.config(cursor='fleur')
            self._draw()

    def _on_release(self, event):
        p, self._press = self._press, None
        drop, self._drop = self._drop, None
        if p is None:
            return
        if p['kind'] == 'border':
            if p['moved']:
                self._columns_changed()
        elif p['moved']:
            keys = [c['key'] for c in self._view]
            at = keys.index(p['key'])
            # dropping a column on either side of itself leaves it where it is
            if drop is not None and drop not in (at, at + 1):
                self.move_column(p['key'], drop if drop < at else drop - 1)
            else:
                self._draw()
        else:
            self.sort(p['key'])

    def _on_header_menu(self, event):
        if not (self.column_menu and self._in_header(event)):
            return None
        menu = tk.Menu(self, tearoff=0, bg=Theme.SURFACE, fg=Theme.TEXT, activebackground=Theme.PRIMARY,
                       activeforeground='white', bd=0)
        for label, checked, enabled, command in self.header_menu_entries():
            if label is None:
                menu.add_separator()
            elif command == self.reset_columns:
                menu.add_command(label=label, command=command)
            else:
                menu.add_command(label=('✓ ' if checked else '    ') + label, command=command,
                                 state='normal' if enabled else 'disabled')
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return 'break'              # a row menu the application bound must not open as well

    def _on_double(self, event):
        b = self._border_hit(event)
        if b is not None:
            self.fit_column(self._view[b]['key'])
            return
        if self.nearest(event.y) is not None:
            self._activate()

    def _activate(self):
        try:
            self.canvas.event_generate('<<ListboxActivate>>')
        except tk.TclError:
            pass

    def _on_motion(self, event):
        m = self._metrics()
        pos = listview_row_at(event.y, self._scroll, m['top'], m['row_h'], len(self._rows), m['top'] + m['view_h'])
        if pos != self._hover:
            self._hover = pos
            if self.hover:
                self._draw()
        if self._press is not None and self._press.get('moved'):
            return                      # a drag owns the cursor
        if self._border_hit(event) is not None:
            cursor = 'sb_h_double_arrow'
        else:
            cursor = 'hand2' if (self._header_hit(event) or pos is not None) else 'arrow'
        self.canvas.config(cursor=cursor)

    def _on_leave(self, event):
        if self._hover is not None:
            self._hover = None
            if self.hover:
                self._draw()

    def _on_wheel(self, event):
        step = -1 if event.delta > 0 else 1
        self._scroll_by(3 * step)

    def _on_key(self, event):
        n = len(self._rows)
        if n == 0:
            return 'break'
        sym = event.keysym
        if sym == 'Return':
            self._activate()
            return 'break'
        if sym == 'space':
            if self._anchor is not None:
                self.select(self._anchor, toggle=True)
            return 'break'
        m = self._metrics()
        page = max(1, m['view_h'] // m['row_h'])
        cur = self._pos.get(self._anchor, -1) if self._anchor is not None else -1
        step = {'Up': -1, 'Down': 1, 'Prior': -page, 'Next': page}.get(sym)
        if step is not None:
            pos = max(0, min(n - 1, cur + step if cur >= 0 else (0 if step > 0 else n - 1)))
        elif sym == 'Home':
            pos = 0
        else:                           # End
            pos = n - 1
        i = self._order[pos]
        if event.state & 0x1:
            self.select(i, extend=True)
        else:
            self.select(i)
        self.see(i)
        return 'break'

    # ---- tk plumbing

    def bind(self, sequence=None, command=None, add=True):
        ''' Bindings land on the canvas (where the events happen); always additive so the
            widget's own handlers survive, like the Listbox wrapper. '''
        if not (add is True or add == '+'):
            raise ValueError("ListView.bind requires add=True (or '+') to preserve internal callbacks")
        return self.canvas.bind(sequence, command, add=True)

    def focus_set(self):
        self.canvas.focus_set()


# --- FileDialog: a themed open / save / directory chooser on ListView ---
#
# tkinter.filedialog on X11 is a Motif-era widget in the system colours; next to a themed
# window it looks like a different program. This one is the same chrome as everything else
# and reuses ListView (so the columns sort, resize and can be arranged), with the pure parts
# (listing, matching, resolving a typed path, the places) kept apart for tests.

def filedialog_matches(name, patterns):
    ''' Whether a file name fits one of the glob `patterns` ('*' = anything); the match is
        case-insensitive since ".Torrent" and ".torrent" are the same file to a user. '''

    import fnmatch
    low = name.casefold()
    return any(p == '*' or fnmatch.fnmatchcase(low, p.casefold()) for p in (patterns or ('*',)))


def filedialog_fmt_size(n):
    ''' 0 B, 12 KiB, 1.5 MiB ... (None for a directory) '''

    if n is None:
        return ''
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return ('%d %s' if unit == 'B' or n >= 100 else '%.1f %s') % (n, unit)
        n /= 1024


def filedialog_entries(path, patterns=('*',), show_hidden=False, dirs_only=False, now=None):
    ''' ListView rows for the directory `path`: directories first, each group sorted by
        name without regard to case; files narrowed by `patterns`. A row carries name, path,
        is_dir, size (None for a directory), mtime and the sort values. Dot files (and, on
        Windows, hidden attributes are not consulted) stay out unless `show_hidden`. An
        unreadable directory lists as empty rather than raising. '''

    import time
    rows = []
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except OSError:
        return rows
    for e in entries:
        name = e.name
        if name.startswith('.') and not show_hidden:
            continue
        try:
            is_dir = e.is_dir()
        except OSError:
            is_dir = False
        if not is_dir and (dirs_only or not filedialog_matches(name, patterns)):
            continue
        try:
            st = e.stat()
            size, mtime = (None if is_dir else st.st_size), st.st_mtime
        except OSError:
            size, mtime = None, 0
        rows.append({'name': name, 'path': os.path.join(path, name), 'is_dir': is_dir, 'size': size, 'mtime': mtime,
                     'text': ('▸ ' if is_dir else '   ') + name,
                     'size_text': filedialog_fmt_size(size),
                     'modified': time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime)) if mtime else '',
                     '_sort': {'text': ('0' if is_dir else '1') + name.casefold(), 'size_text': size, 'modified': mtime}})
    rows.sort(key=lambda r: r['_sort']['text'])
    return rows


def filedialog_resolve(text, cwd):
    ''' The absolute path a user typed: ~ expanded, a relative name taken against `cwd`,
        separators normalised. Empty text is `cwd`. '''

    text = (text or '').strip()
    if not text:
        return cwd
    p = os.path.expanduser(os.path.expandvars(text))
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def filedialog_parent(path):
    ''' The directory above `path`; a root (or a bare relative name) is its own parent. '''

    stripped = path.rstrip('/\\')
    if len(stripped) <= len(os.path.splitdrive(path)[0]):
        return path                                # '/' or 'C:\\'
    return os.path.dirname(stripped) or path


def filedialog_places(home=None, volumes=None):
    ''' (label, path) pairs for the places list: the home directory, its usual folders
        that exist, the root (or drives) and mounted volumes. '''

    home = home or os.path.expanduser('~')
    out = [('Home', home)]
    for name in ('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos'):
        p = os.path.join(home, name)
        if os.path.isdir(p):
            out.append((name, p))
    if sys.platform.startswith('win'):
        for letter in 'CDEFGHIJKLMNOPQRSTUVWXYZ':
            d = letter + ':\\'
            if os.path.isdir(d):
                out.append((d, d))
    else:
        out.append(('/', '/'))
        if volumes is None:
            volumes = []
            user = os.path.basename(home)
            for base in ('/run/media/' + user, '/media/' + user, '/media', '/mnt', '/Volumes'):
                try:
                    volumes += [os.path.join(base, n) for n in sorted(os.listdir(base))]
                except OSError:
                    pass
        for v in volumes:
            if os.path.isdir(v) and (v, v) not in out:
                out.append((v.rstrip('/').rsplit('/', 1)[-1] or v, v))
    return out


class FileDialog(Toplevel):
    '''
    FileDialog(master, mode='open' | 'save' | 'directory', title=None, initialdir=None,
               initialfile='', filetypes=[(label, pattern), ...], multiple=False).show()
    returns the chosen path (a list when `multiple`), or None when cancelled. The class
    methods ask_open / ask_save / ask_directory wrap that in one call. The last directory
    accepted is remembered for the next dialog of the process.

    Double-click a folder to enter it, a file to choose it; type a path in the bar and press
    Return to go there (or to choose that file); BackSpace in the list goes up. In 'save'
    mode an existing file asks before it is replaced (`confirm` is the asker, replaceable).
    `list` is the ListView of the directory, so an application may arrange and remember its
    columns like any other table.
    '''

    COLUMNS = [('text', 'Name', 0, 'w', {'required': True}), ('size_text', 'Size', 10, 'e'), ('modified', 'Modified', 17, 'w')]
    last_dir = None

    def __init__(self, master, mode='open', title=None, initialdir=None, initialfile='', filetypes=None,
                 multiple=False, show_hidden=False, chars=96, lines=26):
        self.mode = mode
        if mode not in ('open', 'save', 'directory'):
            raise ValueError('mode must be open, save or directory')
        self.multiple = bool(multiple) and mode == 'open'
        self.filetypes = [(str(label), (pat,) if isinstance(pat, str) else tuple(pat)) for label, pat in (filetypes or [])]
        if not self.filetypes:
            self.filetypes = [('All files', ('*',))]
        self.type_index = 0
        self.show_hidden = show_hidden
        self.result = None
        self.confirm = MessageBox.askyesno
        f = tkfont.Font(family=Font.FAMILY, size=Font.FONT[1])
        cw, lh = max(1, f.measure('0')), max(1, f.metrics('linespace'))
        scale = getattr(master, 'ui_scale', 1.0) or 1.0
        super().__init__(master, title=title or {'open': 'Open', 'save': 'Save as', 'directory': 'Choose a folder'}[mode],
                         width=int(chars * cw / scale), height=int(lines * lh / scale))
        self.minsize(int(40 * cw), int(12 * lh))
        start = initialdir or self.last_dir or os.getcwd()
        if not os.path.isdir(start):
            start = os.path.expanduser('~')
        self.cwd = os.path.abspath(start)
        self._history = []
        self._build(cw, lh, initialfile)
        self.go(self.cwd)
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.bind('<Escape>', lambda e: self.cancel())

    # ---- layout
    def _build(self, cw, lh, initialfile):
        '''The dialog as a spec tree (the sizes computed here, since two are mixed units).'''
        nav = int(2.5 * cw) + 12
        ok = {'open': 'Open', 'save': 'Save', 'directory': 'Choose'}[self.mode]
        with ui.column() as tree:
            with ui.row(fill='x', pad=(12, (12, 6))):
                ui.button('◀', on='back')
                ui.button('▲', on='up', pad=((4, 8), 0))
                ui.entry('path', fill='x', expand=True)
                ui.checkbox('Hidden', 'hidden', on='_toggle_hidden', checked=self.show_hidden, pad=((8, 0), 0))
            with ui.row('foot', side='bottom', fill='x', pad=(12, 12)):
                ui.button('Cancel', side='right', pad=((4, 0), 0))
                ui.button(ok, on='accept', side='right', pad=(4, 0))
                if self.mode != 'directory':
                    ui.button(self.filetypes[0][0], 'next_type', name='types', side='right', pad=((8, 12), 0))
            with ui.row(side='bottom', fill='x', pad=(12, 0)):
                ui.label('Folder:' if self.mode == 'directory' else 'Name:', pad=((0, 8), 0))
                ui.entry('name', fill='x', expand=True)
            with ui.row(fill='both', expand=True, pad=(12, 0)):
                ui.listview('places', header=False, multiple=False, on_select='_place_chosen', fill='y', pad=((0, 8), 0))
                ui.listview('list', self.COLUMNS, multiple=self.multiple, on_select='_picked', on_activate='open_selected',
                            fill='both', expand=True)
        style = Style({
            'back': {'width': nav, 'fg_color': Theme.BG, 'hover_color': Theme.BORDER},
            'up': {'width': nav, 'fg_color': Theme.BG, 'hover_color': Theme.BORDER},
            'cancel': {'fg_color': Theme.BG, 'hover_color': Theme.BORDER},
            'types': {'width': int(16 * cw), 'fg_color': Theme.SURFACE, 'hover_color': Theme.BORDER},
            'path': {'width': int(50 * cw), 'height': int(lh * 1.6)},
            'name': {'width': int(40 * cw), 'height': int(lh * 1.6)},
            'places': {'width': int(14 * cw)},
        })
        r = build(tree, self, controller=self, style=style)
        self.path, self.hidden, self.places, self.list, self.name = r.path, r.hidden, r.places, r.list, r.name
        # directory mode keeps the type button made but unmapped, as before
        self.types = r.get('types') or Button(r.foot, text=self.filetypes[0][0], command=self.next_type,
                                              width=int(16 * cw), fg_color=Theme.SURFACE, hover_color=Theme.BORDER)
        self.path.entry.bind('<Return>', lambda e: self.go_typed())
        self.places.set_rows([{'text': label, 'path': p} for label, p in filedialog_places()])
        self.list.bind('<KeyPress-BackSpace>', lambda e: self.up())
        self.name.entry.bind('<Return>', lambda e: self.accept())
        if initialfile:
            self.name.entry.insert(0, initialfile)

    # ---- navigation
    def go(self, path, remember=True):
        ''' Show directory `path` (a file path shows its directory and names the file). '''
        path = os.path.abspath(path)
        file = ''
        if os.path.isfile(path):
            path, file = os.path.dirname(path), os.path.basename(path)
        if not os.path.isdir(path):
            return False
        if remember and path != self.cwd:
            self._history.append(self.cwd)
        if path != self.cwd and self.mode == 'open':
            self.name.entry.delete(0, 'end')          # a file named in the last folder is not in this one
        self.cwd = path
        self.path.entry.delete(0, 'end')
        self.path.entry.insert(0, path)
        if file:
            self.name.entry.delete(0, 'end')
            self.name.entry.insert(0, file)
        self.refresh()
        return True

    def refresh(self):
        self.list.set_rows(filedialog_entries(self.cwd, self.filetypes[self.type_index][1], self.show_hidden,
                                              dirs_only=self.mode == 'directory'))
        if self.mode == 'directory':
            self.name.entry.delete(0, 'end')
            self.name.entry.insert(0, self.cwd)

    def up(self):
        self.go(filedialog_parent(self.cwd))

    def back(self):
        if self._history:
            self.go(self._history.pop(), remember=False)

    def go_typed(self):
        ''' The path bar: a directory is entered, a file is chosen, anything else is left
            in the bar for correction. '''
        p = filedialog_resolve(self.path.get(), self.cwd)
        if os.path.isdir(p):
            self.go(p)
        elif os.path.isfile(p) and self.mode != 'directory':
            self.go(p)
            self.accept()

    def next_type(self):
        self.type_index = (self.type_index + 1) % len(self.filetypes)
        self.types.text = self.filetypes[self.type_index][0]
        self.types._draw()
        self.refresh()

    def _toggle_hidden(self, *_):
        self.show_hidden = self.hidden.get()
        self.refresh()

    def _place_chosen(self, row):
        if row:
            self.go(row['path'])
            self.places.select(None)

    def _picked(self, sel):
        rows = sel if isinstance(sel, list) else ([sel] if sel else [])
        if self.mode == 'directory':
            target = rows[0]['path'] if rows else self.cwd
        elif len(rows) == 1 and not rows[0]['is_dir']:
            target = rows[0]['name']
        elif len(rows) > 1:
            target = ''                 # several: the selection itself is the choice
        else:
            return
        self.name.entry.delete(0, 'end')
        self.name.entry.insert(0, target)

    def open_selected(self):
        ''' Double-click or Return on the list: enter a folder, choose a file. '''
        row = self.list.get() if not self.multiple else (self.list.get() or [None])[0]
        if row is None:
            return
        if row['is_dir']:
            self.go(row['path'])
        else:
            self.accept()

    # ---- outcome
    def chosen(self):
        ''' What accept() would return now, or None when nothing valid is named. '''
        if self.mode == 'directory':
            p = filedialog_resolve(self.name.get(), self.cwd)
            return p if os.path.isdir(p) else None
        if self.multiple:
            rows = [r for r in self.list.get() if not r['is_dir']]
            if rows:
                return [r['path'] for r in rows]
        text = self.name.get().strip()
        if not text:
            return None
        p = filedialog_resolve(text, self.cwd)
        if self.mode == 'open':
            if not os.path.isfile(p):
                return None
            return [p] if self.multiple else p
        return None if os.path.isdir(p) else p

    def accept(self):
        ''' Choose: a typed directory is entered instead, an existing save target is
            confirmed, anything else is ignored. '''
        text = self.name.get().strip()
        if self.mode != 'directory' and text:
            p = filedialog_resolve(text, self.cwd)
            if os.path.isdir(p):
                self.name.entry.delete(0, 'end')
                self.go(p)
                return
        choice = self.chosen()
        if choice is None:
            return
        if self.mode == 'save' and os.path.exists(choice):
            if not self.confirm('Replace file?', '%s already exists. Replace it?' % os.path.basename(choice)):
                return
        self.result = choice
        FileDialog.last_dir = self.cwd
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        ''' Reveal, run modally, and return the choice (None when cancelled). '''
        super().show()
        self.list.focus_set()
        self.wait_window()
        return self.result

    @classmethod
    def ask_open(cls, master, **kw):
        return cls(master, mode='open', **kw).show()

    @classmethod
    def ask_save(cls, master, **kw):
        return cls(master, mode='save', **kw).show()

    @classmethod
    def ask_directory(cls, master, **kw):
        return cls(master, mode='directory', **kw).show()


# ====================================================================== spec
# Describe a window as data and build it in one call. Structure is a tree of the node
# dataclasses under `spec` (plain data, importable without a display); style is a dict or
# a TOML sheet keyed by node kind or node name, with sizes in font units ("22ch", "1.7lh")
# or pixels; handlers are named and resolved on a controller object at build time.
# `validate` checks a tree headless; `build` turns it into real widgets and hands back the
# named ones. An app plugs its own widgets in with `register(kind)`; nothing app-specific
# lives here. The nodes sit in the `spec` namespace because several share a name with the
# widget they describe (`spec.Button` describes a `Button`); `ui` writes the same tree by
# indentation (`with ui.row(): ui.button('Add')`).
from dataclasses import dataclass as _dataclass, field as _field


class SpecError(ValueError):
    pass


def font_metrics(widget, size=None):
    '''(character width, line height) in pixels of the UI font at this widget's scale: the
    units a spec's "22ch" and "1.7lh" resolve through.'''
    tl = widget.winfo_toplevel()
    fs = getattr(tl, 'font_scale', 1.0)
    f = tkfont.Font(family=Font.FAMILY, size=int((size or Font.FONT[1]) * fs))
    return max(1, f.measure('0')), max(1, f.metrics('linespace'))


def to_px(value, cw, lh):
    '''A size: a number is pixels; "22ch" is 22 character widths, "1.7lh" 1.7 line heights,
    "40px" pixels. None stays None.'''
    if value is None or isinstance(value, (int, float)):
        return None if value is None else int(round(value))
    v = str(value).strip()
    for unit, scale in (('ch', cw), ('lh', lh), ('px', 1)):
        if v.endswith(unit):
            try:
                return int(round(float(v[:-len(unit)]) * scale))
            except ValueError:
                break
    raise SpecError('bad size %r (want a number, "Nch", "Nlh" or "Npx")' % (value,))


SIZE_KEYS = ('width', 'height', 'min', 'padx', 'pady')


@_dataclass(kw_only=True)   # the common fields are keyword-only, so a leaf's own first field is positional
class SpecNode:
    '''Common to every node. ``side``/``fill``/``expand``/``pad`` are how the parent packs
    it; ``style`` holds inline style keys (same names as the sheet, highest precedence).'''
    name: str = None
    side: str = None
    fill: str = None
    expand: bool = False
    pad: tuple = None
    style: dict = _field(default_factory=dict)
    kind = 'node'
    children = ()

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    # `with node:` makes it the open container the `ui` builder appends to
    def __enter__(self):
        _OPEN.append(self)
        return self

    def __exit__(self, *exc):
        _OPEN.pop()
        return False


_OPEN = []      # the containers whose `with` blocks are open, innermost last


def _ident(text):
    '''"Start all" -> "start_all"; None when the text is not a plain name (e.g. "Browse…").'''
    t = str(text).strip()
    if t and t[0].isalpha() and all(c.isalnum() or c in ' _' for c in t):
        return t.lower().replace(' ', '_')
    return None


def _container(kind_name, default_side, default_fill, default_expand):
    class Container(SpecNode):
        kind = kind_name

        def __init__(self, *children, name=None, side=None, fill=default_fill, expand=default_expand,
                     pad=None, style=None):
            SpecNode.__init__(self, name=name, side=side, fill=fill, expand=expand, pad=pad, style=dict(style or {}))
            self.children = list(children)
            self.child_side = default_side

        def __repr__(self):
            return '%s(%s)' % (type(self).__name__, ', '.join(repr(c) for c in self.children))
    Container.__name__ = Container.__qualname__ = 'spec.' + kind_name.capitalize()
    return Container


class spec:
    '''The node types. ``spec.Column(spec.Row(spec.Button('Add', on='add'), ...), ...)``.'''
    Node = SpecNode
    Column = _container('column', 'top', 'both', True)
    Row = _container('row', 'left', 'x', False)

    class Split(SpecNode):
        '''A paned window; a child's ``style['min']`` / ``['width']`` / ``['height']`` are
        its sash limit and initial size.'''
        kind = 'split'

        def __init__(self, *children, vertical=False, name=None, fill='both', expand=True, pad=None, style=None):
            SpecNode.__init__(self, name=name, fill=fill, expand=expand, pad=pad, style=dict(style or {}))
            self.children = list(children)
            self.vertical = vertical

    class Tab(SpecNode):
        '''One page of a ``Tabs``: ``key``, ``title`` and the one node that fills it.'''
        kind = 'tab'

        def __init__(self, key, title, child=None, name=None):
            SpecNode.__init__(self, name=name)
            self.key, self.title = key, title
            self.children = [] if child is None else [child]

    class Tabs(SpecNode):
        '''A tab strip. The widget comes from the registry under ``widget`` (an app's own
        class; it must offer ``add(key, title) -> frame``), so this file stays app-agnostic.'''
        kind = 'tabs'

        def __init__(self, *tabs, widget='tabs', on_change=None, name=None, fill='both', expand=True, pad=None,
                     style=None):
            SpecNode.__init__(self, name=name, fill=fill, expand=expand, pad=pad, style=dict(style or {}))
            self.children = list(tabs)
            self.widget, self.on_change = widget, on_change

    @_dataclass
    class Button(SpecNode):
        '''``on`` defaults to the text as a handler name ("Add" -> ``add``, "Start all" ->
        ``start_all``; nothing for "Browse…"), ``name`` to the handler when that is a string:
        ``Button('Add')`` calls ``add`` and is ``refs.add``.'''
        text: str = ''
        on: object = None
        kind = 'button'

        def __post_init__(self):
            self.inferred = False
            if self.on is None:
                self.on = _ident(self.text)
                self.inferred = self.on is not None
            if self.name is None and isinstance(self.on, str):
                self.name = self.on

    @_dataclass
    class Label(SpecNode):
        text: str = ''
        muted: bool = False
        anchor: str = 'w'
        chars: int = None          # a fixed width in characters (tk's unit for a label)
        kind = 'label'

    @_dataclass
    class Entry(SpecNode):
        placeholder: str = ''
        show: str = ''
        on_key: object = None
        kind = 'entry'

    @_dataclass
    class Checkbox(SpecNode):
        text: str = ''
        on: object = None
        checked: bool = False
        kind = 'checkbox'

    @_dataclass
    class Toggle(SpecNode):
        text: str = ''
        on: object = None
        on_state: bool = False
        kind = 'toggle'

    @_dataclass
    class Textbox(SpecNode):
        kind = 'textbox'

    @_dataclass
    class Dropdown(SpecNode):
        '''``items`` may be a list or the name of a controller attribute; ``on(value)``.'''
        items: object = None
        on: object = None
        placeholder: str = ''
        kind = 'dropdown'

    @_dataclass
    class Progress(SpecNode):
        kind = 'progress'

    @_dataclass
    class Separator(SpecNode):
        '''A one-pixel line in the border colour; ``fill`` defaults to x.'''
        kind = 'separator'

        def __post_init__(self):
            if self.fill is None:
                self.fill = 'x'

    @_dataclass
    class Spacer(SpecNode):
        '''Empty space; its ``style['height']`` (or ``width``) is the size.'''
        kind = 'spacer'

    @_dataclass
    class ListView(SpecNode):
        columns: object = None
        header: bool = True
        multiple: bool = True
        on_select: object = None
        on_activate: object = None
        on_columns: object = None
        stretch_floor: float = 0.3
        kind = 'listview'

    @_dataclass
    class Widget(SpecNode):
        '''Any registered kind, with its own keyword arguments.'''
        widget: str = ''
        kwargs: dict = _field(default_factory=dict)
        kind = 'widget'


class ui:
    '''The same nodes by indentation: a container opened with ``with`` is where the next
    calls put their node, so a window reads like its outline::

        with ui.column() as UI:
            with ui.row('bar', fill='x'):
                ui.entry('filter', placeholder='find', side='right', on_key='refresh')
                for text in ('Add', 'Pause', 'Remove'):
                    ui.button(text)
            with ui.split('main'):
                ui.listview('side', header=False, on_select='chosen')
                with ui.tabs('tabs'):
                    with ui.tab('files', 'Files'):
                        ui.listview('files', columns='FILE_COLUMNS')

    Each call returns its node, so the two forms mix: ``ui.add(node)`` puts a node a helper
    made where the next call would go, and a helper that opens a container with ``with``
    composes (a form row is a function with ``with ui.row(): ui.label(text); yield``).
    Argument order is what one writes first anyway: the text for a button, label, checkbox
    or toggle; the name for an entry, textbox, list view, widget or container.'''

    @staticmethod
    def add(node):
        if _OPEN:
            _OPEN[-1].children.append(node)
        return node

    @staticmethod
    def column(name=None, **kw):
        return ui.add(spec.Column(name=name, **kw))

    @staticmethod
    def row(name=None, **kw):
        return ui.add(spec.Row(name=name, **kw))

    @staticmethod
    def split(name=None, vertical=False, **kw):
        return ui.add(spec.Split(name=name, vertical=vertical, **kw))

    @staticmethod
    def tabs(name=None, widget='tabs', on_change=None, **kw):
        return ui.add(spec.Tabs(name=name, widget=widget, on_change=on_change, **kw))

    @staticmethod
    def tab(key, title, name=None):
        return ui.add(spec.Tab(key, title, name=name))

    @staticmethod
    def button(text, on=None, **kw):
        return ui.add(spec.Button(text, on=on, **kw))

    @staticmethod
    def label(text='', **kw):
        return ui.add(spec.Label(text, **kw))

    @staticmethod
    def checkbox(text, name=None, **kw):
        return ui.add(spec.Checkbox(text, name=name, **kw))

    @staticmethod
    def toggle(text, name=None, **kw):
        return ui.add(spec.Toggle(text, name=name, **kw))

    @staticmethod
    def entry(name=None, placeholder='', **kw):
        return ui.add(spec.Entry(placeholder, name=name, **kw))

    @staticmethod
    def textbox(name=None, **kw):
        return ui.add(spec.Textbox(name=name, **kw))

    @staticmethod
    def dropdown(name=None, items=None, on=None, **kw):
        return ui.add(spec.Dropdown(items, on=on, name=name, **kw))

    @staticmethod
    def progress(name=None, **kw):
        return ui.add(spec.Progress(name=name, **kw))

    @staticmethod
    def separator(**kw):
        return ui.add(spec.Separator(**kw))

    @staticmethod
    def spacer(height=None, width=None, **kw):
        style = dict(kw.pop('style', {}) or {})
        if height is not None:
            style['height'] = height
        if width is not None:
            style['width'] = width
        return ui.add(spec.Spacer(style=style, **kw))

    @staticmethod
    def listview(name=None, columns=None, **kw):
        return ui.add(spec.ListView(columns, name=name, **kw))

    @staticmethod
    def widget(name, widget, kwargs=None, **kw):
        return ui.add(spec.Widget(widget, dict(kwargs or {}), name=name, **kw))


# ---- registry: kind -> factory(node, master, px, bind) -> widget
_SPEC = {}


def register(kind):
    '''Decorator: ``@register('piecemap')`` on ``factory(node, master, px, bind)``. ``px`` is
    the node's resolved style with sizes in pixels; ``bind(h)`` resolves a handler.'''
    def deco(factory):
        _SPEC[kind] = factory
        return factory
    return deco


def _size_kw(px, *keys):
    return {k: px[k] for k in keys if px.get(k) is not None}


@register('button')
def _mk_button(node, master, px, bind):
    kw = _size_kw(px, 'width', 'height')
    for k in ('fg_color', 'hover_color', 'font_size'):
        if px.get(k):
            kw[k] = px[k]
    return Button(master, text=node.text, command=bind(node.on) or (lambda: None), **kw)


@register('label')
def _mk_label(node, master, px, bind):
    kw = {'anchor': node.anchor}
    if node.chars:
        kw['width'] = node.chars
    if node.muted:
        kw['fg'] = Theme.TEXT_MUTED
    for k in ('fg', 'font'):
        if px.get(k):
            kw[k] = px[k]
    return Label(master, text=node.text, **kw)


@register('entry')
def _mk_entry(node, master, px, bind):
    w = Entry(master, placeholder=node.placeholder, show=node.show, **_size_kw(px, 'width', 'height'))
    if node.on_key:
        h = bind(node.on_key)
        w.entry.bind('<KeyRelease>', lambda e: h())
    return w


@register('checkbox')
def _mk_checkbox(node, master, px, bind):
    return Checkbox(master, text=node.text, command=bind(node.on), checked=node.checked)


@register('toggle')
def _mk_toggle(node, master, px, bind):
    return Toggle(master, text=node.text, command=bind(node.on), is_on=node.on_state)


@register('textbox')
def _mk_textbox(node, master, px, bind):
    kw = _size_kw(px, 'width', 'height')
    if px.get('font'):
        kw['font'] = tuple(px['font']) if isinstance(px['font'], (list, tuple)) else px['font']
    return Textbox(master, **kw)


@register('dropdown')
def _mk_dropdown(node, master, px, bind):
    items = node.items
    if isinstance(items, str):
        items = bind(items)
    return Dropdown(master, items=items or (), command=bind(node.on), placeholder=node.placeholder,
                    **_size_kw(px, 'width', 'height'))


@register('progress')
def _mk_progress(node, master, px, bind):
    return ProgressBar(master, **_size_kw(px, 'width', 'height'))


@register('separator')
def _mk_separator(node, master, px, bind):
    return tk.Frame(master, bg=Theme.BORDER, height=px.get('height') or 1, width=px.get('width') or 1)


@register('spacer')
def _mk_spacer(node, master, px, bind):
    return tk.Frame(master, bg=Theme.BG, height=px.get('height') or 1, width=px.get('width') or 1)


@register('listview')
def _mk_listview(node, master, px, bind):
    cols = node.columns
    if isinstance(cols, str):
        cols = bind(cols)
    on_select, on_columns = bind(node.on_select), bind(node.on_columns)
    w = ListView(master, columns=cols, header=node.header, multiple=node.multiple,
                 command=(lambda sel: on_select(sel)) if on_select else None,
                 columns_command=on_columns, stretch_floor=node.stretch_floor,
                 **_size_kw(px, 'width', 'height'))
    if node.on_activate:
        h = bind(node.on_activate)
        w.bind('<<ListboxActivate>>', lambda e: h())
    return w


@register('widget')
def _mk_widget(node, master, px, bind):
    factory = _SPEC.get(node.widget)
    if factory is None:
        raise SpecError('unregistered widget kind %r' % node.widget)
    return factory(node, master, px, bind)


# ---- style
class Style(dict):
    '''Sections keyed by node kind ("button") or node name ("filter"); name beats kind,
    a node's inline ``style`` beats both. ``load`` reads a TOML sheet (stdlib ``tomllib``).'''

    @classmethod
    def load(cls, path):
        import tomllib
        with open(path, 'rb') as f:
            return cls(tomllib.load(f))

    def resolve(self, node):
        out = {}
        out.update(self.get(node.kind, {}))
        if node.kind == 'widget':
            out.update(self.get(node.widget, {}))
        if node.name:
            out.update(self.get(node.name, {}))
        out.update(node.style)
        return out


class Refs(dict):
    '''The named widgets a build made, by attribute or by key.'''

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k) from None


def validate(tree, controller=None, style=None):
    '''Problems with a tree as a list of strings (empty = fine): duplicate names, unknown
    kinds, handlers the controller lacks, bad sizes, a Split with one pane, a Tab outside
    Tabs. Headless.'''
    problems, names = [], set()
    style = style if isinstance(style, Style) else Style(style or {})
    for n in tree.walk():
        where = '%s %r' % (n.kind, n.name or '')
        if n.name:
            if n.name in names:
                problems.append('duplicate name %r' % n.name)
            names.add(n.name)
        if n.kind in ('widget', 'tabs'):
            if n.widget not in _SPEC:
                problems.append('%s: unregistered widget kind %r' % (where, n.widget))
        elif n.kind not in _SPEC and n.kind not in ('column', 'row', 'split', 'tab'):
            problems.append('%s: unknown kind' % where)
        if n.kind == 'split' and len(n.children) < 2:
            problems.append('%s: a split wants two or more panes' % where)
        if n.kind == 'tabs' and any(c.kind != 'tab' for c in n.children):
            problems.append('%s: children of tabs must be Tab' % where)
        if n.kind == 'tab' and len(n.children) != 1:
            problems.append('tab %r wants exactly one child' % n.key)
        for h in ('on', 'on_key', 'on_select', 'on_activate', 'on_columns', 'on_change'):
            v = getattr(n, h, None)
            if isinstance(v, str) and controller is not None and not callable(getattr(controller, v, None)):
                hint = ' (inferred from the text; pass on=)' if h == 'on' and getattr(n, 'inferred', False) else ''
                problems.append('%s: handler %r is not on the controller%s' % (where, v, hint))
        try:
            for k, v in style.resolve(n).items():
                if k in SIZE_KEYS:
                    to_px(v, 10, 20)
        except SpecError as e:
            problems.append('%s: %s' % (where, e))
    for n in tree.walk():
        for c in n.children:
            if c.kind == 'tab' and n.kind != 'tabs':
                problems.append('tab %r outside tabs' % c.key)
    return problems


def build(tree, master, controller=None, style=None):
    '''Make the widgets for ``tree`` under ``master`` and pack them; returns ``Refs``.
    Handlers given as strings are looked up on ``controller``; callables pass through.'''
    style = style if isinstance(style, Style) else Style(style or {})
    problems = validate(tree, controller, style)
    if problems:
        raise SpecError('; '.join(problems))
    cw, lh = font_metrics(master)
    refs = Refs()

    def bind(h):
        if h is None or not isinstance(h, str):
            return h
        v = getattr(controller, h, None)
        if v is None:
            raise SpecError('handler %r is not on the controller' % h)
        return v

    def px_of(node):
        out = {}
        for k, v in style.resolve(node).items():
            out[k] = to_px(v, cw, lh) if k in SIZE_KEYS else v
        return out

    def place(node, widget, parent, default_side):
        if parent is None:
            return
        px = px_of(node)
        pad = node.pad or (px.get('padx', 0), px.get('pady', 0))
        widget.pack(side=node.side or default_side, fill=node.fill, expand=node.expand,
                    padx=pad[0], pady=pad[1])

    def make(node, master, parent=None, default_side='top'):
        px = px_of(node)
        if node.kind in ('column', 'row'):
            w = tk.Frame(master, bg=Theme.BG)
            place(node, w, parent, default_side)
            for c in node.children:
                make(c, w, node, node.child_side)
        elif node.kind == 'split':
            w = tk.PanedWindow(master, orient='vertical' if node.vertical else 'horizontal', bg=Theme.BG,
                               sashwidth=5, bd=0, relief='flat')
            place(node, w, parent, default_side)
            for c in node.children:
                pane = make(c, w, None)
                cpx = px_of(c)
                kw = {}
                if cpx.get('min') is not None:
                    kw['minsize'] = cpx['min']
                if cpx.get('width') is not None and not node.vertical:
                    kw['width'] = cpx['width']
                if cpx.get('height') is not None and node.vertical:
                    kw['height'] = cpx['height']
                w.add(pane, **kw)
        elif node.kind == 'tabs':
            w = _SPEC[node.widget](node, master, px, bind)
            place(node, w, parent, default_side)
            for t in node.children:
                page = w.add(t.key, t.title)
                inner = t.children[0]
                child = make(inner, page, None)
                ipx = px_of(inner)
                pad = inner.pad or (ipx.get('padx', 0), ipx.get('pady', 0))
                child.pack(fill='both', expand=True, padx=pad[0], pady=pad[1])
        else:
            w = _SPEC[node.kind](node, master, px, bind)
            place(node, w, parent, default_side)
        if node.name:
            refs[node.name] = w
        return w

    root = refs['root'] = make(tree, master)
    px = px_of(tree)
    pad = tree.pad or (px.get('padx', 0), px.get('pady', 0))
    root.pack(side=tree.side or 'top', fill=tree.fill or 'both', expand=tree.expand, padx=pad[0], pady=pad[1])
    return refs
