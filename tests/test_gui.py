'''
Tests for the tkinter layer: ui_bridge (headless), dashboard wiring (headless),
tkinter_mods widgets and ModalRenderer dialogs (need a display - real, or Xvfb).

Run on Linux CI with:  xvfb-run -a python -m unittest tests.test_gui
Machines with no display skip the Tk-dependent classes automatically.
'''

import ast, atexit, locale, logging, os, queue, sys, threading, time, types, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import ui_bridge
from src.ui_bridge import (
    ThreadSafeUIProxy, CLIUserInterface, ui_task_queue, set_gui_active,
    get_ui_provider,
)


_SRC = __file__.replace('\\', '/').rsplit('/', 2)[0] + '/src'

try:
    import tkinter as tk
    from src.tkinter_mods import (
        Window, Toplevel, Button, Entry, Toggle, Textbox, Listbox, Theme, Font,
    )
    from src.dashboard import DesktopDashboard
    _TK_IMPORTABLE = True
except ImportError:
    _TK_IMPORTABLE = False
    DesktopDashboard = None

# ONE shared hidden root for the entire module. Repeatedly creating and
# destroying Tk() roots in a single process is a classic Aqua Tk segfault
# on macOS runners
_SHARED_ROOT = None
if _TK_IMPORTABLE and not os.environ.get('PYBISS_SKIP_GUI_TESTS'):
    try:
        _SHARED_ROOT = Window(title='pybiss-tests')
        _SHARED_ROOT.withdraw()
        _SHARED_ROOT._dpi_scale = 1.0
        Font.apply(Font.resolve_mono())   # real monospace metrics, not the 6px bitmap fallback

        def _destroy_shared_root():
            try:
                _SHARED_ROOT.destroy()
            except tk.TclError:
                pass
        atexit.register(_destroy_shared_root)
    except tk.TclError:
        _SHARED_ROOT = None

HAS_DISPLAY = _SHARED_ROOT is not None
_needs_display = unittest.skipUnless(HAS_DISPLAY, 'no display server (run under xvfb-run on CI)')


def find_widgets(root, cls) -> list:
    ''' Recursively collect all widgets of a given class under `root` '''

    found = [w for w in root.winfo_children() if isinstance(w, cls)]
    for child in root.winfo_children():
        found.extend(find_widgets(child, cls))
    return found


def find_by_attr(root, attr) -> list:
    ''' Collect widgets that carry `attr` '''

    found = [w for w in root.winfo_children() if hasattr(w, attr)]
    for child in root.winfo_children():
        found.extend(find_by_attr(child, attr))
    return found


class TestUiBridge(unittest.TestCase):
    ''' Layer 1: the queue bridge - no display, runs on every CI platform '''

    def tearDown(self):
        # Never leak tasks into the next test
        while not ui_task_queue.empty():
            ui_task_queue.get_nowait()


    def test_prompt_pin_roundtrip(self):
        ''' A server thread's prompt blocks until the consumer answers, then unblocks '''

        result = {}

        def server_thread():
            result['pin'] = ThreadSafeUIProxy().prompt_pin(label='PIN')

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # Play the role of the dashboard's _monitor_ui_queue loop
        task_type, kwargs, res_q = ui_task_queue.get(timeout=2)
        assert task_type == 'prompt_pin'
        assert kwargs['label'] == 'PIN'
        res_q.put('9999')

        t.join(timeout=2)
        assert not t.is_alive(), 'proxy never unblocked after the answer'
        assert result['pin'] == '9999'


    def test_confirm_sign_carries_both_texts(self):
        threading.Thread(
            target=lambda: ThreadSafeUIProxy().confirm_sign('msg', additional_text='extra'),
            daemon=True,
        ).start()
        task_type, kwargs, res_q = ui_task_queue.get(timeout=2)
        assert task_type == 'confirm_sign'
        assert kwargs == {'text': 'msg', 'additional_text': 'extra'}
        res_q.put(True)  # unblock the worker so it doesn't linger


    def test_prompt_times_out_to_cancel_sentinels(self):
        ''' The handlers run inline in the server's asyncio loop, an  unanswerable prompt 
            must not block forever
        '''

        proxy = ThreadSafeUIProxy(timeout=0.05)
        assert proxy.prompt_pin() is None
        assert proxy.choose_certificate([{'subject': 'A'}]) == -1
        assert not proxy.confirm_sign('sign this?')

    def test_late_answer_after_timeout_is_harmless(self):
        ''' The stale task stays queued - an answer put after the requester gave
            up lands in a queue nobody reads 
        '''

        proxy = ThreadSafeUIProxy(timeout=0.05)
        assert proxy.prompt_pin() is None
        task_type, kwargs, res_q = ui_task_queue.get_nowait()
        res_q.put('1234')               # the "user" answers too late: no error


    def test_gui_flag_routes_provider(self):
        ''' dashboard.destroy() flips the flag so new prompts route to the CLI fallback, 
            not an undrained queue
        '''

        # read the flag live off the module: a from-import binds the value at
        # import time and would always "restore" the stale snapshot
        saved = ui_bridge._GUI_IS_ACTIVE
        try:
            set_gui_active(True)
            assert isinstance(get_ui_provider(), ThreadSafeUIProxy)
            set_gui_active(False)
            assert isinstance(get_ui_provider(), CLIUserInterface)
        finally:
            set_gui_active(saved)


@unittest.skipUnless(_TK_IMPORTABLE, 'dashboard module needs tkinter importable')
class TestMonitorUiQueueLive(unittest.TestCase):
    ''' _monitor_ui_queue() must route a queued task to the renderer and put the answer back. 
        uses self.ui_renderer and self.after, no display or a real DesktopDashboard needed
    '''

    class _FakeDash:
        class _Renderer:
            def prompt_pin(self, attempt=1, label='PIN'): return '1234'
            def choose_certificate(self, certs): return 1
            def confirm_sign(self, text, additional_text=None): return True
        ui_renderer = _Renderer()
        rescheduled = False
        _monitor_ui_queue = None   # looked up by the real method when it reschedules
        def after(self, delay, cb): self.rescheduled = True


    def tearDown(self):
        while not ui_task_queue.empty():
            ui_task_queue.get_nowait()

    def test_single_queue_identity(self):
        ''' The packaging pass retired the dual-module trap: dashboard.py once
            imported `ui_bridge` via a sys.path shim while tests imported
            `src.ui_bridge` - two module objects, two DIFFERENT queues. Pin
            that there is exactly one queue object ever again. '''

        import src.dashboard
        assert src.dashboard.ui_task_queue is ui_task_queue

    def test_routes_pin_task_and_answers(self):

        res_q = queue.Queue()
        ui_task_queue.put(('prompt_pin', {'attempt': 1, 'label': 'PIN'}, res_q))
        dash = self._FakeDash()
        DesktopDashboard._monitor_ui_queue(dash)
        assert res_q.get_nowait() == '1234'
        assert dash.rescheduled, 'monitor loop must reschedule itself'


    def test_empty_queue_is_not_an_error(self):

        dash = self._FakeDash()
        DesktopDashboard._monitor_ui_queue(dash)   # must not raise
        assert dash.rescheduled


class TestTrustOfferDecision(unittest.TestCase):
    '''
    _poll_trust_offer must re-offer when the cert is untrusted (a delete or a
    regen), yet never nag about a cert the user already declined - keyed on the
    cert fingerprint. Drives the unbound method with a stub self, no display.
    '''

    def setUp(self):
        import src.dashboard as D
        self.D = D
        self.store = {}
        self._orig_get, self._orig_set = D.config.get, D.config.set
        self._orig_mb = D.MessageBox
        D.config.get = lambda k, d='': self.store.get(k, d)
        D.config.set = lambda k, v: self.store.__setitem__(k, v)
        self.asked = []
        outer = self

        class FakeMB:
            answer = True
            @staticmethod
            def askyesno(title, msg):
                outer.asked.append(title)
                return FakeMB.answer
        self.FakeMB = FakeMB
        D.MessageBox = FakeMB

    def tearDown(self):
        self.D.config.get, self.D.config.set = self._orig_get, self._orig_set
        self.D.MessageBox = self._orig_mb

    def _self(self, status, fp):
        s = types.SimpleNamespace(_trust_status=status, _trust_cert_fp=fp)
        s.after = lambda *a, **k: None
        s.trusted = []
        s._ui_trust_cert = lambda: s.trusted.append(True)
        return s

    def _poll(self, s):
        self.D.DesktopDashboard._poll_trust_offer(s)

    def test_untrusted_new_cert_offers(self):
        s = self._self('untrusted', 'FP1')
        self._poll(s)
        assert self.asked and s.trusted == [True]

    def test_declined_cert_is_not_nagged(self):
        self.store['trustDeclinedFor'] = 'FP1'
        s = self._self('untrusted', 'FP1')
        self._poll(s)
        assert not self.asked

    def test_regenerated_cert_reoffers_despite_old_decline(self):
        self.store['trustDeclinedFor'] = 'FP1'      # declined the OLD cert
        s = self._self('untrusted', 'FP2')          # a new fingerprint
        self._poll(s)
        assert self.asked

    def test_decline_is_remembered_per_cert(self):
        self.FakeMB.answer = False
        s = self._self('untrusted', 'FP9')
        self._poll(s)
        assert self.store.get('trustDeclinedFor') == 'FP9'

    def test_trusted_never_offers(self):
        s = self._self('trusted', 'FP1')
        self._poll(s)
        assert not self.asked


@unittest.skipUnless(HAS_DISPLAY, 'needs a Tk display')
class TestTrustIndicator(unittest.TestCase):
    ''' _set_trust_indicator maps status -> label text + palette colour '''

    def setUp(self):
        import tkinter as tk
        from src.tkinter_mods import Theme
        Theme.apply('dark')
        self.Theme = Theme
        self.label = tk.Label(_SHARED_ROOT)
        self.stub = types.SimpleNamespace(trust_status_label=self.label)

    def tearDown(self):
        self.label.destroy()

    def test_trusted_is_green(self):
        DesktopDashboard._set_trust_indicator(self.stub, 'trusted')
        assert 'trusted' in self.label.cget('text')
        assert self.label.cget('fg') == self.Theme.SUCCESS

    def test_untrusted_is_danger(self):
        DesktopDashboard._set_trust_indicator(self.stub, 'untrusted')
        assert 'not trusted' in self.label.cget('text')
        assert self.label.cget('fg') == self.Theme.DANGER

    def test_unavailable_is_muted(self):
        DesktopDashboard._set_trust_indicator(self.stub, 'unavailable')
        assert self.label.cget('fg') == self.Theme.TEXT_MUTED


class TestDashboardWiring(unittest.TestCase):
    ''' Dashboard wiring regression guards - pure source inspection, no display '''

    @classmethod
    def setUpClass(cls):
        with open(_SRC + '/dashboard.py', encoding='utf-8') as fh:
            cls.source = fh.read()
        cls.tree = ast.parse(cls.source)


    def _imported_modules(self):

        mods = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                mods.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module)
        return mods


    def test_no_dead_module_imports(self):
        mods = self._imported_modules()
        assert 'crypto_parsing' not in mods
        assert 'server_ui' not in mods

    def test_pem_conversion_uses_cert_parser(self):
        assert 'cert_parser' in self._imported_modules()


    def test_get_ui_provider_is_never_called(self):
        called = [
            n for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'get_ui_provider'
        ]
        assert called == [], 'get_ui_provider() must not be called; use self.ui_renderer'


    def test_no_hardcoded_slot_id_one(self):
        bad = [
            kw for n in ast.walk(self.tree) if isinstance(n, ast.Call)
            for kw in n.keywords
            if kw.arg == 'slot_id' and isinstance(kw.value, ast.Constant) and kw.value.value == 1
        ]
        assert bad == [], 'slot_id=1 hard-coding regressed; use hardware.get_slots(...)'


    def test_admin_path_reads_slots_dynamically(self):
        assert 'get_slots' in self.source

    def test_websites_view_is_built_and_navigable(self):
        # The view must be constructed AND reachable from the sidebar - building
        # one without the other leaves a dead tab or a KeyError on click.
        assert '_build_websites_view' in self.source
        assert "'websites'" in self.source

    def test_verify_flow_runs_the_real_checker_tool(self):
        # The in-app dry run must reuse tools/check_registrar_flow.py, not fork
        # a second implementation of the portal's probe sequence.
        assert 'check_registrar_flow.py' in self.source

    def test_every_detector_call_exists(self):
        ''' scan_card called detector.get_readers(), which did not exist -
            the Scan button AttributeError'd on click. Pin that every
            detector.X the dashboard calls is actually defined. '''

        from src import detector
        called = {
            n.func.attr for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == 'detector'
        }
        missing = sorted(c for c in called if not hasattr(detector, c))
        assert missing == [], f'dashboard calls detector.{missing} which do not exist'


    def test_destroy_deactivates_gui_routing(self):
        ''' The GUI is the queue's only consumer; if the flag outlives it,
            get_ui_provider() routes prompts to a queue nobody drains and the
            server loop freezes. destroy() must call set_gui_active(False)
        '''

        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'destroy':
                calls = [
                    n for n in ast.walk(node)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == 'set_gui_active'
                    and n.args and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value is False
                ]
                assert calls, 'destroy() no longer flips the GUI flag'
                return
        self.fail('DesktopDashboard.destroy() is gone - the dead-GUI deadlock is back')


@unittest.skipUnless(_TK_IMPORTABLE, 'dashboard module needs tkinter importable')
class TestKnownPortals(unittest.TestCase):
    ''' The Websites tab is data-driven; pin the data's shape and provenance '''

    def test_entries_are_well_formed(self):
        from src.dashboard import KNOWN_PORTALS
        assert KNOWN_PORTALS
        for p in KNOWN_PORTALS:
            assert p['name']
            assert p['url'].startswith('https://'), p['url']
            assert p['note']
            if 'test_url' in p:
                assert p['test_url'].startswith('https://'), p['test_url']

    def test_registrar_is_listed_with_its_test_page(self):
        from src.dashboard import KNOWN_PORTALS
        registrar = [p for p in KNOWN_PORTALS if 'registryagency.bg' in p['url']]
        assert len(registrar) == 1
        assert registrar[0]['test_url'] == 'https://portal.registryagency.bg/test-signature'


# Layer 2: composite widgets - display required, mainloop NOT required
@_needs_display
class TkTestCase(unittest.TestCase):
    ''' All display tests share the ONE module root (macOS Aqua Tk segfaults
        on repeated root create/destroy cycles); tests pump events manually '''

    @classmethod
    def setUpClass(cls):
        cls.root = _SHARED_ROOT

    @classmethod
    def tearDownClass(cls):
        # Scrub whatever this class packed into the shared root, but keep the
        # root itself alive for the next class.
        for w in list(cls.root.winfo_children()):
            w.destroy()
        cls.root.update_idletasks()

    def pump(self):
        ''' Process all pending Tk events without entering mainloop '''

        self.root.update_idletasks()
        self.root.update()

    def wait_for(self, cond, timeout_ms=1000):
        ''' Pump until `cond()` holds or the timeout expires. Unlike a bare pump(),
            the sleep lets after()-scheduled work mature - needed for the bounded
            grab retry, which arrives on a 25ms timer under strict X11.
        '''

        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            self.pump()
            if cond():
                return True
            time.sleep(0.01)
        return cond()


class TestWidgets(TkTestCase):

    def _button(self, *args, **kwargs):
        ''' Build a Button and force its first paint '''

        btn = Button(self.root, *args, **kwargs)
        btn.pack()
        self.pump()
        btn._draw()
        return btn

    def test_button_renders_its_label(self):
        btn = self._button('Go', lambda: None, width=100, height=30)
        assert btn.itemcget(btn.text_id, 'text') == 'Go'

    def test_button_release_inside_fires_command(self):
        fired = []
        btn = self._button('Go', lambda: fired.append(1), width=100, height=30)

        class E: x, y = 10, 10          # release inside the button bounds
        btn._on_release(E)
        assert fired == [1]

        class Outside: x, y = 500, 500  # drag-off-and-release must NOT fire
        btn._on_release(Outside)
        assert fired == [1]

    def test_button_hover_changes_canvas_fill(self):
        ''' Assert on canvas item state, not pixels '''

        btn = self._button('Hover', lambda: None)
        btn._on_enter(None)
        assert btn.itemcget(btn.rect_id, 'fill') == Theme.HOVER
        btn._on_leave(None)
        assert btn.itemcget(btn.rect_id, 'fill') == Theme.PRIMARY

    def test_toggle_flips_state_and_notifies(self):
        seen = []
        t = Toggle(self.root, text='opt', command=seen.append, is_on=False)
        t.pack(); self.pump()
        t.toggle()
        assert t.get()
        assert seen == [True]

    def test_entry_masks_but_returns_plaintext(self):
        e = Entry(self.root, show='*')
        e.pack(); self.pump()
        e.entry.insert(0, '1234')
        assert e.get() == '1234'
        assert e.entry.cget('show') == '*'

    def test_entry_placeholder_is_not_masked_and_reads_empty(self):
        # The PIN-field subtlety: the hint must not render as asterisks, 
        # an untouched field must read as empty rather than as the hint text.
        e = Entry(self.root, show='*', placeholder='Enter PIN')
        e.pack(); self.pump()
        assert e.entry.cget('show') == ''
        assert e.get() == ''
        e._clear_placeholder()
        e.entry.insert(0, '4321')
        assert e.entry.cget('show') == '*'
        assert e.get() == '4321'

    def test_button_survives_bare_toplevel_host(self):
        ''' Unscaled buttons beat invisible ones '''

        host = tk.Toplevel(self.root)   # mapped briefly: withdrawn toplevels
        host.geometry('120x50+0+0')     # never lay out children (width stays 1)
        try:
            btn = Button(host, 'Go', lambda: None, width=100, height=30)
            btn.pack()
            self.wait_for(lambda: btn.winfo_width() > 1)
            btn._draw()                 # must not die on missing ui_scale
            assert btn.text_id is not None, 'Button never drew on a bare host'
            assert btn.itemcget(btn.text_id, 'text') == 'Go'
        finally:
            host.destroy()

    def test_callback_exceptions_are_logged_not_swallowed(self):
        ''' Window.report_callback_exception routes Tk-swallowed tracebacks
            into logging 
        '''

        records = []
        handler = logging.Handler()
        handler.emit = records.append              # capture each record verbatim
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.ERROR)
        try:
            try:
                raise ValueError('boom in a callback')
            except ValueError:
                self.root.report_callback_exception(*sys.exc_info())
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)

        # format() folds in the traceback (exc_info), where the message lands
        fmt = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
        output = '\n'.join(fmt.format(r) for r in records if r.levelno >= logging.ERROR)
        assert 'boom in a callback' in output


    def test_zoom_respects_bounds(self):
        saved = self.root.zoom_level    # shared root: leave it as found
        try:
            for _ in range(30):
                self.root._zoom_in()
            assert self.root.zoom_level <= 24
            for _ in range(40):
                self.root._zoom_out()
            assert self.root.zoom_level >= 8
        finally:
            self.root.zoom_level = saved


class TestWidgetDelegation(TkTestCase):
    ''' Textbox/Listbox wrap a native widget inside a rounded Frame '''

    def test_textbox_configure_and_cget_round_trip(self):

        tb = Textbox(self.root)
        tb.configure(bg='#123456')
        assert str(tb.cget('bg')) == '#123456'
        tb.insert('end', 'hello')
        assert 'hello' in tb.text.get('1.0', 'end')


    def test_listbox_configure_and_cget_round_trip(self):
        lb = Listbox(self.root)
        lb.configure(selectforeground='#abcdef')
        assert str(lb.cget('selectforeground')) == '#abcdef'


    def test_listbox_insert_and_delete(self):

        lb = Listbox(self.root)
        lb.insert('end', 'a')
        lb.insert('end', 'b')
        assert lb.listbox.size() == 2
        lb.delete(0, 'end')
        assert lb.listbox.size() == 0


class TestToplevelGrabLifecycle(TkTestCase):
    ''' Pins the lifecycle contract: no modal grab while withdrawn (X11 raises "grab failed: window not viewable"  
    
        NOTE: Xvfb's grab semantics are lenient - the crash these guard against only manifests 
        under a real WM. A green run here is necessary but not sufficient - sanity-run
        the widget gallery on an actual desktop too.
    '''

    def tearDown(self):
        # A failed assertion must not leave a grab that poisons later tests
        for w in list(self.root.winfo_children()):
            if isinstance(w, tk.Toplevel) and w.winfo_exists():
                w.grab_release()
                w.destroy()
        self.pump()

    def test_construction_takes_no_grab_and_stays_hidden(self):
        ''' THE regression: __init__ used to grab_set() while withdrawn, which
            X11 rejects with TclError. Construction must neither raise nor
            hold a grab. '''

        try:
            tl = Toplevel(self.root, title='probe', width=200, height=120)
        except tk.TclError as e:
            self.fail(f'grab regression: Toplevel unconstructable while '
                      f'withdrawn ({e}) - grab_set belongs in show()')
        self.pump()
        assert tl.winfo_viewable() == 0, 'flashed before show()'
        assert self.root.grab_current() is None, 'modal grab taken while withdrawn - X11 crashes here'

    def test_show_takes_grab_and_reveals(self):
        tl = Toplevel(self.root, title='pin', width=200, height=120)
        tl.show()
        # The master root is withdrawn here, so show() drops the transient
        # hint (a transient of an unmapped master may never map at all) and
        # the grab may arrive via the bounded 25ms retry - hence wait_for.
        assert self.wait_for(lambda: tl.winfo_viewable() == 1), 'dialog never mapped after show()'
        # str() comparison sidesteps the dual-module class-identity trap
        assert self.wait_for(
            lambda: str(self.root.grab_current()) == str(tl)), 'show() must own the modal grab'

    def test_destroy_releases_grab(self):
        ''' A cancelled PIN dialog must not leave the whole app ungrabbable '''

        tl = Toplevel(self.root, title='pin', width=200, height=120)
        tl.show()
        self.wait_for(lambda: self.root.grab_current() is not None)
        tl.destroy()
        self.pump()
        assert self.root.grab_current() is None

    def test_show_survives_destroy_mid_reveal(self):
        ''' A scripted user (or our modal test driver) can destroy the dialog
            around the reveal; the pending grab retry then fires against a
            dead window. Pinned: show() never raises and no grab is left. '''

        tl = Toplevel(self.root, title='doomed', width=200, height=120)
        self.root.after(1, tl.destroy)
        tl.show()                       # must not raise
        self.wait_for(lambda: not tl.winfo_exists())
        assert self.root.grab_current() is None

    def test_two_dialogs_in_sequence(self):
        ''' The retry-PIN flow: dialog one closes, dialog two must be able to
            take the grab afresh (a leaked grab here blocks the second prompt). '''

        first = Toplevel(self.root, title='attempt 1', width=200, height=120)
        first.show()
        self.wait_for(lambda: self.root.grab_current() is not None)
        first.destroy(); self.pump()

        second = Toplevel(self.root, title='attempt 2', width=200, height=120)
        second.show()
        assert self.wait_for(
            lambda: str(self.root.grab_current()) == str(second)), 'second dialog never re-acquired the grab'


class TestMessageBoxGrabLifecycle(TkTestCase):
    ''' MessageBox builds a bare tk.Toplevel with no master, so it attaches to
        the default root - which in this suite is TkTestCase's Window. The
        driver below leans on that (and documents it). '''

    def setUp(self):
        self._after_ids = []

    def tearDown(self):
        # The retry loops below reschedule themselves
        for aid in self._after_ids:
            try:
                self.root.after_cancel(aid)
            except tk.TclError:
                pass
        for w in list(self.root.winfo_children()):
            if isinstance(w, tk.Toplevel) and w.winfo_exists():
                w.grab_release()
                w.destroy()
        self.pump()

    def _close_when_present(self, closed):
        def run():
            dlgs = [w for w in self.root.winfo_children()
                    if isinstance(w, tk.Toplevel) and w.winfo_exists()]
            if not dlgs:
                self._after_ids.append(self.root.after(50, run))
                return
            dlgs[-1].destroy()
            closed.append(1)
        self._after_ids.append(self.root.after(150, run))

    def test_askyesno_defaults_false_when_closed_and_releases_grab(self):
        from src.tkinter_mods import MessageBox
        closed = []
        self._close_when_present(closed)
        assert not MessageBox.askyesno('Confirm', 'Proceed?'), 'closing the dialog must mean No, not Yes'
        assert closed, 'driver never found the MessageBox toplevel'
        self.pump()
        assert self.root.grab_current() is None, 'MessageBox leaked its modal grab'

    def test_messagebox_inherits_root_ui_scale(self):
        ''' Regression: raw tk.Toplevel had no ui_scale, so Button._draw died
            with AttributeError (swallowed by Tk) and the OK/Yes/No buttons
            never rendered; on HiDPI the box also stayed at 100%. '''

        from src.tkinter_mods import MessageBox, Button as ModsButton

        seen = {}
        def probe(dlg):
            seen['ui_scale'] = getattr(dlg, 'ui_scale', None)
            buttons = find_by_attr(dlg, 'rect_id')
            self.pump()
            for b in buttons:
                b._draw()               # withdrawn-root harness: force paint
            seen['drawn'] = [b.text_id is not None for b in buttons]
            dlg.destroy()

        def run():
            dlgs = [w for w in self.root.winfo_children()
                    if isinstance(w, tk.Toplevel) and w.winfo_exists()]
            if not dlgs:
                self._after_ids.append(self.root.after(50, run))
                return
            probe(dlgs[-1])
        self._after_ids.append(self.root.after(150, run))

        MessageBox.showinfo('Info', 'scaled?')
        assert seen.get('ui_scale') == self.root.ui_scale
        assert seen.get('drawn') and all(seen['drawn']), 'MessageBox buttons failed to draw (ui_scale missing?)'


# -- Layer 3: blocking modal dialogs, driven by scheduled interaction
class TestModalRenderer(TkTestCase):

    def setUp(self):
        self._after_ids = []
        self._drive_error = None

    def tearDown(self):
        ''' A dialog that raises leaves an open Toplevel (holding a grab) and a pending 
            after() callback behind
        '''

        for aid in self._after_ids:
            try:
                self.root.after_cancel(aid)
            except tk.TclError:
                pass
        for w in list(self.root.winfo_children()):
            if isinstance(w, tk.Toplevel) and w.winfo_exists():
                w.grab_release()
                w.destroy()
        self.pump()

        if self._drive_error is not None:
            raise self._drive_error

    def _renderer(self):
        from src.dashboard import ModalRenderer
        return ModalRenderer(self.root)

    def _dialog(self):
        dialogs = [w for w in self.root.winfo_children()
                   if isinstance(w, tk.Toplevel) and w.winfo_exists()]
        return dialogs[-1] if dialogs else None

    def _drive(self, action, delay=150):
        ''' Drive the modal once it is viewable '''

        def run(tries=0):
            dialog = self._dialog()
            if dialog is None or not dialog.winfo_viewable():
                if tries < 80:          # not built, or mapped+grabbed yet
                    self._after_ids.append(self.root.after(50, lambda: run(tries + 1)))
                return
            dialog.focus_force()
            try:
                action(dialog)
            except Exception as exc:
                # Tk swallows exceptions raised inside an after() callback, so a
                # never-dismissed dialog would block wait_window() forever.
                # Capture the error and close it so the test *fails* instead.
                self._drive_error = exc
                dialog.destroy()
                return
            self._after_ids.append(self.root.after(100, lambda: self._ensure_dismissed(0)))

        self._after_ids.append(self.root.after(delay, run))

    def _ensure_dismissed(self, tries):
        ''' Safety net: never let a stuck modal hang the suite - fail cleanly '''

        dialog = self._dialog()
        if dialog is None:
            return                      # dismissed as intended
        if tries < 40:                  # ~4s grace for the interaction to take
            self._after_ids.append(self.root.after(100, lambda: self._ensure_dismissed(tries + 1)))
            return
        self._drive_error = self._drive_error or AssertionError(
            'modal did not dismiss - the interaction event was not honoured')
        dialog.grab_release()
        dialog.destroy()

    def test_prompt_pin_returns_entered_pin(self):
        def type_and_submit(dlg):
            # Drive the composite Entry, not the raw tk.Entry
            field = find_by_attr(dlg, '_clear_placeholder')[0]
            field._clear_placeholder()
            field.entry.insert(0, '4321')
            dlg.event_generate('<Return>')

        self._drive(type_and_submit)
        assert self._renderer().prompt_pin() == '4321'

    def test_prompt_pin_escape_cancels(self):
        self._drive(lambda dlg: dlg.event_generate('<Escape>'))
        assert self._renderer().prompt_pin() is None

    def test_confirm_sign_reject(self):
        self._drive(lambda dlg: dlg.event_generate('<Escape>'))
        assert not self._renderer().confirm_sign('sign this?')

    def test_choose_certificate_defaults_to_first(self):
        self._drive(lambda dlg: dlg.event_generate('<Return>'))
        certs = [{'subject': 'Alice', 'serial': '1'}, {'subject': 'Bob', 'serial': '2'}]
        assert self._renderer().choose_certificate(certs) == 0

    def test_choose_certificate_escape_returns_sentinel(self):
        self._drive(lambda dlg: dlg.event_generate('<Escape>'))
        certs = [{'subject': 'Alice', 'serial': '1'}]
        assert self._renderer().choose_certificate(certs) == -1


# ===========================================================================
# Comma-decimal locale (bg_BG) canvas smoke. pybiss's audience runs bg_BG,
# where LC_NUMERIC's decimal separator is ','. Historically Tk's float->Tcl
# conversion followed the C locale and emitted "1,5", crashing canvas coord
# parsing. Modern CPython converts dot-decimal regardless, so this passes today
# -- guards the older-Tk platforms in the CI matrix.
# ===========================================================================
@_needs_display
class TestCommaLocaleCanvas(unittest.TestCase):

    def _try_set_bg_locale(self):
        for name in ('bg_BG.UTF-8', 'bg_BG.utf8', 'bg_BG'):
            try:
                locale.setlocale(locale.LC_NUMERIC, name)
                return name
            except locale.Error:
                continue
        return None

    def test_float_coords_survive_comma_locale(self):
        # Reuse the shared root (no second Tk() - see the macOS note up top);
        # the float->Tcl conversion under test happens per-call, so setting
        # LC_NUMERIC now affects the canvas calls below regardless of when the
        # root was created.
        saved = locale.setlocale(locale.LC_NUMERIC)
        cv = None
        try:
            if not self._try_set_bg_locale():
                self.skipTest('bg_BG locale not installed')
            if locale.str(1.5) != '1,5':
                # musl (Alpine) accepts any locale name in setlocale() but
                # keeps C-locale numeric formatting - there is no comma-decimal
                # behaviour to exercise, so it can't run the test.
                self.skipTest('libc has no real bg_BG numeric locale (musl?)')
            cv = tk.Canvas(_SHARED_ROOT, width=100, height=100)
            cv.create_line(1.5, 2.5, 10.25, 20.75)     # must not raise
            cv.create_polygon(1.5, 1.5, 50.5, 10.0, 25.25, 40.5)
            _SHARED_ROOT.update_idletasks()
        finally:
            if cv is not None:
                cv.destroy()
            locale.setlocale(locale.LC_NUMERIC, saved)


if __name__ == '__main__':
    unittest.main()
