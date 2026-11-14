import sys, unittest
import tkinter as tk

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

try:
    from src.tkinter_mods import (
        detect_system_theme, _even, scrollbar_thumb_bounds, scrollbar_drag_start,
        get_window_dpi_scale, DpiTracker, Window, Theme, Label, Button, Entry,
    )
except ImportError as e:
    raise unittest.SkipTest(f'tkinter not available on this platform: {e}')


class FakeWindow:
    ''' Headless stand-in that captures after() callbacks so we can drive them '''

    def __init__(self, tk_scaling=1.3333):
        self._exists = True
        self._state = 'normal'
        self._tk_scaling = tk_scaling
        self.pending = []  # (delay, callback)

    # tkinter surface used by the code under test
    def winfo_exists(self): return self._exists
    def state(self): return self._state
    def after(self, delay, cb): self.pending.append((delay, cb))

    class _Tk:
        def __init__(self, outer): self._outer = outer
        def call(self, *args): return self._outer._tk_scaling

    @property
    def tk(self): return self._Tk(self)

    def run_next(self):
        delay, cb = self.pending.pop(0)
        cb()
        return delay


class TestEven(unittest.TestCase):

    def test_floors_to_even(self):
        assert _even(11) == 10
        assert _even(10) == 10
        assert _even(11.9) == 10
        assert _even(0) == 0


class TestScrollbarThumbBounds(unittest.TestCase):

    def test_normal_thumb_maps_proportionally(self):
        y1, y2 = scrollbar_thumb_bounds(0.25, 0.75, 200)
        assert (y1, y2) == (50.0, 150.0)

    def test_tiny_thumb_gets_minimum_size_without_leaving_track(self):
        # A near-zero thumb at the very bottom must still fit inside [0, height]
        y1, y2 = scrollbar_thumb_bounds(0.99, 1.0, 200, min_px=10)
        assert y2 - y1 >= 10 - 1e-9
        assert y2 <= 200 + 1e-9
        assert y1 >= 0

    def test_tiny_thumb_at_top_stays_anchored_at_zero(self):
        y1, y2 = scrollbar_thumb_bounds(0.0, 0.001, 200, min_px=10)
        assert round(y1 - 0.0, 7) == 0
        assert y2 - y1 >= 10 - 1e-9


class TestScrollbarDragStart(unittest.TestCase):

    def test_grabbed_point_stays_under_cursor(self):
        # thumb occupies 25% of track; grabbed 10% from its top
        thumb_len = 0.25
        grab_offset = 0.10
        # cursor at 0.60 -> thumb top should be 0.50
        assert round(scrollbar_drag_start(0.60, grab_offset, thumb_len) - 0.50, 7) == 0

    def test_clamped_to_track_top_and_bottom(self):
        assert scrollbar_drag_start(-5, 0.0, 0.25) == 0.0
        assert scrollbar_drag_start(5, 0.0, 0.25) == 0.75

    def test_center_grab_behaves_like_page_jump(self):
        # grab_offset = half the thumb -> cursor becomes the thumb centre
        assert round(scrollbar_drag_start(0.5, 0.125, 0.25) - 0.375, 7) == 0


class TestDetectSystemTheme(unittest.TestCase):

    def test_returns_valid_value_or_none(self):
        # Never raises; result is one of the three allowed values on any OS
        assert detect_system_theme() in ('dark', 'light', None)


class TestThemePalette(unittest.TestCase):
    ''' Palette swap + change-mapping logic (no Tk root needed) '''

    def setUp(self):
        Theme.apply('dark')                      # deterministic start

    def tearDown(self):
        Theme.apply('dark')                      # never leak light into other tests

    def test_apply_switches_mode_and_values(self):
        assert Theme.MODE == 'dark'
        assert Theme.BG == '#242424'
        Theme.apply('light')
        assert Theme.MODE == 'light'
        assert Theme.BG == '#EBEBEB'
        assert Theme.PRIMARY == '#3B8ED0'

    def test_mapping_reports_only_changed_colours(self):
        mapping = Theme.apply('light')
        assert mapping['#242424'] == '#EBEBEB'
        # DANGER is identical in both palettes -> never in the mapping
        assert '#e74c3c' not in mapping

    def test_switch_is_reversible(self):
        Theme.apply('light')
        Theme.apply('dark')
        assert Theme.BG == '#242424'
        assert Theme.PRIMARY == '#1F6AA5'

    def test_resolve_passes_explicit_modes_through(self):
        assert Theme.resolve('dark') == 'dark'
        assert Theme.resolve('light') == 'light'

    def test_resolve_system_yields_a_concrete_mode(self):
        # 'system'/'auto'/None all resolve to a real palette name, never raise
        for pref in ('system', 'auto', None):
            assert Theme.resolve(pref) in ('dark', 'light')


class TestThemeLiveRetint(unittest.TestCase):
    ''' apply_live repaints already-built widgets in place (needs a Tk root) '''

    def setUp(self):
        Theme.apply('dark')
        try:
            self.win = Window(title='theme-retint-test')
        except Exception as e:
            self.skipTest(f'no Tk display: {e}')

    def tearDown(self):
        try:
            self.win.destroy()
        except Exception:
            pass
        Theme.apply('dark')

    def test_widgets_retint_on_switch_and_back(self):
        label = Label(self.win, text='x'); label.pack()
        button = Button(self.win, 'Primary', lambda: None); button.pack()
        entry = Entry(self.win, width=120); entry.pack()
        self.win.update_idletasks()

        assert label.cget('bg').lower() == '#242424'
        assert button.fg_color == '#1F6AA5'

        mapping = Theme.apply('light')
        Theme.apply_live(self.win, mapping)
        self.win.update_idletasks()

        assert label.cget('bg').lower() == '#ebebeb'
        assert button.fg_color == '#3B8ED0'
        assert entry.entry.cget('insertbackground').lower() == '#1a1a1a'

        mapping = Theme.apply('dark')
        Theme.apply_live(self.win, mapping)
        self.win.update_idletasks()
        assert label.cget('bg').lower() == '#242424'


class TestRetint052(unittest.TestCase):
    ''' 0.5.2: a Textbox's rounded frame follows a live theme switch (its ``configure`` proxies
        to the text widget, so apply_live could not reach the frame itself), and a second
        Window can be created while the first one lives (its blank icon used the first root). '''

    def setUp(self):
        Theme.apply('dark')
        try:
            self.win = Window(title='retint-052')
        except Exception as e:                            # noqa: BLE001
            self.skipTest(f'no Tk display: {e}')
        self.win.withdraw()

    def tearDown(self):
        self.win.destroy()
        Theme.apply('dark')

    def test_textbox_frame_retints(self):
        from src.tkinter_mods import Textbox
        box = Textbox(self.win, width=200, height=80); box.pack()
        self.win.update_idletasks()
        Theme.apply_live(self.win, Theme.apply('light'))
        self.win.update_idletasks()
        light = Theme.BG.lower()
        assert tk.Frame.cget(box, 'bg').lower() == light, tk.Frame.cget(box, 'bg')
        assert box.canvas.cget('bg').lower() == light and box.inner.cget('bg').lower() == Theme.SURFACE.lower()
        assert box.text.cget('bg').lower() == Theme.SURFACE.lower()
        fills = {box.canvas.itemcget(i, 'fill').lower() for i in box.canvas.find_all() if box.canvas.type(i) != 'line'}
        assert fills == {Theme.SURFACE.lower()}, fills

    def test_second_window_gets_its_own_icon(self):
        other = Window(title='retint-052-second')
        try:
            assert str(other._blank_icon) != str(self.win._blank_icon)
        finally:
            other.destroy()


@unittest.skipUnless(sys.platform not in ('win32', 'darwin'), 'Linux tk-scaling path')
class TestDpiScaleLinux(unittest.TestCase):

    def test_tk_scaling_maps_to_dpi_factor(self):
        # 1.3333 px/pt == 96 dpi == 100% -> factor 1.0
        assert round(get_window_dpi_scale(FakeWindow(tk_scaling=1.3333)) - 1.0, 3) == 0
        # 2.0 px/pt -> 150%
        assert round(get_window_dpi_scale(FakeWindow(tk_scaling=2.0)) - 1.5, 3) == 0


class TestScaleSplit(unittest.TestCase):
    '''
    ui_scale (geometry, absolute DPI) vs font_scale (fonts, DPI ratio) must differ above 100%, 
    or fonts double-scale. Properties are exercised via .fget on a stub - no Tk root.
    '''

    class _Stub:
        def __init__(self, zoom, dpi, startup):
            self.zoom_level, self._dpi_scale, self._startup_dpi_scale = zoom, dpi, startup

    def test_startup_on_150pct_leaves_fonts_untouched(self):
        s = self._Stub(zoom=12, dpi=1.5, startup=1.5)
        assert round(Window.ui_scale.fget(s) - 1.5, 7) == 0
        assert round(Window.font_scale.fget(s) - 1.0, 7) == 0

    def test_dragging_to_100pct_shrinks_fonts_by_ratio(self):
        s = self._Stub(zoom=12, dpi=1.0, startup=1.5)
        assert round(Window.ui_scale.fget(s) - 1.0, 7) == 0
        assert round(Window.font_scale.fget(s) - 1.0 / 1.5, 7) == 0

    def test_font_never_gets_absolute_factor(self):
        # font_scale must NOT equal ui_scale above 100%
        s = self._Stub(zoom=12, dpi=1.5, startup=1.5)
        assert round(Window.font_scale.fget(s) - Window.ui_scale.fget(s), 7) != 0


class TestDpiTracker(unittest.TestCase):

    def test_fires_on_change_and_settles(self):
        win = FakeWindow()
        # __init__ probe -> 1.0; poll #1 -> 1.0 (no change); poll #2 -> 1.5 (change)
        scales = iter([1.0, 1.0, 1.5])
        events = []
        tr = DpiTracker(win, lambda old, new: events.append((old, new)),
                        probe=lambda w: next(scales))

        assert tr.scale == 1.0
        win.run_next()                                          # poll #1: no change
        assert events == []
        assert win.pending[-1][0] == DpiTracker.poll_interval
        win.run_next()                                          # poll #2: change
        assert events == [(1.0, 1.5)]
        assert tr.scale == 1.5
        assert win.pending[-1][0] == DpiTracker.settle_interval

    def test_loop_dies_when_window_gone(self):
        win = FakeWindow()
        DpiTracker(win, lambda o, n: None, probe=lambda w: 1.0)
        win._exists = False
        win.run_next()                          # should return without rescheduling
        assert win.pending == []

    def test_skips_probe_while_minimized(self):
        win = FakeWindow()
        win._state = 'iconic'
        probed = []
        DpiTracker(win, lambda o, n: None, probe=lambda w: probed.append(1) or 1.0)
        probed.clear()                          # ignore the initial probe
        win.run_next()
        assert probed == []
        assert win.pending

    def test_a_destroyed_window_leaves_no_timer_behind(self):
        try:
            win = Window(title='dpi-timer-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        win.withdraw()
        tr = win._dpi_tracker
        pending = lambda: set(win.tk.splitlist(win.tk.call('after', 'info')))
        timer = tr._timer
        assert timer in pending()
        tr.stop()
        assert timer not in pending() and tr._timer is None
        tr.stop()                               # twice is harmless
        tr._timer = win.after(DpiTracker.poll_interval, tr._poll)
        win.destroy()                           # the window stops its tracker on the way out
        assert tr._timer is None


if __name__ == '__main__':
    unittest.main()


# --- ListView (canvas-drawn, virtualised) ---

from src.tkinter_mods import (
    ListView, listview_column_layout, listview_visible_range, listview_row_at,
    listview_clamp_scroll, listview_scroll_fraction, listview_sort_key, listview_sorted,
    listview_range, listview_elide, listview_border_at, listview_drag_widths,
    listview_drop_index, listview_move_key, listview_merge_state,
    FileDialog, filedialog_matches, filedialog_fmt_size, filedialog_entries, filedialog_resolve,
    filedialog_parent, filedialog_places,
)


class TestListViewGeometry(unittest.TestCase):

    def test_columns_fixed_and_stretch_share_the_leftover(self):
        # 300 px: two fixed 50s, two stretch columns split the 200 left (no gap)
        assert listview_column_layout([50, 0, 50, 0], 300) == [(0, 50), (50, 100), (150, 50), (200, 100)]
        # gaps come off the stretch share
        assert listview_column_layout([50, 0], 300, gap=10) == [(0, 50), (60, 240)]
        # a stretch column never collapses below min_w even when the widget is narrow
        assert listview_column_layout([200, 0], 100, min_w=40) == [(0, 200), (200, 40)]
        assert listview_column_layout([], 100) == []
        # all fixed: laid out end to end, no stretch share
        assert listview_column_layout([30, 30], 500) == [(0, 30), (30, 30)]
        # with a stretch floor the name column keeps its share and fixed columns shrink
        lay = listview_column_layout([0, 300, 300], 400, min_w=40, stretch_floor=0.25)
        assert lay[0] == (0, 100) and lay[1][1] == lay[2][1] == 150 and lay[2][0] + lay[2][1] == 400, lay
        # enough room: the floor changes nothing
        assert listview_column_layout([0, 50, 50], 400, stretch_floor=0.25) == [(0, 300), (300, 50), (350, 50)]

    def test_visible_range_covers_partial_rows_at_both_edges(self):
        assert listview_visible_range(0, 100, 20, 1000) == (0, 5)
        assert listview_visible_range(10, 100, 20, 1000) == (0, 6)     # half row top and bottom
        assert listview_visible_range(20, 100, 20, 1000) == (1, 6)
        assert listview_visible_range(19_980, 100, 20, 1000) == (999, 1000)
        assert listview_visible_range(0, 100, 20, 3) == (0, 3)
        assert listview_visible_range(0, 100, 20, 0) == (0, 0)
        assert listview_visible_range(0, 0, 20, 10) == (0, 0)

    def test_row_at_respects_header_and_scroll(self):
        assert listview_row_at(5, 0, 30, 20, 10) is None          # on the header
        assert listview_row_at(30, 0, 30, 20, 10) == 0
        assert listview_row_at(49, 0, 30, 20, 10) == 0
        assert listview_row_at(50, 0, 30, 20, 10) == 1
        assert listview_row_at(30, 45, 30, 20, 10) == 2           # scrolled 2.25 rows
        assert listview_row_at(30 + 20 * 10, 0, 30, 20, 10) is None  # past the last row
        assert listview_row_at(130, 0, 30, 20, 10, bottom=130) is None  # below the viewport
        assert listview_row_at(129, 0, 30, 20, 10, bottom=130) == 4

    def test_scroll_clamp_and_fraction(self):
        assert listview_clamp_scroll(-5, 1000, 100) == 0
        assert listview_clamp_scroll(950, 1000, 100) == 900
        assert listview_clamp_scroll(50, 80, 100) == 0            # all fits
        assert listview_scroll_fraction(0, 80, 100) == (0.0, 1.0)
        s, e = listview_scroll_fraction(250, 1000, 100)
        assert abs(s - 0.25) < 1e-9 and abs(e - 0.35) < 1e-9
        assert listview_scroll_fraction(900, 1000, 100)[1] == 1.0

    def test_sort_key_orders_numbers_text_then_none_without_raising(self):
        rows = [{'v': 'b'}, {'v': 3}, {'v': None}, {'v': 'A'}, {'v': 1.5}, {'v': True}]
        order = listview_sorted(range(len(rows)), rows, 'v')
        assert [rows[i]['v'] for i in order] == [True, 1.5, 3, 'A', 'b', None]
        rev = listview_sorted(range(len(rows)), rows, 'v', reverse=True)
        assert [rows[i]['v'] for i in rev] == [None, 'b', 'A', 3, 1.5, True]
        assert listview_sort_key('x') < listview_sort_key(None)

    def test_sort_prefers_the_hidden_sort_value(self):
        rows = [{'size': '1.2 GB', '_sort': {'size': 1.2e9}}, {'size': '900 MB', '_sort': {'size': 9e8}}]
        assert listview_sorted([0, 1], rows, 'size') == [1, 0]
        assert listview_sorted([0, 1], rows, 'size', reverse=True) == [0, 1]
        # stable: equal keys keep their order
        rows = [{'n': 1}, {'n': 1}, {'n': 0}]
        assert listview_sorted([0, 1, 2], rows, 'n') == [2, 0, 1]

    def test_shift_range_is_inclusive_both_ways(self):
        assert list(listview_range(2, 5)) == [2, 3, 4, 5]
        assert list(listview_range(5, 2)) == [2, 3, 4, 5]
        assert list(listview_range(3, 3)) == [3]

    def test_elide_fits_under_a_pixel_budget(self):
        measure = lambda s: 7 * len(s)                     # 7 px per char
        assert listview_elide('hello', 100, measure) == 'hello'
        assert listview_elide('hello world', 42, measure) == 'hello…'   # 6 chars = 42 px
        assert listview_elide('hello world', 41, measure) == 'hell…'
        assert listview_elide('hello world', 7, measure) == '…'
        assert listview_elide('hello world', 6, measure) == ''
        assert listview_elide('', 0, measure) == ''


class TestListViewColumnHelpers(unittest.TestCase):
    def test_border_under_a_point(self):
        layout = [(0, 100), (108, 50), (166, 60)]                 # borders at 104 and 162
        assert listview_border_at(104, layout) == 0
        assert listview_border_at(107, layout) == 0 and listview_border_at(100, layout) == 0
        assert listview_border_at(109, layout) is None and listview_border_at(50, layout) is None
        assert listview_border_at(162, layout) == 1
        assert listview_border_at(226, layout) is None            # the last column's far edge is no border
        assert listview_border_at(112, layout, tolerance=8) == 0
        assert listview_border_at(5, []) is None and listview_border_at(5, [(0, 10)]) is None

    def test_drag_between_two_fixed_columns_trades_width_and_clamps(self):
        assert listview_drag_widths([10, 8], [10, 8], 0, 3, 4) == [13, 5]
        assert listview_drag_widths([10, 8], [10, 8], 0, -3, 4) == [7, 11]
        assert listview_drag_widths([10, 8], [10, 8], 0, 100, 4) == [14, 4]
        assert listview_drag_widths([10, 8], [10, 8], 0, -100, 4) == [4, 14]
        # the others are untouched and the total never changes
        out = listview_drag_widths([0, 10, 8, 6], [30, 10, 8, 6], 2, 1.5, 4)
        assert out == [0, 10, 9.5, 4.5] and sum(out) == 24

    def test_drag_next_to_the_stretch_column_changes_only_the_fixed_one(self):
        assert listview_drag_widths([10, 0], [10, 30], 0, 5, 4) == [15, 0]
        assert listview_drag_widths([10, 0], [10, 30], 0, 100, 4) == [36, 0]     # stretch keeps its minimum
        assert listview_drag_widths([10, 0], [10, 30], 0, -100, 4) == [4, 0]
        assert listview_drag_widths([0, 10], [30, 10], 0, 3, 4) == [0, 7]
        assert listview_drag_widths([0, 10], [30, 10], 0, 100, 4) == [0, 4]
        assert listview_drag_widths([0, 10], [30, 10], 0, -100, 4) == [0, 36]
        assert listview_drag_widths([0, 0], [20, 20], 0, 5, 4) == [0, 0]          # nothing fixed to change

    def test_drop_position_goes_by_midpoints(self):
        layout = [(0, 100), (100, 50), (150, 50)]
        assert [listview_drop_index(x, layout) for x in (-5, 10, 49, 51, 120, 126, 174, 176, 999)] == \
            [0, 0, 0, 1, 1, 2, 2, 3, 3]
        assert listview_drop_index(5, []) == 0

    def test_move_keeps_hidden_columns_beside_their_neighbours(self):
        order = ['a', 'b', 'c', 'd']
        assert listview_move_key(order, set(), 'd', 0) == ['d', 'a', 'b', 'c']
        assert listview_move_key(order, set(), 'a', 3) == ['b', 'c', 'd', 'a']
        assert listview_move_key(order, set(), 'a', 99) == ['b', 'c', 'd', 'a']
        assert listview_move_key(order, set(), 'b', 1) == order
        assert listview_move_key(order, {'b'}, 'd', 0) == ['d', 'a', 'b', 'c']
        assert listview_move_key(order, {'b'}, 'a', 1) == ['b', 'c', 'a', 'd']   # visible others: c, d
        assert listview_move_key(order, {'b'}, 'a', 2) == ['b', 'c', 'd', 'a']
        assert listview_move_key(['a'], set(), 'a', 0) == ['a']
        assert listview_move_key(order, {'a', 'b', 'c'}, 'd', 0) == ['a', 'b', 'c', 'd']

    def test_saved_state_merges_with_the_definitions(self):
        cols = [ListView._norm_column(c) for c in (
            ('name', 'Name', 0, 'w', {'required': True}), ('size', 'Size', 9, 'e'),
            ('progress', 'Progress', 10, 'w', 'progress'), ('state', 'Status', 11, 'w'))]
        assert cols[0]['required'] and cols[2]['kind'] == 'progress'
        for nothing in (None, [], 'junk', 7, {'key': 'size'}):
            order, widths, hidden = listview_merge_state(cols, nothing)
            assert order == ['name', 'size', 'progress', 'state'] and hidden == set()
            assert widths == {'name': 0, 'size': 9, 'progress': 10, 'state': 11}
        saved = [{'key': 'state', 'width': 20}, {'key': 'gone', 'width': 5}, 'junk', None,
                 {'key': 'name', 'width': 33, 'hidden': True},     # stays stretch, cannot be hidden
                 {'key': 'size', 'width': 'wide', 'hidden': True}, {'key': 'state', 'width': 3}]
        order, widths, hidden = listview_merge_state(cols, saved)
        # 'progress' is new to this state: it lands after 'size', its neighbour in the definitions
        assert order == ['state', 'name', 'size', 'progress']
        assert widths == {'name': 0, 'size': 9, 'progress': 10, 'state': 20}
        assert hidden == {'size'}
        for bad in (0, -4, 501, True, float('nan')):
            assert listview_merge_state(cols, [{'key': 'size', 'width': bad}])[1]['size'] == 9, bad
        # a new first definition goes first; something always stays visible
        order, _, hidden = listview_merge_state(cols[1:], [{'key': 'state', 'hidden': True}, {'key': 'progress', 'hidden': True}])
        assert order == ['size', 'state', 'progress'] and hidden == {'state', 'progress'}
        order, _, hidden = listview_merge_state(cols[1:], [{'key': k, 'hidden': True} for k in ('state', 'progress', 'size')])
        assert order == ['state', 'progress', 'size'] and hidden == {'progress', 'size'}


class FakeEvent:
    def __init__(self, x=0, y=0, keysym='', state=0, delta=0):
        self.x, self.y, self.keysym, self.state, self.delta = x, y, keysym, state, delta


class TestListViewWidget(unittest.TestCase):
    ''' Needs a display; drives the handlers directly (event_generate needs focus and a
        mapped window, which a withdrawn test root does not reliably give). '''

    @classmethod
    def setUpClass(cls):
        try:
            cls.win = Window(title='listview-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        cls.win.withdraw()
        cls.win._dpi_scale = 1.0        # geometry at 100% DPI (match CI, not a HiDPI display)

    @classmethod
    def tearDownClass(cls):
        cls.win.destroy()

    def make(self, n=1000, **kw):
        cols = [('name', 'Name', 0, 'w'), ('size', 'Size', 8, 'e'), ('progress', 'Progress', 10, 'w', 'progress')]
        lv = ListView(self.win, columns=cols, width=400, height=200, row_height=20, **kw)
        lv.pack()
        self.win.update_idletasks()
        lv.canvas.configure(width=400, height=200)
        self.win.update_idletasks()
        rows = [{'id': i, 'name': f'torrent {i}', 'size': f'{i} MB', '_sort': {'size': i}, 'progress': (i % 101) / 100}
                for i in range(n)]
        lv.set_rows(rows)
        self.addCleanup(lv.destroy)
        return lv

    def test_only_visible_rows_are_drawn(self):
        lv = self.make(1000)
        m = lv._metrics()
        assert lv.size() == 1000 and m['view_h'] > 0
        first, last = listview_visible_range(lv._scroll, m['view_h'], m['row_h'], 1000)
        drawn = last - first
        assert 5 <= drawn <= 12, (drawn, m)
        # each row draws 2 texts + a progress bar (2-3 polygons + 1 text); nowhere near 1000 rows' worth
        items = len(lv.canvas.find_all())
        assert items < drawn * 8 + 20, items
        lv.yview('moveto', 1.0)
        assert lv.nearest(m['top'] + m['view_h'] - 1) == 999
        assert lv.nearest(m['top'] + m['view_h'] - 1) == lv._order[-1]

    def test_click_shift_ctrl_selection_and_events(self):
        lv = self.make(50)
        seen = []
        lv.command = lambda sel: seen.append([r['id'] for r in sel])
        m = lv._metrics()
        y = lambda pos: m['top'] + pos * m['row_h'] + 2
        lv._on_click(FakeEvent(x=10, y=y(1)))
        assert lv.curselection() == (1,)
        lv._on_click(FakeEvent(x=10, y=y(4), state=0x1))          # shift
        assert lv.curselection() == (1, 2, 3, 4)
        lv._on_click(FakeEvent(x=10, y=y(2), state=0x4))          # ctrl toggles off
        assert lv.curselection() == (1, 3, 4)
        lv._on_click(FakeEvent(x=10, y=y(7)))                     # plain click replaces
        assert lv.curselection() == (7,) and lv.get() == [lv._items[7]]
        assert seen[-1] == [7] and seen[0] == [1]
        lv._on_click(FakeEvent(x=10, y=m['top'] + m['view_h'] + 500))  # below the rows
        assert lv.curselection() == ()
        # clicking a header sorts; sorting keeps the selection by row, not position
        lv.select(3)
        head = FakeEvent(x=m['pad'] + 1 + lv._layout[1][0] + lv._layout[1][1] // 2, y=m['pad'] + 2)
        lv._on_click(head)
        assert lv._sort_key is None                               # a press alone decides nothing
        lv._on_release(head)
        assert lv._sort_key == 'size' and lv.curselection() == (3,)
        lv._on_click(head)
        lv._on_release(head)
        assert lv._sort_reverse and lv._order[0] == 49 and lv.get('all')[0]['id'] == 49

    def test_keyboard_navigation_and_paging(self):
        lv = self.make(100)
        lv._on_key(FakeEvent(keysym='Down'))
        assert lv.curselection() == (0,)
        lv._on_key(FakeEvent(keysym='Down'))
        lv._on_key(FakeEvent(keysym='Down', state=0x1))
        assert lv.curselection() == (1, 2)
        lv._on_key(FakeEvent(keysym='End'))
        assert lv.curselection() == (99,) and lv._scroll > 0
        m = lv._metrics()
        first, last = listview_visible_range(lv._scroll, m['view_h'], m['row_h'], 100)
        assert first <= 99 < last
        lv._on_key(FakeEvent(keysym='Home'))
        assert lv.curselection() == (0,) and lv._scroll == 0
        lv._on_key(FakeEvent(keysym='Next'))
        page = max(1, m['view_h'] // m['row_h'])
        assert lv.curselection() == (page,)
        lv._on_key(FakeEvent(keysym='Prior'))
        assert lv.curselection() == (0,)
        lv._on_key(FakeEvent(keysym='space'))
        assert lv.curselection() == ()

    def test_insert_delete_move_and_selection_bookkeeping(self):
        lv = ListView(self.win, width=200, height=120, row_height=20)   # single column, no header
        lv.pack()
        self.win.update_idletasks()
        self.addCleanup(lv.destroy)
        assert not lv.show_header
        for s in 'abcde':
            lv.insert('end', s)
        assert lv.size() == 5 and lv.get(2) == 'c' and lv.get('all') == list('abcde')
        lv.select(3)                                     # 'd'
        lv.insert(0, 'z')
        assert lv.curselection() == (4,) and lv.get() == ['d']
        lv.delete(0)
        assert lv.curselection() == (3,)
        lv.delete(0, 1)                                  # 'a','b' gone
        assert lv.get('all') == list('cde') and lv.curselection() == (1,)
        lv.move_up(1)
        assert lv.get('all') == list('dce') and lv.curselection() == (0,)
        lv.move_down(0)
        assert lv.get('all') == list('cde') and lv.curselection() == (1,)
        lv.delete(1)
        assert lv.curselection() == () and lv.get() == []
        lv.delete('all')
        assert lv.size() == 0 and lv.get('all') == []
        lv._on_key(FakeEvent(keysym='Down'))            # empty list: no crash, nothing selected
        assert lv.curselection() == ()

    def test_set_rows_keeps_selection_by_id_and_item_updates_in_place(self):
        lv = self.make(10, multiple=False)
        lv.select(4)
        lv.set_rows([{'id': i, 'name': f'n{i}', 'size': '', 'progress': 0.5} for i in (9, 4, 2)])
        assert lv.curselection() == (1,) and lv.get()['id'] == 4
        lv.item(1, progress=1.0, name='done')
        assert lv._rows[1]['progress'] == 1.0 and lv.get()['name'] == 'done'
        lv.select(2)
        assert lv.curselection() == (2,)                # single-select replaces
        lv.select(1, toggle=True)
        assert lv.curselection() == (1,)                # toggle in single mode is a plain select
        lv.select('all')
        assert lv.curselection() == (1,)

    def test_see_scrolls_minimally_and_theme_switch_redraws(self):
        lv = self.make(200)
        # default row height follows the font's line spacing (a widget without row_height)
        auto = ListView(self.win, width=200, height=100)
        self.addCleanup(auto.destroy)
        am = auto._metrics()
        assert am['row_h'] == int(am['font'].metrics('linespace') * 1.7) and am['char_w'] > 0
        lv.see(0)
        assert lv._scroll == 0
        lv.see(150)
        m = lv._metrics()
        first, last = listview_visible_range(lv._scroll, m['view_h'], m['row_h'], 200)
        assert first <= 150 < last and last - 1 == 150     # bottom-aligned: minimal move
        s = lv._scroll
        lv.see(151)
        assert lv._scroll == s + m['row_h']
        lv.see(140)
        assert lv._scroll == 140 * m['row_h']            # top-aligned when above
        lv._on_wheel(FakeEvent(delta=-120))
        assert lv._scroll == 143 * m['row_h']
        mode = Theme.MODE
        try:
            mapping = Theme.apply('light' if mode == 'dark' else 'dark')
            Theme.apply_live(self.win, mapping)
            assert str(lv.canvas.cget('bg')).lower() == Theme.SURFACE.lower()
        finally:
            Theme.apply_live(self.win, Theme.apply(mode))
        with self.assertRaises(ValueError):
            lv.bind('<Button-3>', lambda e: None, add=False)
        lv.bind('<Button-3>', lambda e: None)


class TestListViewColumns(unittest.TestCase):
    ''' Resize, hide and reorder, driven through the same handlers the mouse reaches. '''

    @classmethod
    def setUpClass(cls):
        try:
            cls.win = Window(title='listview-columns-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        cls.win.withdraw()
        cls.win._dpi_scale = 1.0        # geometry at 100% DPI (match CI, not a HiDPI display)

    @classmethod
    def tearDownClass(cls):
        cls.win.destroy()

    def make(self, n=20, width=800, **kw):
        cols = [('name', 'Name', 0, 'w', {'required': True}), ('size', 'Size', 8, 'e'),
                ('progress', 'Progress', 10, 'w', 'progress'), ('state', 'Status', 9, 'w')]
        self.changes = []
        lv = ListView(self.win, columns=cols, width=width, height=200, row_height=20,
                      columns_command=self.changes.append, **kw)
        lv.pack()
        self.win.update_idletasks()
        lv.canvas.configure(width=width, height=200)
        self.win.update_idletasks()
        lv.set_rows([{'id': i, 'name': f'torrent {i}', 'size': f'{i} MB', '_sort': {'size': i},
                      'progress': i / 20, 'state': 'seeding'} for i in range(n)])
        self.addCleanup(lv.destroy)
        return lv

    @staticmethod
    def border_x(lv, i):
        return lv._x0 + (lv._layout[i][0] + lv._layout[i][1] + lv._layout[i + 1][0]) / 2

    @staticmethod
    def title_x(lv, i):
        return lv._x0 + lv._layout[i][0] + lv._layout[i][1] / 2

    @staticmethod
    def head_y(lv):
        return lv._metrics()['pad'] + 3

    def drag(self, lv, x0, x1, steps=4):
        y = self.head_y(lv)
        lv._on_click(FakeEvent(x=x0, y=y))
        for n in range(1, steps + 1):
            lv._on_drag(FakeEvent(x=x0 + (x1 - x0) * n / steps, y=y + 30 * n))   # the pointer may leave the header
        lv._on_release(FakeEvent(x=x1, y=y))

    def widths(self, lv):
        return {e['key']: e['width'] for e in lv.column_state()}

    @staticmethod
    def marks(lv):
        ''' The insertion lines on the canvas (there is one, while a title is being dragged) '''
        c = lv.canvas
        return [i for i in c.find_all() if c.type(i) == 'line' and c.itemcget(i, 'fill').lower() == Theme.PRIMARY.lower()]

    def keys(self, lv):
        return [c['key'] for c in lv._view]

    def test_dragging_a_border_between_fixed_columns_trades_their_width(self):
        lv = self.make()
        cw, before = lv._char_w, list(lv._layout)
        x = self.border_x(lv, 1)                                  # size | progress
        self.drag(lv, x, x + 2 * cw)
        assert self.widths(lv) == {'name': 0, 'size': 10, 'progress': 8, 'state': 9}
        assert lv._sort_key is None and len(self.changes) == 1    # one event, on release; no sort
        assert abs(self.border_x(lv, 1) - (x + 2 * cw)) <= 1      # the border is where the pointer left it
        assert lv._layout[0] == before[0] and lv._layout[3] == before[3]
        # far past the neighbour: it stops at the minimum, and the total is unchanged
        self.drag(lv, self.border_x(lv, 1), self.border_x(lv, 1) + 500)
        assert self.widths(lv) == {'name': 0, 'size': 14, 'progress': 4, 'state': 9}

    def test_dragging_the_stretch_columns_border_resizes_only_its_neighbour(self):
        lv = self.make()
        cw = lv._char_w
        x = self.border_x(lv, 0)                                  # name | size
        name_w = lv._layout[0][1]
        self.drag(lv, x, x - 3 * cw)
        assert self.widths(lv) == {'name': 0, 'size': 11, 'progress': 10, 'state': 9}
        assert abs(lv._layout[0][1] - (name_w - 3 * cw)) <= 1
        assert abs(self.border_x(lv, 0) - (x - 3 * cw)) <= 1
        # the stretch column cannot be squeezed under its minimum
        self.drag(lv, self.border_x(lv, 0), -5000)
        assert lv._layout[0][1] >= 3 * cw and lv._layout[-1][0] + lv._layout[-1][1] <= lv._metrics()['w']
        assert len(self.changes) == 2

    def test_a_still_click_sorts_and_a_border_click_does_nothing(self):
        lv = self.make()
        y = self.head_y(lv)
        x = self.title_x(lv, 1)
        lv._on_click(FakeEvent(x=x, y=y))
        lv._on_drag(FakeEvent(x=x + 2, y=y))                      # a shaky hand is still a click
        lv._on_release(FakeEvent(x=x + 2, y=y))
        assert lv._sort_key == 'size' and self.keys(lv) == ['name', 'size', 'progress', 'state']
        bx = self.border_x(lv, 1)
        lv._on_click(FakeEvent(x=bx, y=y))
        lv._on_release(FakeEvent(x=bx, y=y))
        assert lv._sort_key == 'size' and not lv._sort_reverse and self.changes == []
        # a release with no press before it (the tail of a double click) is ignored
        lv._on_release(FakeEvent(x=x, y=y))
        assert not lv._sort_reverse

    def test_dragging_a_title_reorders(self):
        lv = self.make()
        self.drag(lv, self.title_x(lv, 3), lv._x0 + 5)            # status to the front
        assert self.keys(lv) == ['state', 'name', 'size', 'progress']
        assert lv._sort_key is None and len(self.changes) == 1
        self.drag(lv, self.title_x(lv, 0), self.title_x(lv, 2) + lv._layout[2][1] / 2 - 2)   # just short of size's far edge
        assert self.keys(lv) == ['name', 'size', 'state', 'progress']
        self.drag(lv, self.title_x(lv, 1), 5000)                  # past the end
        assert self.keys(lv) == ['name', 'state', 'progress', 'size']
        # dropped on itself, or just beside itself: nothing moves and nothing is announced
        n = len(self.changes)
        self.drag(lv, self.title_x(lv, 1), lv._x0 + lv._layout[1][0] + 2)
        self.drag(lv, self.title_x(lv, 1), lv._x0 + lv._layout[1][0] + lv._layout[1][1] - 2)
        assert self.keys(lv) == ['name', 'state', 'progress', 'size'] and len(self.changes) == n
        assert self.marks(lv) == []                               # and the insertion line is gone
        self.drag(lv, self.title_x(lv, 1), lv._x0 + lv._layout[1][0] + 2)
        assert self.marks(lv) == []
        assert lv._sort_key is None and lv._press is None and lv._drop is None

    def test_the_insertion_mark_follows_the_drag(self):
        lv = self.make()
        y = self.head_y(lv)
        lv._on_click(FakeEvent(x=self.title_x(lv, 3), y=y))
        assert lv._drop is None
        assert self.marks(lv) == []
        lv._on_drag(FakeEvent(x=lv._x0 + 5, y=y))
        assert lv._drop == 0 and lv._press['moved'] and len(self.marks(lv)) == 1
        assert lv.canvas.coords(self.marks(lv)[0])[0] < lv._x0 + lv._layout[0][0] + 1
        lv._on_drag(FakeEvent(x=self.title_x(lv, 1) + 4, y=y))
        assert lv._drop == 2
        lv._on_motion(FakeEvent(x=self.title_x(lv, 1), y=y))      # hovering mid-drag leaves the cursor alone
        assert str(lv.canvas.cget('cursor')) == 'fleur'
        mark = lv.canvas.coords(self.marks(lv)[0])[0]
        assert lv._x0 + lv._layout[1][0] + lv._layout[1][1] <= mark <= lv._x0 + lv._layout[2][0]
        lv._on_release(FakeEvent(x=self.title_x(lv, 1) + 4, y=y))
        assert self.keys(lv) == ['name', 'size', 'state', 'progress'] and self.marks(lv) == []

    def test_hiding_and_showing(self):
        lv = self.make()
        lv.set_column_hidden('size')
        assert self.keys(lv) == ['name', 'progress', 'state'] and len(lv._layout) == 3
        lv.set_column_hidden('name')                              # required: refused
        lv.set_column_hidden('nope')
        assert self.keys(lv) == ['name', 'progress', 'state'] and len(self.changes) == 1
        lv.set_column_hidden('size', False)
        assert self.keys(lv) == ['name', 'size', 'progress', 'state']
        # rows draw the visible columns only, in their order
        lv.move_column('state', 0)
        lv.set_column_hidden('progress')
        texts = [lv.canvas.itemcget(i, 'text') for i in lv.canvas.find_all() if lv.canvas.type(i) == 'text']
        assert texts[:3] == ['Status', 'Name', 'Size'] and 'Progress' not in texts
        assert texts[3:6] == ['seeding', 'torrent 0', '0 MB']

    def test_without_the_stretch_column_the_last_visible_one_takes_the_spare_width(self):
        cols = [('name', 'Name', 0, 'w'), ('size', 'Size', 8, 'e'), ('state', 'Status', 9, 'w')]
        lv = ListView(self.win, columns=cols, width=800, height=200, row_height=20)
        lv.pack()
        self.win.update_idletasks()
        lv.canvas.configure(width=800, height=200)
        self.win.update_idletasks()
        lv.set_rows([])
        self.addCleanup(lv.destroy)
        full = lv._layout[-1][0] + lv._layout[-1][1]
        lv.set_column_hidden('name')
        assert [c['key'] for c in lv._view] == ['size', 'state']
        assert lv._layout[-1][0] + lv._layout[-1][1] == full and lv._layout[0][1] == 8 * lv._char_w
        assert lv.column_state()[2] == {'key': 'state', 'width': 9, 'hidden': False}   # its own width is kept
        lv.set_column_hidden('size')
        lv.set_column_hidden('state')                             # the last one stays
        assert [c['key'] for c in lv._view] == ['state']
        lv.set_column_hidden('name', False)
        assert lv._layout[1][1] == 9 * lv._char_w

    def test_header_menu_lists_every_column_and_reset(self):
        lv = self.make()
        lv.set_column_hidden('size')
        entries = lv.header_menu_entries()
        assert [(label, checked, enabled) for label, checked, enabled, _ in entries] == [
            ('Name', True, False), ('Size', False, True), ('Progress', True, True), ('Status', True, True),
            (None, False, False), ('Reset columns', False, True)]
        entries[1][3]()                                           # show Size
        entries[2][3]()                                           # hide Progress
        assert self.keys(lv) == ['name', 'size', 'state']
        self.drag(lv, self.border_x(lv, 0), self.border_x(lv, 0) - 2 * lv._char_w)
        lv.move_column('state', 0)
        assert lv.column_state() != ListView(self.win, columns=lv.columns).column_state()
        lv.header_menu_entries()[-1][3]()                         # reset
        assert self.keys(lv) == ['name', 'size', 'progress', 'state']
        assert self.widths(lv) == {'name': 0, 'size': 8, 'progress': 10, 'state': 9} and not lv._user_sized
        assert self.changes[-1] == lv.column_state()
        # a right click off the header is left for the application's row menu
        assert lv._on_header_menu(FakeEvent(x=20, y=lv._metrics()['top'] + 5)) is None
        lv.column_menu = False
        assert lv._on_header_menu(FakeEvent(x=20, y=self.head_y(lv))) is None

    def test_state_round_trips_into_a_fresh_widget(self):
        lv = self.make()
        self.drag(lv, self.border_x(lv, 1), self.border_x(lv, 1) + 2 * lv._char_w)
        lv.move_column('state', 0)
        lv.set_column_hidden('progress')
        state = lv.column_state()
        assert state == [{'key': 'state', 'width': 9, 'hidden': False}, {'key': 'name', 'width': 0, 'hidden': False},
                         {'key': 'size', 'width': 10, 'hidden': False}, {'key': 'progress', 'width': 8, 'hidden': True}]
        import json
        other = self.make()                                       # (starts a fresh self.changes)
        other.set_column_state(json.loads(json.dumps(state)))
        assert other.column_state() == state and other._layout == lv._layout
        assert self.changes == []                                 # restoring is not a user change
        other.set_column_state('garbage')
        assert self.keys(other) == ['name', 'size', 'progress', 'state']

    def test_fit_to_content_on_a_border_double_click(self):
        lv = self.make()
        lv.insert('end', {'id': 99, 'name': 'x', 'size': '1234567.89 GiB of data', 'progress': 0, 'state': ''})
        m = lv._metrics()
        want = -(-(m['font'].measure('1234567.89 GiB of data') + 12) // m['char_w'])
        lv._on_double(FakeEvent(x=self.border_x(lv, 1), y=self.head_y(lv)))
        assert self.widths(lv)['size'] == want > 8 and len(self.changes) == 1
        assert lv.curselection() == ()                            # it was not a row activation
        lv.fit_column('state')                                    # 'Status ▲' is wider than 'seeding'
        assert self.widths(lv)['state'] == max(4, -(-(m['font'].measure('Status ▲') + 12) // m['char_w']))
        n = len(self.changes)
        lv.fit_column('name')                                     # the stretch column has no width to fit
        lv.fit_column('progress')                                 # nor has a bar any content
        lv._on_double(FakeEvent(x=self.border_x(lv, 0), y=self.head_y(lv)))
        assert len(self.changes) == n and self.widths(lv)['name'] == 0 and self.widths(lv)['progress'] == 10

    def test_cursor_tells_the_gestures_apart(self):
        lv = self.make()
        y = self.head_y(lv)
        lv._on_motion(FakeEvent(x=self.border_x(lv, 1), y=y))
        assert str(lv.canvas.cget('cursor')) == 'sb_h_double_arrow'
        lv._on_motion(FakeEvent(x=self.title_x(lv, 1), y=y))
        assert str(lv.canvas.cget('cursor')) == 'hand2'
        lv._on_motion(FakeEvent(x=self.border_x(lv, 1), y=lv._metrics()['top'] + 5))   # same x, on a row
        assert str(lv.canvas.cget('cursor')) == 'hand2'

    def test_user_sized_columns_hold_their_width_when_the_widget_narrows(self):
        lv = self.make()
        cw = lv._char_w
        self.drag(lv, self.border_x(lv, 0), self.border_x(lv, 0) - 5 * cw)        # size: 8 -> 13 characters
        assert self.widths(lv)['size'] == 13
        state = lv.column_state()

        # Gaps and padding are fixed pixels while column widths are in characters, so the exact
        # fit threshold drifts with whatever font the platform substitutes. Test the two
        # behaviours at two comfortable margins rather than at one boundary width where both
        # would have to hold at once (that window is only ~2 characters wide and font-fragile).

        # Narrow: the DEFAULT arrangement shrinks the fixed columns to keep the name readable.
        narrow = self.make(width=38 * cw)
        assert narrow._layout[1][1] < 8 * cw and narrow._layout[0][1] >= 10 * cw, narrow._layout

        # Wide enough to hold them: a hand-sized arrangement keeps its exact widths, and the
        # stretch (name) column yields the difference versus the default at the same width.
        default_wide, kept = self.make(width=50 * cw), self.make(width=50 * cw)
        kept.set_column_state(state)
        assert abs(kept._metrics()['w'] - 50 * cw) <= 4, kept._metrics()['w']
        assert [w for _, w in kept._layout[1:]] == [13 * cw, 10 * cw, 9 * cw], (kept._layout, cw)
        assert 3 * cw <= kept._layout[0][1] < default_wide._layout[0][1]

        # And when it cannot fit at all, the columns shrink instead of running off the edge.
        tight = self.make(width=20 * cw)
        tight.set_column_state(state)
        assert tight._layout[-1][0] + tight._layout[-1][1] <= tight._metrics()['w'], tight._layout


# --- FileDialog ---

import os, tempfile, time


class TestFileDialogHelpers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        os.makedirs(os.path.join(self.tmp, 'sub', 'deeper'))
        os.makedirs(os.path.join(self.tmp, '.git'))
        for name, n in (('a.torrent', 3000), ('B.TORRENT', 5), ('notes.txt', 2_500_000), ('.hidden', 1)):
            with open(os.path.join(self.tmp, name), 'wb') as f:
                f.write(b'x' * n)

    def test_matching_is_case_insensitive_and_star_is_everything(self):
        assert filedialog_matches('x.torrent', ('*.torrent',)) and filedialog_matches('X.TORRENT', ['*.torrent'])
        assert not filedialog_matches('x.torrent.bak', ('*.torrent',))
        assert filedialog_matches('anything', ('*',)) and filedialog_matches('anything', None)
        assert filedialog_matches('a.txt', ('*.torrent', '*.txt')) and not filedialog_matches('a.md', ('*.torrent', '*.txt'))

    def test_sizes(self):
        assert [filedialog_fmt_size(n) for n in (None, 0, 999, 1024, 1536, 100 * 1024, 2_500_000, 3 << 40)] == \
            ['', '0 B', '999 B', '1.0 KiB', '1.5 KiB', '100 KiB', '2.4 MiB', '3.0 TiB']

    def test_entries_list_folders_first_filtered_and_sorted(self):
        rows = filedialog_entries(self.tmp, ('*.torrent',))
        assert [r['name'] for r in rows] == ['sub', 'a.torrent', 'B.TORRENT']
        assert rows[0]['is_dir'] and rows[0]['size'] is None and rows[0]['size_text'] == ''
        assert rows[1]['size'] == 3000 and rows[1]['size_text'] == '2.9 KiB' and rows[1]['path'] == os.path.join(self.tmp, 'a.torrent')
        assert rows[0]['text'].endswith('sub') and rows[0]['text'] != 'sub' and rows[1]['text'].endswith('a.torrent')
        assert rows[1]['modified'] == time.strftime('%Y-%m-%d %H:%M', time.localtime(rows[1]['mtime']))
        # the name sort keeps folders first; size and date sort by the raw values
        assert rows[0]['_sort']['text'] < rows[1]['_sort']['text'] < rows[2]['_sort']['text']
        assert rows[1]['_sort']['size_text'] == 3000 and rows[0]['_sort']['size_text'] is None
        assert [r['name'] for r in filedialog_entries(self.tmp)] == ['sub', 'a.torrent', 'B.TORRENT', 'notes.txt']
        assert [r['name'] for r in filedialog_entries(self.tmp, show_hidden=True)] == \
            ['.git', 'sub', '.hidden', 'a.torrent', 'B.TORRENT', 'notes.txt']
        assert [r['name'] for r in filedialog_entries(self.tmp, ('*.txt',), dirs_only=True)] == ['sub']
        assert filedialog_entries(os.path.join(self.tmp, 'nope')) == []
        assert filedialog_entries(os.path.join(self.tmp, 'notes.txt')) == []

    def test_typed_paths_resolve_against_the_current_folder(self):
        cwd = os.path.join(self.tmp, 'sub')
        assert filedialog_resolve('', cwd) == cwd and filedialog_resolve('   ', cwd) == cwd
        assert filedialog_resolve('deeper', cwd) == os.path.join(cwd, 'deeper')
        assert filedialog_resolve('../a.torrent', cwd) == os.path.join(self.tmp, 'a.torrent')
        assert filedialog_resolve('~', cwd) == os.path.expanduser('~')
        assert filedialog_resolve(self.tmp + '/', cwd) == self.tmp
        assert filedialog_resolve('/x/./y/../z', cwd) == os.path.normpath('/x/z')

    def test_parent_stops_at_the_root(self):
        assert filedialog_parent(os.path.join(self.tmp, 'sub')) == self.tmp
        assert filedialog_parent(os.path.join(self.tmp, 'sub') + os.sep) == self.tmp
        root = os.path.abspath(os.sep)
        assert filedialog_parent(root) == root and filedialog_parent('name') == 'name'
        if sys.platform.startswith('win'):
            assert filedialog_parent('C:\\') == 'C:\\' and filedialog_parent('C:\\x') == 'C:\\'

    def test_places_are_home_its_folders_and_the_volumes(self):
        home = os.path.join(self.tmp, 'home')
        os.makedirs(os.path.join(home, 'Downloads'))
        vol = os.path.join(self.tmp, 'Common')
        os.makedirs(vol)
        places = filedialog_places(home=home, volumes=[vol, os.path.join(self.tmp, 'gone')])
        assert places[:2] == [('Home', home), ('Downloads', os.path.join(home, 'Downloads'))]
        assert ('Common', vol) in places and not any('gone' in p for _, p in places)
        if not sys.platform.startswith('win'):
            assert ('/', '/') in places


class TestEntryBorder(unittest.TestCase):
    def test_border_follows_the_width_and_the_theme(self):
        try:
            win = Window(title='entry-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        self.addCleanup(win.destroy)
        win.withdraw()
        entry = Entry(win, width=120, height=30)
        entry.pack(fill='x')
        win.update_idletasks()
        border = lambda: entry.canvas.find_withtag('border')
        assert len(border()) == 1
        x1, _, x2, _ = entry.canvas.bbox(border()[0])
        assert 110 <= x2 - x1 <= 124, (x1, x2)
        # a withdrawn window never lays out, so the resize is fed by hand: the border is
        # redrawn once, at the new size (the <Configure> binding does exactly this)
        assert '<Configure>' in entry.canvas.bind()
        entry._draw_border(600, 30)
        assert len(border()) == 1
        x1, _, x2, _ = entry.canvas.bbox(border()[0])
        assert x2 - x1 >= 590, (x1, x2)
        mode = Theme.MODE
        try:
            Theme.apply_live(win, Theme.apply('light' if mode == 'dark' else 'dark'))
            assert entry.canvas.itemcget(border()[0], 'fill').lower() == Theme.SURFACE.lower()
        finally:
            Theme.apply_live(win, Theme.apply(mode))
        assert len(border()) == 1


class TestFileDialogWidget(unittest.TestCase):
    """ Built for real on a withdrawn root, never shown: the handlers are driven directly. """

    @classmethod
    def setUpClass(cls):
        try:
            cls.win = Window(title='filedialog-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        cls.win.withdraw()
        cls.win._dpi_scale = 1.0        # geometry at 100% DPI (match CI, not a HiDPI display)

    @classmethod
    def tearDownClass(cls):
        cls.win.destroy()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        os.makedirs(os.path.join(self.tmp, 'sub', 'deeper'))
        for name in ('a.torrent', 'b.torrent', 'notes.txt', '.hidden', 'sub/c.torrent'):
            with open(os.path.join(self.tmp, name), 'wb') as f:
                f.write(b'x')
        FileDialog.last_dir = None

    def make(self, mode='open', **kw):
        kw.setdefault('initialdir', self.tmp)
        kw.setdefault('filetypes', [('Torrents', '*.torrent'), ('All files', '*')])
        d = FileDialog(self.win, mode=mode, **kw)
        self.win.update_idletasks()
        self.addCleanup(lambda: d.winfo_exists() and d.destroy())
        return d

    @staticmethod
    def names(d):
        return [r['name'] for r in d.list.get('all')]

    def pick(self, d, index):
        """ A single click on row `index`: the ListView selects and calls the command """
        d.list.select(index)
        d._picked(d.list.get())

    def test_open_lists_filters_and_chooses_a_file(self):
        d = self.make()
        assert d.title() == 'Open' and d.cwd == self.tmp and d.path.get() == self.tmp
        assert self.names(d) == ['sub', 'a.torrent', 'b.torrent'] and d.result is None
        assert [c['key'] for c in d.list._view] == ['text', 'size_text', 'modified']
        assert d.chosen() is None
        d.accept()                                                # nothing named: still open
        assert d.winfo_exists() and d.result is None
        self.pick(d, 1)
        assert d.name.get() == 'a.torrent' and d.chosen() == os.path.join(self.tmp, 'a.torrent')
        d.accept()
        assert d.result == os.path.join(self.tmp, 'a.torrent') and not d.winfo_exists()
        assert FileDialog.last_dir == self.tmp
        # the next dialog of the process opens where the last one accepted
        again = FileDialog(self.win, mode='open')
        self.addCleanup(again.destroy)
        assert again.cwd == self.tmp

    def test_folders_enter_on_activation_and_the_bar_navigates(self):
        d = self.make()
        self.pick(d, 1)
        self.pick(d, 0)
        assert d.name.get() == 'a.torrent'                        # a folder click leaves the name alone ...
        d.open_selected()                                         # ... but entering one forgets it
        assert d.cwd == os.path.join(self.tmp, 'sub') and self.names(d) == ['deeper', 'c.torrent']
        assert d.name.get() == '' and d.path.get() == d.cwd
        d.up()
        assert d.cwd == self.tmp
        d.back()
        assert d.cwd == os.path.join(self.tmp, 'sub')
        d.back()
        assert d.cwd == self.tmp
        d.back()                                                  # history exhausted: stays
        assert d.cwd == self.tmp
        root = os.path.abspath(os.sep)
        d.go(root)
        d.up()
        assert d.cwd == root
        d.path.entry.delete(0, 'end')
        d.path.entry.insert(0, os.path.join(self.tmp, 'sub', 'deeper'))
        d.go_typed()
        assert d.cwd == os.path.join(self.tmp, 'sub', 'deeper') and self.names(d) == []
        d.path.entry.delete(0, 'end')
        d.path.entry.insert(0, '../..')
        d.go_typed()
        assert d.cwd == self.tmp
        d.path.entry.delete(0, 'end')
        d.path.entry.insert(0, os.path.join(self.tmp, 'nowhere'))
        d.go_typed()
        assert d.cwd == self.tmp and d.path.get().endswith('nowhere')   # left for correction
        d.path.entry.delete(0, 'end')
        d.path.entry.insert(0, 'sub/c.torrent')
        d.go_typed()                                              # a file in the bar is the choice
        assert d.result == os.path.join(self.tmp, 'sub', 'c.torrent')

    def test_typed_names_folders_and_the_type_filter(self):
        d = self.make()
        d.name.entry.insert(0, 'sub')
        d.accept()                                                # a folder name enters it
        assert d.cwd == os.path.join(self.tmp, 'sub') and d.name.get() == '' and d.winfo_exists()
        d.name.entry.insert(0, '../notes.txt')
        d.accept()                                                # a file outside the filter still opens by name
        assert d.result == os.path.join(self.tmp, 'notes.txt')
        d = self.make()
        d.name.entry.insert(0, 'missing.torrent')
        d.accept()
        assert d.winfo_exists() and d.result is None
        assert d.types.text == 'Torrents'
        d.next_type()
        assert d.types.text == 'All files' and self.names(d) == ['sub', 'a.torrent', 'b.torrent', 'notes.txt']
        d.hidden.toggle()
        assert '.hidden' in self.names(d)
        d.hidden.toggle()
        assert '.hidden' not in self.names(d)
        d.next_type()
        assert d.types.text == 'Torrents' and 'notes.txt' not in self.names(d)
        d.hidden.toggle()
        assert '.hidden' not in self.names(d)                     # hidden, but not a torrent either
        d.cancel()
        assert d.result is None and not d.winfo_exists()

    def test_multiple_selection(self):
        d = self.make(multiple=True)
        assert d.list.multiple
        d.list.select(1)
        d.list.select(2, extend=True)
        d._picked(d.list.get())
        assert d.name.get() == ''                                 # two files: the list is the choice
        assert d.chosen() == [os.path.join(self.tmp, n) for n in ('a.torrent', 'b.torrent')]
        d.list.select(0, toggle=True)                             # a folder in the selection is ignored
        assert d.chosen() == [os.path.join(self.tmp, n) for n in ('a.torrent', 'b.torrent')]
        d.accept()
        assert d.result == [os.path.join(self.tmp, n) for n in ('a.torrent', 'b.torrent')]
        d = self.make(multiple=True)
        d.name.entry.insert(0, 'notes.txt')
        d.accept()
        assert d.result == [os.path.join(self.tmp, 'notes.txt')]  # typed: still a list
        assert not self.make('save', multiple=True).multiple      # only open can take several

    def test_save_names_a_new_file_and_asks_before_replacing(self):
        d = self.make('save', initialfile='new.torrent')
        assert d.title() == 'Save as' and d.name.get() == 'new.torrent'
        assert d.chosen() == os.path.join(self.tmp, 'new.torrent')
        self.pick(d, 0)
        d.open_selected()
        assert d.cwd == os.path.join(self.tmp, 'sub') and d.name.get() == 'new.torrent'   # the name survives a folder change
        d.up()
        asked = []
        d.confirm = lambda title, msg: asked.append(msg) or False
        self.pick(d, 1)
        assert d.name.get() == 'a.torrent'
        d.accept()
        assert asked == ['a.torrent already exists. Replace it?'] and d.winfo_exists() and d.result is None
        d.confirm = lambda title, msg: True
        d.accept()
        assert d.result == os.path.join(self.tmp, 'a.torrent')
        d = self.make('save')
        d.name.entry.insert(0, 'sub')
        assert d.chosen() is None                                 # cannot save over a folder
        d.accept()
        assert d.cwd == os.path.join(self.tmp, 'sub') and d.result is None

    def test_directory_mode(self):
        d = self.make('directory')
        assert d.title() == 'Choose a folder' and self.names(d) == ['sub'] and d.name.get() == self.tmp
        assert not d.types.winfo_ismapped() and d.chosen() == self.tmp
        self.pick(d, 0)
        assert d.name.get() == os.path.join(self.tmp, 'sub') and d.chosen() == d.name.get()
        d.list.select(None)
        d._picked(d.list.get())
        assert d.name.get() == self.tmp
        d.open_selected()                                         # nothing selected: nothing happens
        assert d.cwd == self.tmp
        self.pick(d, 0)
        d.open_selected()
        assert d.cwd == os.path.join(self.tmp, 'sub') and d.name.get() == d.cwd
        d.name.entry.delete(0, 'end')
        d.name.entry.insert(0, 'deeper')
        d.accept()
        assert d.result == os.path.join(self.tmp, 'sub', 'deeper')
        d = self.make('directory')
        d.name.entry.delete(0, 'end')
        d.name.entry.insert(0, 'a.torrent')
        d.accept()
        assert d.winfo_exists() and d.result is None

    def test_places_and_a_missing_start_folder(self):
        d = self.make()
        rows = d.places.get('all')
        assert rows[0]['text'] == 'Home' and rows[0]['path'] == os.path.expanduser('~')
        d._place_chosen(rows[0])
        assert d.cwd == os.path.expanduser('~') and d.places.curselection() == ()
        d._place_chosen(None)
        assert d.cwd == os.path.expanduser('~')
        d = self.make(initialdir=os.path.join(self.tmp, 'nope'))
        assert d.cwd == os.path.expanduser('~')
        with self.assertRaises(ValueError):
            self.make('pick')
        assert self.make(filetypes=None).types.text == 'All files'
        assert self.make(filetypes=[('Media', ('*.mkv', '*.mp4'))]).filetypes == [('Media', ('*.mkv', '*.mp4'))]


# ---------------------------------------------------------------- spec: structure as data
class TestSpecHeadless(unittest.TestCase):
    def setUp(self):
        from src import tkinter_mods as tm
        self.tm = tm

    def test_units(self):
        to_px = self.tm.to_px
        assert to_px(12, 9, 20) == 12 and to_px('22ch', 9, 20) == 198 and to_px('1.7lh', 9, 20) == 34
        assert to_px('40px', 9, 20) == 40 and to_px(None, 9, 20) is None
        with self.assertRaises(self.tm.SpecError):
            to_px('wide', 9, 20)

    def test_style_precedence_kind_then_name_then_inline(self):
        tm = self.tm
        st = tm.Style({'button': {'height': '1.7lh', 'width': '8ch'}, 'go': {'width': '12ch'}})
        node = tm.spec.Button('Go', name='go', style={'height': 40})
        assert st.resolve(node) == {'height': 40, 'width': '12ch'}
        assert st.resolve(tm.spec.Button('x')) == {'height': '1.7lh', 'width': '8ch'}

    def test_validate_finds_the_usual_mistakes(self):
        tm = self.tm

        class Ctl:
            def go(self):
                pass
        tree = tm.spec.Column(
            tm.spec.Row(tm.spec.Button('Go', on='go', name='a'), tm.spec.Button('No', on='nope', name='a')),
            tm.spec.Split(tm.spec.Label('alone')),
            tm.spec.Widget(widget='unknown-kind'),
            tm.spec.Label('sized', style={'width': 'wide'}),
        )
        problems = validate = tm.validate(tree, Ctl())
        text = '\n'.join(problems)
        assert 'duplicate name' in text and "'nope'" in text and 'two or more panes' in text
        assert 'unregistered widget kind' in text and 'bad size' in text, text
        assert tm.validate(tm.spec.Column(tm.spec.Button('Go', on='go')), Ctl()) == []

    def test_tree_walk_and_repr(self):
        tm = self.tm
        t = tm.spec.Column(tm.spec.Row(tm.spec.Button('a'), tm.spec.Entry(name='f')), tm.spec.Label('s', name='status'))
        kinds = [n.kind for n in t.walk()]
        assert kinds == ['column', 'row', 'button', 'entry', 'label'] and 'Row(' in repr(t)


    def test_button_infers_handler_and_name(self):
        B = self.tm.spec.Button
        b = B('Add')
        assert b.on == 'add' and b.name == 'add' and b.inferred
        assert B('Start all').on == 'start_all' and B('Browse…').on is None and B('Browse…').name is None
        assert B('◀', on='back').name == 'back' and not B('◀', on='back').inferred
        assert B('Apply', on='ok').name == 'ok' and B('Apply', on='ok', name='go').name == 'go'
        fn = lambda: None                                 # noqa: E731
        assert B('Go', on=fn).on is fn and B('Go', on=fn).name is None

        class Ctl:
            pass
        text = '\n'.join(self.tm.validate(self.tm.spec.Column(B('Add')), Ctl()))
        assert "handler 'add'" in text and 'inferred from the text' in text, text

    def test_ui_builder_makes_the_same_tree(self):
        tm, spec, ui = self.tm, self.tm.spec, self.tm.ui
        nested = spec.Column(
            spec.Row(spec.Entry('find', name='filter', side='right', on_key='typed'), spec.Button('Add'), spec.Button('Pause'),
                     name='bar', fill='x', pad=(8, 6)),
            spec.Label('', name='status', side='bottom', fill='x'),
            spec.Split(
                spec.ListView(name='side', header=False, on_select='chosen'),
                spec.Tabs(spec.Tab('files', 'Files', spec.ListView(name='files', columns='COLS')),
                          spec.Tab('map', 'Map', spec.Widget(widget='box', name='box', kwargs={'n': 1})),
                          name='tabs', on_change='tab'),
                name='main', pad=(8, 0),
            ),
        )
        with ui.column() as built:
            with ui.row('bar', fill='x', pad=(8, 6)):
                ui.entry('filter', 'find', side='right', on_key='typed')
                for text in ('Add', 'Pause'):
                    ui.button(text)
            ui.label('', name='status', side='bottom', fill='x')
            with ui.split('main', pad=(8, 0)):
                ui.listview('side', header=False, on_select='chosen')
                with ui.tabs('tabs', on_change='tab'):
                    with ui.tab('files', 'Files'):
                        ui.listview('files', 'COLS')
                    with ui.tab('map', 'Map'):
                        ui.widget('box', 'box', kwargs={'n': 1})
        assert not tm._OPEN

        def flat(t):
            return [(n.kind, n.name, n.side, n.fill, n.expand, n.pad, getattr(n, 'text', None), getattr(n, 'on', None),
                     getattr(n, 'key', None), getattr(n, 'kwargs', None)) for n in t.walk()]
        assert flat(built) == flat(nested), (flat(built), flat(nested))
        assert built.children[0].child_side == 'left' and built.children[2].children[1].children[0].children[0].name == 'files'
        # a helper that opens a container composes; ui.add places a ready node; outside any `with` nothing is appended
        from contextlib import contextmanager

        @contextmanager
        def field(label):
            with ui.row(fill='x'):
                ui.label(label, chars=12)
                yield
        with ui.column() as form:
            with field('Port'):
                ui.entry('port')
            ui.add(spec.Checkbox('Paused', name='paused'))
        assert [n.kind for n in form.walk()] == ['column', 'row', 'label', 'entry', 'checkbox']
        loose = ui.button('Loose')
        assert loose.kind == 'button' and loose not in form.children
        # a Tab needs its one child
        with ui.tabs() as tabs:
            ui.tab('empty', 'Empty')
        assert any('exactly one child' in p for p in tm.validate(tabs))


class TestSpecBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src import tkinter_mods as tm
        cls.tm = tm
        try:
            cls.win = tm.Window(title='spec-test')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        cls.win.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.win.destroy()

    def test_builds_binds_and_sizes(self):
        tm = self.tm
        calls = []

        class Ctl:
            COLS = [('name', 'Name', 0, 'w'), ('n', 'N', 5, 'e')]

            def add(self):
                calls.append('add')

            def chosen(self, sel):
                calls.append(('chosen', sel))

            def typed(self):
                calls.append('typed')

        @tm.register('box')
        def _box(node, master, px, bind):
            f = tk.Frame(master, bg='red', width=px.get('width') or 10, height=px.get('height') or 10)
            return f

        tree = tm.spec.Column(
            tm.spec.Row(tm.spec.Button('Add', on='add', name='add'), tm.spec.Entry(name='filter', placeholder='find', side='right', on_key='typed'),
                   name='bar'),
            tm.spec.Split(tm.spec.ListView(name='side', columns='COLS', header=False, on_select='chosen', style={'min': '10ch'}),
                     tm.spec.Column(tm.spec.Widget(widget='box', name='box', style={'width': '5ch', 'height': 30}), tm.spec.Label('Hi', name='hi', muted=True))),
            tm.spec.Label('', name='status', side='bottom'),
        )
        style = tm.Style({'button': {'height': '1.7lh'}, 'filter': {'width': '22ch'}})
        host = tk.Frame(self.win)
        refs = tm.build(tree, host, Ctl(), style)
        cw, lh = tm.font_metrics(host)
        assert isinstance(refs.add, tm.Button) and isinstance(refs.filter, tm.Entry) and isinstance(refs.side, tm.ListView)
        assert refs['status'] is refs.status and refs.root.master is host
        assert refs.root.winfo_manager() == 'pack' and refs.root.pack_info()['fill'] == 'both'   # the root shows
        assert int(refs.filter.canvas.cget('width')) == 22 * cw, (refs.filter.canvas.cget('width'), cw)
        assert int(refs.box.cget('width')) == 5 * cw and int(refs.box.cget('height')) == 30
        # a button's font size from the style (a glyph that needs to be bigger than the text)
        big = tm.build(tm.spec.Column(tm.spec.Button('\u23f5', on='add', style={'font_size': 15})), host, Ctl())
        assert big.add.font_size == 15 and big.add.itemcget(big.add.text_id, 'font').split()[-2] == '15'
        refs.add.command()
        refs.side.set_rows([{'name': 'x', 'n': '1', 'id': 1}])
        refs.side.select(0)
        assert 'add' in calls and any(c[0] == 'chosen' for c in calls if isinstance(c, tuple)), calls
        with self.assertRaises(tm.SpecError):
            tm.build(tm.spec.Column(tm.spec.Button('x', on='missing')), host, Ctl())


class TestWidgets050(unittest.TestCase):
    ''' 0.5.0: Dropdown, ProgressBar, Button.set_enabled, Entry.set/get, separator and spacer
        kinds in the spec. Needs a display. '''

    @classmethod
    def setUpClass(cls):
        from src import tkinter_mods as tm
        cls.tm = tm
        try:
            cls.win = tm.Window(title='widgets-050')
        except Exception as e:                            # noqa: BLE001
            raise unittest.SkipTest(f'no Tk display: {e}')
        cls.win.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.win.destroy()

    def test_dropdown_keeps_or_replaces_its_value(self):
        tm, seen = self.tm, []
        d = tm.Dropdown(self.win, items=['a', 'b'], command=seen.append)
        assert d.get() == 'a'
        d.set('b', notify=True)
        assert d.get() == 'b' and seen == ['b']
        d.set_items(['b', 'c'])                           # the value survives: no callback
        assert d.get() == 'b' and seen == ['b']
        d.set_items(['x', 'y'])                           # it does not: the first is taken, and reported
        assert d.get() == 'x' and seen == ['b', 'x']
        d.set_items([])
        assert d.get() is None and seen == ['b', 'x', None]
        d.set('nonsense')
        assert d.get() is None

    def test_progress_bar_clamps(self):
        p = self.tm.ProgressBar(self.win, width=200, height=20)
        p.set(0.5, '1 of 2'); assert p.get() == 0.5 and p.text == '1 of 2'
        p.set(7); assert p.get() == 1.0
        p.set(-1); assert p.get() == 0.0 and p.text == '1 of 2', 'the text stays unless given'

    def test_disabled_button_ignores_clicks(self):
        calls = []
        b = self.tm.Button(self.win, text='Go', command=lambda: calls.append(1))
        b._on_release(None); assert calls == [1]
        b.set_enabled(False)
        b._on_release(None); assert calls == [1]
        b.set_enabled(True)
        b._on_release(None); assert calls == [1, 1]

    def test_entry_set_and_get_round_the_placeholder(self):
        e = self.tm.Entry(self.win, placeholder='type here')
        assert e.get() == '' and e.entry.get() == 'type here'
        e.set('/tmp/x.iso'); assert e.get() == '/tmp/x.iso'
        e.set(''); assert e.get() == '' and e.entry.get() == 'type here'

    def test_spec_builds_the_new_kinds(self):
        tm = self.tm
        class C:
            picked = []
            choices = ['one', 'two']
            def chosen(self, v): self.picked.append(v)
        with tm.ui.column() as tree:
            tm.ui.dropdown('drive', items='choices', on='chosen', style={'height': 30})
            tm.ui.progress('bar', style={'height': 16})
            tm.ui.separator()
            tm.ui.spacer(height=12)
        assert tm.validate(tree, C()) == []
        refs = tm.build(tree, self.win, controller=C())
        assert isinstance(refs.drive, tm.Dropdown) and refs.drive.items == ['one', 'two']
        assert isinstance(refs.bar, tm.ProgressBar)
        refs.drive.set('two', notify=True)
        assert C.picked == ['two']
        refs.root.destroy()
