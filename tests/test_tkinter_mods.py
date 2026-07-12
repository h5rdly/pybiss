import sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.tkinter_mods import (
    detect_system_theme, _even, scrollbar_thumb_bounds, scrollbar_drag_start,
    get_window_dpi_scale, DpiTracker, Window,
)


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
        self.assertEqual(_even(11), 10)
        self.assertEqual(_even(10), 10)
        self.assertEqual(_even(11.9), 10)
        self.assertEqual(_even(0), 0)


class TestScrollbarThumbBounds(unittest.TestCase):

    def test_normal_thumb_maps_proportionally(self):
        y1, y2 = scrollbar_thumb_bounds(0.25, 0.75, 200)
        self.assertEqual((y1, y2), (50.0, 150.0))

    def test_tiny_thumb_gets_minimum_size_without_leaving_track(self):
        # A near-zero thumb at the very bottom must still fit inside [0, height]
        y1, y2 = scrollbar_thumb_bounds(0.99, 1.0, 200, min_px=10)
        self.assertGreaterEqual(y2 - y1, 10 - 1e-9)
        self.assertLessEqual(y2, 200 + 1e-9)   # naive clamp would push y2 past the end
        self.assertGreaterEqual(y1, 0)

    def test_tiny_thumb_at_top_stays_anchored_at_zero(self):
        y1, y2 = scrollbar_thumb_bounds(0.0, 0.001, 200, min_px=10)
        self.assertAlmostEqual(y1, 0.0)
        self.assertGreaterEqual(y2 - y1, 10 - 1e-9)


class TestScrollbarDragStart(unittest.TestCase):

    def test_grabbed_point_stays_under_cursor(self):
        # thumb occupies 25% of track; grabbed 10% from its top
        thumb_len = 0.25
        grab_offset = 0.10
        # cursor at 0.60 -> thumb top should be 0.50
        self.assertAlmostEqual(scrollbar_drag_start(0.60, grab_offset, thumb_len), 0.50)

    def test_clamped_to_track_top_and_bottom(self):
        self.assertEqual(scrollbar_drag_start(-5, 0.0, 0.25), 0.0)
        self.assertEqual(scrollbar_drag_start(5, 0.0, 0.25), 0.75)  # 1 - thumb_len

    def test_center_grab_behaves_like_page_jump(self):
        # grab_offset = half the thumb -> cursor becomes the thumb centre
        self.assertAlmostEqual(scrollbar_drag_start(0.5, 0.125, 0.25), 0.375)


class TestDetectSystemTheme(unittest.TestCase):

    def test_returns_valid_value_or_none(self):
        # Never raises; result is one of the three allowed values on any OS
        self.assertIn(detect_system_theme(), ('dark', 'light', None))


@unittest.skipUnless(sys.platform not in ('win32', 'darwin'), 'Linux tk-scaling path')
class TestDpiScaleLinux(unittest.TestCase):

    def test_tk_scaling_maps_to_dpi_factor(self):
        # 1.3333 px/pt == 96 dpi == 100% -> factor 1.0
        self.assertAlmostEqual(get_window_dpi_scale(FakeWindow(tk_scaling=1.3333)), 1.0, places=3)
        # 2.0 px/pt -> 150%
        self.assertAlmostEqual(get_window_dpi_scale(FakeWindow(tk_scaling=2.0)), 1.5, places=3)


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
        self.assertAlmostEqual(Window.ui_scale.fget(s), 1.5)     # geometry grows
        self.assertAlmostEqual(Window.font_scale.fget(s), 1.0)   # font ratio neutral

    def test_dragging_to_100pct_shrinks_fonts_by_ratio(self):
        s = self._Stub(zoom=12, dpi=1.0, startup=1.5)
        self.assertAlmostEqual(Window.ui_scale.fget(s), 1.0)
        self.assertAlmostEqual(Window.font_scale.fget(s), 1.0 / 1.5)

    def test_font_never_gets_absolute_factor(self):
        # font_scale must NOT equal ui_scale above 100%
        s = self._Stub(zoom=12, dpi=1.5, startup=1.5)
        self.assertNotAlmostEqual(Window.font_scale.fget(s), Window.ui_scale.fget(s))


class TestDpiTracker(unittest.TestCase):

    def test_fires_on_change_and_settles(self):
        win = FakeWindow()
        # __init__ probe -> 1.0; poll #1 -> 1.0 (no change); poll #2 -> 1.5 (change)
        scales = iter([1.0, 1.0, 1.5])
        events = []
        tr = DpiTracker(win, lambda old, new: events.append((old, new)),
                        probe=lambda w: next(scales))

        self.assertEqual(tr.scale, 1.0)
        win.run_next()                                          # poll #1: no change
        self.assertEqual(events, [])
        self.assertEqual(win.pending[-1][0], DpiTracker.poll_interval)
        win.run_next()                                          # poll #2: change
        self.assertEqual(events, [(1.0, 1.5)])
        self.assertEqual(tr.scale, 1.5)
        self.assertEqual(win.pending[-1][0], DpiTracker.settle_interval)  # settle pause after change

    def test_loop_dies_when_window_gone(self):
        win = FakeWindow()
        DpiTracker(win, lambda o, n: None, probe=lambda w: 1.0)
        win._exists = False
        win.run_next()                          # should return without rescheduling
        self.assertEqual(win.pending, [])

    def test_skips_probe_while_minimized(self):
        win = FakeWindow()
        win._state = 'iconic'
        probed = []
        DpiTracker(win, lambda o, n: None, probe=lambda w: probed.append(1) or 1.0)
        probed.clear()                          # ignore the initial probe
        win.run_next()
        self.assertEqual(probed, [])            # no probe while iconified
        self.assertTrue(win.pending)            # but keeps polling


if __name__ == '__main__':
    unittest.main()
