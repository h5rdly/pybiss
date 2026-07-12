'''
Manual widget gallery -- eyeball check for the custom tkinter_mods widgets.

Run to sanity-check styling, dark titlebar, placeholder behaviour, scrollbar drag,
toggle/checkbox state, and notably DPI scaling: drag the window between a 100% and a 150%/200% 
monitor and confirm fonts stay put while the chrome grows (the ui_scale vs font_scale split).

    python tests/manual/widget_gallery.py

Use the +/- zoom or move it across monitors to test per-monitor DPI.
'''

import os, sys

sys.path.insert(0, __file__.replace('\\', '/').rsplit('/', 3)[0])

from src.tkinter_mods import (
    Window, Label, Button, Entry, Checkbox, Toggle,
    Textbox, Listbox, Toplevel, MessageBox, Theme,
)


def build():
    win = Window(title='pybiss widget gallery', width=560, height=640)

    Label(win, text='Widget Gallery', font=('Segoe UI', 16, 'bold')).pack(pady=(16, 4))
    Label(win, text='drag me across monitors to test per-monitor DPI').pack(pady=(0, 12))

    # Buttons 
    row = Button(win, text='Info dialog',
                 command=lambda: MessageBox.showinfo('Hello', 'This is an info box.'))
    row.pack(pady=4)
    Button(win, text='Yes / No dialog',
           command=lambda: print('askyesno ->',
                                  MessageBox.askyesno('Confirm', 'Proceed?'))).pack(pady=4)

    def open_modal():
        tl = Toplevel(win, title='Modal', width=320, height=180)
        Label(tl, text='I withdrew until show() -- no flash.').pack(pady=30)
        Button(tl, text='Close', command=tl.destroy).pack()
        tl.show()

    Button(win, text='Open modal (anti-flash)', command=open_modal).pack(pady=4)

    # Entry with placeholder + masking
    Label(win, text='Entry (placeholder, unmasked until typing):').pack(pady=(16, 2))
    Entry(win, placeholder='Enter your name').pack(pady=2)
    Label(win, text='Entry (password, masks once you type):').pack(pady=(8, 2))
    Entry(win, placeholder='PIN', show='*').pack(pady=2)

    # Checkbox / Toggle 
    Checkbox(win, text='Remember this card', checked=True,
             command=lambda: print('checkbox toggled')).pack(pady=(16, 4), anchor='w', padx=40)
    Toggle(win, text='Dark mode', is_on=True,
           command=lambda: print('toggle flipped')).pack(pady=4, anchor='w', padx=40)

    # Textbox (scrollable) 
    Label(win, text='Textbox (drag the scrollbar thumb):').pack(pady=(16, 2))
    tb = Textbox(win, width=480, height=100)
    tb.pack(pady=2)
    tb.insert('end', '\n'.join(f'certificate line {i}' for i in range(40)))

    # Listbox 
    Label(win, text='Listbox:').pack(pady=(12, 2))
    lb = Listbox(win, width=480, height=90)
    lb.pack(pady=2)
    for i in range(20):
        lb.insert('end', f'slot {i}: B-Trust Qualified Certificate')

    return win


if __name__ == '__main__':
    build().mainloop()
