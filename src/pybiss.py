'''
    python -m src.pybiss                # desktop dashboard + local REST API
    python -m src.pybiss server         # headless BISS-compatible HTTPS daemon
    python -m src.pybiss server --http  # ...plain HTTP (debugging)
    python -m src.pybiss tui            # terminal UI

This is what a PyInstaller spec / shell wrapper / console script wraps.
(If a `python -m src` short form is ever wanted, add a src/__main__.py
shim that imports and calls main() from here.)
'''

import sys


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'gui'

    if mode == 'gui':
        from .dashboard import main as dashboard_main
        dashboard_main()
    elif mode == 'server':
        from .app import serve
        serve(https='--http' not in sys.argv)
    elif mode == 'tui':
        from .tui import run_tui
        run_tui()
    else:
        sys.exit(__doc__.strip())


if __name__ == '__main__':
    main()
