import gi

if hasattr(gi, "disable_legacy_autoinit"):
    gi.disable_legacy_autoinit()

from .tray import main

if __name__ == "__main__":
    raise SystemExit(main())
