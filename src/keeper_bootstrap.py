"""Run a Keeper module from the source tree beside this trusted script."""

from pathlib import Path
from runpy import run_module
import sys


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    module = sys.argv.pop(1)
    run_module(module, run_name="__main__", alter_sys=True)
