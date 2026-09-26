"""RECON-WIRE application package."""

import sys

from app.cli import parse_and_validate
from app.core import ReconWireApp
from app.state import AppState, ModuleStatus, ScanConfig


def main() -> None:
    """Primary application console entrypoint."""
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            h_out = kernel32.GetStdHandle(-11)
            if h_out and h_out != -1:
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(h_out, mode.value | 0x0004 | 0x0008)
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass

    try:
        config = parse_and_validate()
        app = ReconWireApp(config=config)
        app.run()
    finally:
        if sys.platform == "win32":
            try:
                import ctypes
                import msvcrt

                kernel32 = ctypes.windll.kernel32
                h_in = kernel32.GetStdHandle(-10)
                if h_in and h_in != -1:
                    kernel32.FlushConsoleInputBuffer(h_in)
                while msvcrt.kbhit():
                    msvcrt.getch()
            except Exception:
                pass


__all__ = ["ScanConfig", "AppState", "ModuleStatus", "parse_and_validate", "ReconWireApp", "main"]
