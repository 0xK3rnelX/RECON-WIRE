import os
import sys

from app.cli import parse_and_validate
from app.core import ReconWireApp

_original_stdin_mode = None


def setup_terminal() -> None:
    """Configure terminal for ANSI/VT processing, UTF-8 codepage, and full cmd.exe support."""
    global _original_stdin_mode
    if sys.platform != "win32":
        return

    # Force Python standard streams to UTF-8
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32

        # Switch Windows console code page to UTF-8 (CP 65001)
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)

        # Enable Virtual Terminal Processing on STDOUT and STDERR for cmd.exe
        ENABLE_PROCESSED_OUTPUT = 0x0001
        ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            h = kernel32.GetStdHandle(handle_id)
            if h and h != -1:
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(
                        h,
                        mode.value
                        | ENABLE_PROCESSED_OUTPUT
                        | ENABLE_WRAP_AT_EOL_OUTPUT
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                    )

        # Save stdin original mode and DO NOT enable ENABLE_VIRTUAL_TERMINAL_INPUT (0x0200)
        # Enabling VT input causes arrow keys/mouse/keys to be converted into raw escape sequences
        # like ^[[A that get trapped in the input buffer and leak into the shell on exit.
        h_in = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        if h_in and h_in != -1:
            mode_in = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_in, ctypes.byref(mode_in)):
                _original_stdin_mode = mode_in.value
                # Ensure line input and echo input are preserved or clean
                ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
                ENABLE_MOUSE_INPUT = 0x0010
                clean_mode = mode_in.value & ~ENABLE_VIRTUAL_TERMINAL_INPUT & ~ENABLE_MOUSE_INPUT
                kernel32.SetConsoleMode(h_in, clean_mode)
    except Exception:
        pass


def restore_terminal() -> None:
    """Flush pending input buffer and restore original console modes."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        h_in = kernel32.GetStdHandle(-10)
        if h_in and h_in != -1:
            # Flush any unread console input records
            kernel32.FlushConsoleInputBuffer(h_in)
            if _original_stdin_mode is not None:
                kernel32.SetConsoleMode(h_in, _original_stdin_mode)
        # Flush msvcrt buffer if available
        import msvcrt

        while msvcrt.kbhit():
            msvcrt.getch()
    except Exception:
        pass


if __name__ == "__main__":
    setup_terminal()
    try:
        config = parse_and_validate()
        app = ReconWireApp(config=config)
        app.run()
    finally:
        restore_terminal()
