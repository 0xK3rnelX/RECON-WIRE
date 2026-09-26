"""ASCII art purple-blue gradient banner for RECON-WIRE."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

BANNER_LINES: list[str] = [
    "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗    ██╗██╗██████╗ ███████╗",
    "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ██║    ██║██║██╔══██╗██╔════╝",
    "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗██║ █╗ ██║██║██████╔╝█████╗  ",
    "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════╝██║███╗██║██║██╔══██╗██╔══╝  ",
    "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ╚███╔███╔╝██║██║  ██║███████╗",
    "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝",
]

# Ensure each line is padded to identical width (78 chars) so ASCII characters never skew
MAX_LINE_LEN = max(len(line) for line in BANNER_LINES)
BANNER_LINES = [line.ljust(MAX_LINE_LEN) for line in BANNER_LINES]

AUTHOR_LINE = (
    "Web Reconnaissance Suite  |  "
    "[bold #58a6ff]author[/bold #58a6ff]: "
    "[bold #bc8cff]0xK3rnelX[/bold #bc8cff]  |  "
    "[#8b949e]v1.0[/#8b949e]"
)


def purpleblue(text: str) -> str:
    """Fade text vertically through an authentic RGB purple-to-blue gradient."""
    os.system("")
    faded = ""
    red = 110
    for line in text.splitlines():
        faded += f"\033[38;2;{red};0;255m{line}\033[0m\n"
        if red != 0:
            red -= 15
            if red < 0:
                red = 0
    return faded


def get_banner_renderable():
    """Returns a Rich renderable with perfect rigid grid alignment centered horizontally."""
    from rich.align import Align
    from rich.console import Group
    from rich.text import Text

    # 1. Rigid banner block
    banner_markup = get_banner_string()
    banner_text = Text.from_markup(banner_markup)

    # 2. Author subline
    author_text = Text.from_markup(f"[#8b949e]{AUTHOR_LINE}[/#8b949e]", justify="center")

    group = Group(
        banner_text,
        Text(""),
        author_text,
    )
    return Align.center(group)


def get_banner_string() -> str:
    """Returns Rich markup string with purple-to-blue RGB gradient matching our cyber theme."""
    lines: list[str] = []
    red = 110
    step = 18
    for line in BANNER_LINES:
        hex_color = f"#{red:02x}00ff"
        lines.append(f"[{hex_color}]{line}[/{hex_color}]")
        red = max(0, red - step)

    return "\n".join(lines)
