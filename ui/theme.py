"""Central color constants and Rich markup helpers for RECON-WIRE UI.

No imports from other project files. Used by all tab widgets.
"""

from __future__ import annotations

# ── Palette ──────────────────────────────────────────────────
BG_PRIMARY    = "#0d1117"
BG_SECONDARY  = "#161b22"
BG_TERTIARY   = "#21262d"
BORDER        = "#30363d"
TEXT_PRIMARY  = "#e6edf3"
TEXT_MUTED    = "#8b949e"
BLUE          = "#58a6ff"
GREEN         = "#3fb950"
YELLOW        = "#d29922"
RED           = "#f85149"
ORANGE        = "#db6d28"
PURPLE        = "#bc8cff"
CYAN          = "#39d353"
DIM           = "#484f58"

# ── Severity markup ───────────────────────────────────────────
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": f"bold {RED}",
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     TEXT_MUTED,
}

# ── HTTP status markup ────────────────────────────────────────
STATUS_COLORS: dict[int, str] = {
    200: GREEN,  201: GREEN,  204: GREEN,
    301: YELLOW, 302: YELLOW, 307: YELLOW, 308: YELLOW,
    400: RED,    401: RED,    403: ORANGE,
    404: DIM,    429: YELLOW,
    500: f"bold {RED}", 502: RED, 503: RED,
}

# ── Markers ───────────────────────────────────────────────────
HOT_MARKER  = f"[bold {RED}]◄◄[/bold {RED}]"
WARN_MARKER = f"[{YELLOW}]⚠[/{YELLOW}]"
OK_MARKER   = f"[{GREEN}]✓[/{GREEN}]"
FAIL_MARKER = f"[{RED}]✗[/{RED}]"
INFO_MARKER = f"[{BLUE}]ℹ[/{BLUE}]"
LOCK_MARKER = f"[{GREEN}]🔒[/{GREEN}]"
UNLOCK_MARKER = f"[{RED}]🔓[/{RED}]"

STATE_MARKERS: dict[str, str] = {
    "PENDING": f"[{DIM}]⏳[/{DIM}]",
    "RUNNING": f"[bold {BLUE}]⟳[/bold {BLUE}]",
    "DONE": OK_MARKER,
    "ERROR": FAIL_MARKER,
}

# ── Helper functions ──────────────────────────────────────────
def severity_markup(text: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, TEXT_MUTED)
    return f"[{color}]{text}[/{color}]"

def status_markup(code: int) -> str:
    color = STATUS_COLORS.get(code, TEXT_MUTED)
    return f"[{color}]{code}[/{color}]"

def hot(text: str) -> str:
    return f"{HOT_MARKER} [{RED}]{text}[/{RED}]"

def muted(text: str) -> str:
    return f"[{TEXT_MUTED}]{text}[/{TEXT_MUTED}]"

def bold_blue(text: str) -> str:
    return f"[bold {BLUE}]{text}[/bold {BLUE}]"

def section_header(text: str) -> str:
    return f"[bold {BLUE}]==[/bold {BLUE}] [bold {TEXT_PRIMARY}]{text}[/bold {TEXT_PRIMARY}] [bold {BLUE}]==[/bold {BLUE}]"

def ok(text: str) -> str:
    return f"[{GREEN}]{text}[/{GREEN}]"

def fail(text: str) -> str:
    return f"[{RED}]{text}[/{RED}]"

def warn(text: str) -> str:
    return f"[{YELLOW}]{text}[/{YELLOW}]"

def dim(text: str) -> str:
    return f"[{DIM}]{text}[/{DIM}]"

def bold(text: str) -> str:
    return f"[bold]{text}[/bold]"

def grade_markup(grade: str) -> str:
    color = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": RED, "F": f"bold {RED}"}.get(grade, TEXT_PRIMARY)
    return f"[{color}]{grade}[/{color}]"
