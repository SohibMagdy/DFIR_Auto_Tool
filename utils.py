"""
utils.py — Shared utilities for the DFIR automation tool.

Provides logging setup, directory initialization, banner display,
and common helper functions used across all modules.
"""

import logging
import json
import sys
import os
from pathlib import Path
from datetime import datetime

# ─── Force UTF-8 output on Windows (prevents cp1252 UnicodeEncodeError) ──────
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # Non-fatal — Kali/Linux won't need this

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


# ─── Global console instance ────────────────────────────────────────────────
console = Console(force_terminal=True)

# ─── Project paths ───────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
RESULTS_DIR = PROJECT_ROOT / "results"
LOGS_DIR = PROJECT_ROOT / "logs"
RULES_DIR = PROJECT_ROOT / "rules"
RULES_FILE = RULES_DIR / "detection_rules.json"

# ─── Volatility command name (auto-detected) ────────────────────────────────
def _detect_vol_command() -> str:
    """Auto-detect the Volatility 3 command available on this system.

    Checks for common command names in PATH order:
      vol3 → volatility3 → vol
    Falls back to 'vol3' if none are found (will error at runtime).
    """
    import shutil
    for candidate in ("vol3", "volatility3", "vol"):
        if shutil.which(candidate):
            return candidate
    return "vol3"  # Default fallback


VOL_COMMAND = _detect_vol_command()


def _ensure_directories() -> None:
    """Create all required directories at import time.

    Called once when the module is first imported so that every other
    function (especially setup_logging) can safely write to these paths.
    Works identically on Windows and Linux thanks to pathlib.
    """
    for d in (OUTPUT_DIR, RESULTS_DIR, LOGS_DIR, RULES_DIR):
        d.mkdir(parents=True, exist_ok=True)


# Eagerly create directories so FileHandler never hits a missing path
_ensure_directories()


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """Configure and return the application-wide logger.

    Logs are written to both console (via Rich) and a file inside the
    results directory so that every run is auditable.
    """
    logger = logging.getLogger("DFIRTool")
    logger.setLevel(log_level)

    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    # File handler — persistent log (stored in logs/ directory)
    log_file = LOGS_DIR / "dfir_tool.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    # Stream handler — terminal output (minimal, Rich handles the fancy stuff)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(file_fmt)
    logger.addHandler(stream_handler)

    return logger


def init_directories() -> None:
    """Ensure all working directories exist.

    This is safe to call multiple times — directories are also created
    at module-import time by ``_ensure_directories()``, but this
    function is kept as an explicit checkpoint in the pipeline.
    """
    _ensure_directories()


def load_rules() -> dict:
    """Load detection rules from the JSON configuration file."""
    if not RULES_FILE.exists():
        console.print(
            f"[bold red]✖ Detection rules not found at {RULES_FILE}[/bold red]"
        )
        raise FileNotFoundError(f"Missing rules file: {RULES_FILE}")

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def display_banner() -> None:
    """Print the tool's startup banner."""
    banner_text = Text()
    banner_text.append("██████╗ ███████╗██╗██████╗ ", style="bold cyan")
    banner_text.append("\n")
    banner_text.append("██╔══██╗██╔════╝██║██╔══██╗", style="bold cyan")
    banner_text.append("\n")
    banner_text.append("██║  ██║█████╗  ██║██████╔╝", style="bold cyan")
    banner_text.append("\n")
    banner_text.append("██║  ██║██╔══╝  ██║██╔══██╗", style="bold cyan")
    banner_text.append("\n")
    banner_text.append("██████╔╝██║     ██║██║  ██║", style="bold cyan")
    banner_text.append("\n")
    banner_text.append("╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝", style="bold cyan")
    banner_text.append("\n\n")
    banner_text.append(
        "  Digital Forensics & Incident Response Automation Tool\n",
        style="bold white",
    )
    banner_text.append(
        "  Memory Forensics  •  Volatility 3  •  Threat Scoring\n",
        style="dim white",
    )

    console.print(
        Panel(
            banner_text,
            border_style="bright_cyan",
            padding=(1, 4),
        )
    )


def timestamp() -> str:
    """Return a formatted timestamp string for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def separator(label: str = "", style: str = "bright_cyan") -> None:
    """Print a styled horizontal separator with an optional label."""
    if label:
        console.print(f"\n[{style}]{'─' * 20} {label} {'─' * 20}[/{style}]")
    else:
        console.print(f"[{style}]{'─' * 60}[/{style}]")
