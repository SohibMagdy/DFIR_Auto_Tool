"""
whitelist.py -- Process and path whitelist for false positive reduction.

Provides functions to determine whether a finding should be suppressed
based on the process name, execution path, or rule context.

Design principle:
  No process is COMPLETELY immune. The whitelist only suppresses
  low-confidence, isolated indicators. Correlated malicious behavior
  (e.g. RWX + MZ + Temp) will still trigger findings even for
  whitelisted processes.
"""

import re
from utils import setup_logging

logger = setup_logging()


# ─── Whitelisted process names (lowercase) ──────────────────────────────────
# These are legitimate Windows processes and common applications.
# When seen with ISOLATED weak indicators (RWX-only, AppData-only),
# findings are suppressed. Strong or correlated indicators still fire.
WHITELISTED_PROCESSES: set[str] = {
    # Windows system
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "dwm.exe", "conhost.exe", "taskhostw.exe", "taskhost.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe",
    "rundll32.exe", "msiexec.exe", "spoolsv.exe", "lsaiso.exe",
    "wininit.exe", "system", "registry",
    "runtimebroker.exe", "applicationframehost.exe",
    "shellexperiencehost.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe",
    "securityhealthservice.exe", "sgrmbroker.exe",
    "smartscreen.exe", "backgroundtaskhost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "microsoftedge.exe", "microsoftedgecp.exe", "microsoftedgesh.exe",
    "opera.exe", "brave.exe",
    # Microsoft Office
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "mspub.exe", "lync.exe",
    "teams.exe", "onedrive.exe",
    # Common system utilities
    "msdtc.exe", "sppsvc.exe", "taskmgr.exe", "regedit.exe",
    "notepad.exe", "mmc.exe", "cmd.exe", "powershell.exe",
    "wmiprvse.exe", "wscript.exe", "cscript.exe",
    "audiodg.exe", "dashost.exe", "sppextcomobj.exe",
    "mpcmdrun.exe", "msmpeng.exe", "nissrv.exe",
}

# ─── Whitelisted temp/appdata path patterns ─────────────────────────────────
# Browser caches, Office temp files, and Windows Update paths that are
# legitimate uses of Temp/AppData directories.
WHITELISTED_TEMP_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"Google\\Chrome\\",
        r"Mozilla\\Firefox\\",
        r"Microsoft\\Edge\\",
        r"Microsoft\\Windows\\INetCache\\",
        r"Microsoft\\Office\\",
        r"Microsoft\\Teams\\",
        r"Microsoft\\OneDrive\\",
        r"Windows\\SoftwareDistribution\\",
        r"Windows\\Temp\\cab_",
        r"Windows\\Temp\\msi",
        r"Packages\\",
        r"WindowsApps\\",
    ]
]

# ─── Rules that can be suppressed for whitelisted processes ──────────────────
# Only WEAK / isolated indicators. Strong indicators are never suppressed.
SUPPRESSIBLE_RULES: set[str] = {
    "rwx_memory",         # RWX alone is common in JIT compilers, .NET, etc.
    "temp_execution",     # Browsers & Office use AppData heavily
    "hidden_process",     # Some system processes are legitimately hidden
}

# Rules that are NEVER suppressed regardless of whitelist
UNSUPPRESSIBLE_RULES: set[str] = {
    "process_injection",  # MZ header = always suspicious
    "random_executable",  # Random names = always suspicious
}


def normalize_process_name(name: str) -> str:
    """Extract and lowercase the base filename from a process string."""
    # Strip PID suffix like "(PID: 1234)"
    clean = re.sub(r"\s*\(PID:.*?\)", "", name).strip()
    # Take just the filename if a path is present
    if "\\" in clean:
        clean = clean.rsplit("\\", 1)[-1]
    if "/" in clean:
        clean = clean.rsplit("/", 1)[-1]
    return clean.lower().strip()


def is_whitelisted_process(process_name: str) -> bool:
    """Check if a process name is in the whitelist.

    Handles truncated names from column-based parsing (e.g. 'chrome.'
    or 'explore' should still match 'chrome.exe' and 'explorer.exe').
    """
    proc = normalize_process_name(process_name)
    if proc in WHITELISTED_PROCESSES:
        return True
    # Handle truncated names ending with '.' (column slicing artifact)
    # e.g. 'chrome.' should match 'chrome.exe'
    if proc.endswith("."):
        candidate = proc + "exe"
        if candidate in WHITELISTED_PROCESSES:
            return True
    # Handle names without extension that are prefix of a whitelisted name
    # e.g. 'explore' should match 'explorer.exe'
    if not proc.endswith(".exe") and len(proc) >= 5:
        for wl in WHITELISTED_PROCESSES:
            if wl.startswith(proc):
                return True
    return False


def is_whitelisted_temp_path(evidence: str) -> bool:
    """Check if a path in the evidence matches known browser/Office temp patterns."""
    return any(pat.search(evidence) for pat in WHITELISTED_TEMP_PATTERNS)


def should_suppress(rule_id: str, process: str, evidence: str = "") -> bool:
    """Determine if a finding should be suppressed.

    Returns True if ALL of the following are true:
      1. The rule is in SUPPRESSIBLE_RULES
      2. The process is whitelisted
      3. The rule is NOT in UNSUPPRESSIBLE_RULES
      4. For temp_execution: the path matches a whitelisted browser/Office pattern

    Returns False otherwise (finding should proceed).
    """
    # Never suppress critical rules
    if rule_id in UNSUPPRESSIBLE_RULES:
        return False

    # Only suppress designated weak rules
    if rule_id not in SUPPRESSIBLE_RULES:
        return False

    proc_lower = normalize_process_name(process)

    # Check if process is whitelisted (handles truncated names)
    if not is_whitelisted_process(process):
        return False

    # For temp_execution, also require the path to be a known-good pattern
    if rule_id == "temp_execution":
        if not is_whitelisted_temp_path(evidence):
            return False  # Unknown temp path -> still suspicious

    logger.debug(
        "Suppressed finding: rule=%s, process=%s (whitelisted)",
        rule_id, proc_lower,
    )
    return True
