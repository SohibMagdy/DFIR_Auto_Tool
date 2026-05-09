"""
correlator.py -- Multi-indicator behavioral correlation engine (v1.2).

Groups raw findings by process, evaluates what combination of indicators
each process exhibits, and assigns a confidence level. Adjusts each
finding's effective_score based on the correlation multiplier.

v1.2 changes:
  - Indicator strength tiers (STRONG/MODERATE/WEAK) for smarter escalation
  - process_spawn category integrated from process_analyzer
  - Tighter escalation logic: weak-only combos stay LOW
  - Execution chain scoring feeds into confidence
"""

import re
from collections import defaultdict

from rich.table import Table

from utils import console, load_rules, setup_logging, separator

logger = setup_logging()


# ─── Indicator categories for correlation ────────────────────────────────────
INDICATOR_CATEGORIES: dict[str, str] = {
    # Memory indicators
    "rwx_memory":           "memory_rwx",
    "process_injection":    "memory_injection",
    "svchost_suspicious":   "memory_injection",
    "explorer_injection":   "memory_injection",
    "wmiprvse_suspicious":  "memory_injection",
    # Process indicators
    "wscript_execution":    "scripting",
    "vbs_script":           "scripting",
    "temp_execution":       "temp_exec",
    "random_executable":    "random_name",
    "hidden_process":       "hidden_proc",
    # Network indicators
    "suspicious_port":      "network",
    "external_connection":  "network",
    # Process relationship indicators (v1.2)
    "office_child_spawn":   "process_spawn",
    "script_child_spawn":   "process_spawn",
    "explorer_temp_child":  "process_spawn",
    "svchost_shell_spawn":  "process_spawn",
    "browser_shell_spawn":  "process_spawn",
    "process_spawning_storm": "process_spawn",
}

# ─── Indicator strength tiers ────────────────────────────────────────────────
# Used for smarter escalation. Two WEAK indicators should not produce MEDIUM.
STRONG_INDICATORS = {"memory_injection", "scripting", "random_name", "process_spawn"}
MODERATE_INDICATORS = {"temp_exec", "network", "hidden_proc"}
WEAK_INDICATORS = {"memory_rwx"}


def _normalize_process(proc: str) -> str:
    """Normalize a process string for grouping.

    Strips PID suffixes, paths, .exe extension, and lowercases.
    Uses first 6 chars to handle column-truncated names.
    """
    clean = re.sub(r"\s*\(PID:.*?\)", "", proc).strip()
    if "\\" in clean:
        clean = clean.rsplit("\\", 1)[-1]
    if "/" in clean:
        clean = clean.rsplit("/", 1)[-1]
    # Remove tab artifacts
    clean = clean.split("\t")[0].strip().lower()
    # Strip .exe and trailing dots (truncation artifacts)
    clean = clean.replace(".exe", "").rstrip(".")
    # Use first 6 chars for grouping to merge truncated variants
    return clean[:6] if len(clean) >= 6 else clean


class CorrelationGroup:
    """Represents a group of correlated findings for one process."""

    def __init__(self, process: str) -> None:
        self.process = process
        self.findings: list = []         # Finding objects
        self.indicator_types: set[str] = set()
        self.confidence: str = "LOW"
        self.multiplier: float = 0.3
        self.mitre_ids: set[str] = set()

    def add_finding(self, finding) -> None:
        """Add a finding and update indicator categories."""
        self.findings.append(finding)
        cat = INDICATOR_CATEGORIES.get(finding.rule_id, "other")
        self.indicator_types.add(cat)
        if finding.mitre_id:
            self.mitre_ids.add(finding.mitre_id)

    def evaluate_confidence(self, multipliers: dict) -> None:
        """Determine confidence level based on indicator diversity and strength.

        v1.2: Uses indicator strength tiers to prevent weak-only combos
        from escalating. Two WEAK indicators stay LOW.
        """
        n = len(self.indicator_types)
        types = self.indicator_types

        # Count by strength tier
        strong_count = len(types & STRONG_INDICATORS)
        moderate_count = len(types & MODERATE_INDICATORS)
        weak_count = len(types & WEAK_INDICATORS)

        # ── CRITICAL: 4+ categories, or specific deadly combos ───────────
        if n >= 4 and strong_count >= 1:
            self.confidence = "CRITICAL"
        elif (
            "memory_injection" in types
            and "temp_exec" in types
            and ("network" in types or "scripting" in types or "process_spawn" in types)
        ):
            self.confidence = "CRITICAL"
        elif (
            "process_spawn" in types
            and "memory_injection" in types
            and n >= 3
        ):
            self.confidence = "CRITICAL"

        # ── HIGH: 3+ with at least 1 STRONG, or injection + 1 STRONG ────
        elif n >= 3 and strong_count >= 1:
            self.confidence = "HIGH"
        elif "memory_injection" in types and strong_count >= 1:
            self.confidence = "HIGH"
        elif "process_spawn" in types and (strong_count + moderate_count) >= 2:
            self.confidence = "HIGH"

        # ── MEDIUM: 2+ with at least 1 STRONG or 2 MODERATE ─────────────
        elif n >= 2 and strong_count >= 1:
            self.confidence = "MEDIUM"
        elif moderate_count >= 2:
            self.confidence = "MEDIUM"
        elif n >= 3 and weak_count <= 1:
            self.confidence = "MEDIUM"

        # ── LOW: single category, or weak-only combinations ──────────────
        else:
            self.confidence = "LOW"

        self.multiplier = multipliers.get(self.confidence, 0.3)

    def apply_scores(self) -> None:
        """Set effective_score on each finding based on the group multiplier."""
        for f in self.findings:
            f.effective_score = round(f.score * self.multiplier)
            f.confidence = self.confidence
            f.correlation_group = self.process


class CorrelationEngine:
    """Group findings by process and assign confidence levels."""

    def __init__(self) -> None:
        rules = load_rules()
        self.multipliers = rules.get("confidence_multipliers", {
            "LOW": 0.3, "MEDIUM": 0.7, "HIGH": 1.0, "CRITICAL": 1.5,
        })
        self.groups: dict[str, CorrelationGroup] = {}

    def correlate(self, findings: list) -> list:
        """Run correlation on all findings.

        Parameters
        ----------
        findings : list[Finding]
            Raw findings from the detector.

        Returns
        -------
        list[Finding]
            Same findings list, now enriched with confidence,
            effective_score, and correlation_group.
        """
        separator("Behavioral Correlation Engine")
        console.print("[bold cyan][*] Correlating indicators across processes...[/bold cyan]\n")

        # ── Group findings by normalized process name ────────────────────
        proc_groups: dict[str, CorrelationGroup] = {}

        for f in findings:
            proc_key = _normalize_process(f.process) if f.process else "__global__"
            if proc_key not in proc_groups:
                proc_groups[proc_key] = CorrelationGroup(proc_key)
            proc_groups[proc_key].add_finding(f)

        # ── Evaluate confidence per group ────────────────────────────────
        for group in proc_groups.values():
            group.evaluate_confidence(self.multipliers)
            group.apply_scores()

        self.groups = proc_groups

        # ── Display correlation results ──────────────────────────────────
        self._display_summary()

        logger.info(
            "Correlation complete -- %d groups, confidences: %s",
            len(proc_groups),
            {g.process: g.confidence for g in proc_groups.values()},
        )

        return findings

    def _display_summary(self) -> None:
        """Print a correlation summary table."""
        confidence_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold bright_red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
        }

        table = Table(
            title="Behavioral Correlation Summary",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
        )
        table.add_column("Process", style="bold white", min_width=20)
        table.add_column("Findings", justify="center", width=9)
        table.add_column("Indicators", min_width=25)
        table.add_column("Confidence", justify="center", min_width=10)
        table.add_column("Multiplier", justify="right", width=10)
        table.add_column("MITRE", min_width=15)

        for group in sorted(
            self.groups.values(),
            key=lambda g: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(g.confidence, 4),
        ):
            color = confidence_colors.get(group.confidence, "white")
            indicators = ", ".join(sorted(group.indicator_types))
            mitre = ", ".join(sorted(group.mitre_ids)) if group.mitre_ids else "--"
            table.add_row(
                group.process[:25],
                str(len(group.findings)),
                indicators,
                f"[{color}]{group.confidence}[/{color}]",
                f"{group.multiplier}x",
                mitre,
            )

        console.print(table)
        console.print()

    def get_groups(self) -> dict[str, CorrelationGroup]:
        """Return correlation groups for reporting."""
        return self.groups
