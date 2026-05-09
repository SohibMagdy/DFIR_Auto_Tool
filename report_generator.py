"""
report_generator.py — Final forensic report generator.

Produces two result files:
  • suspicious_findings.txt — detailed list of every finding
  • final_report.txt        — executive summary + detailed analysis
"""

from utils import console, RESULTS_DIR, setup_logging, separator, timestamp

logger = setup_logging()


class ReportGenerator:
    """Generate human-readable forensic reports from analysis results."""

    def __init__(self, findings: list, scorer) -> None:
        """
        Parameters
        ----------
        findings : list[Finding]
        scorer : ThreatScorer (after .calculate() has been called)
        """
        self.findings = findings
        self.scorer = scorer

    # ── Private helpers ──────────────────────────────────────────────────

    def _build_findings_report(self) -> str:
        """Create the suspicious_findings.txt content."""
        lines = [
            "=" * 70,
            "  SUSPICIOUS FINDINGS REPORT",
            f"  Generated: {timestamp()}",
            "=" * 70,
            "",
        ]

        if not self.findings:
            lines.append("No suspicious indicators were detected.")
            return "\n".join(lines)

        for idx, f in enumerate(self.findings, 1):
            lines.extend([
                f"─── Finding #{idx} {'─' * 50}",
                f"  Rule ID       : {f.rule_id}",
                f"  Category      : {f.category}",
                f"  Severity      : {f.severity}",
                f"  Score         : +{f.score}",
                f"  Process       : {f.process}",
                f"  Description   : {f.description}",
                f"  Evidence      : {f.evidence}",
                f"  Recommendation: {f.recommendation}",
                "",
            ])

        return "\n".join(lines)

    def _build_final_report(self) -> str:
        """Create the final_report.txt content."""
        lines = [
            "=" * 70,
            "  DFIR AUTOMATED FORENSIC REPORT",
            f"  Generated: {timestamp()}",
            "=" * 70,
            "",
            "── EXECUTIVE SUMMARY ──────────────────────────────────",
            "",
            f"  Total Findings     : {len(self.findings)}",
            f"  Threat Score       : {self.scorer.total_score}/100",
            f"  Risk Classification: {self.scorer.classification}",
            "",
        ]

        # Category breakdown
        categories: dict[str, list] = {}
        for f in self.findings:
            categories.setdefault(f.category, []).append(f)

        if categories:
            lines.append("── FINDINGS BY CATEGORY ───────────────────────────────")
            lines.append("")
            for cat, items in categories.items():
                lines.append(f"  [{cat.upper()}] — {len(items)} finding(s)")
                for item in items:
                    lines.append(f"    • [{item.severity}] {item.description}")
                    lines.append(f"      Process : {item.process}")
                    lines.append(f"      Evidence: {item.evidence}")
                    lines.append(f"      Action  : {item.recommendation}")
                    lines.append("")

        # Severity summary
        sev_counts: dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        if sev_counts:
            lines.append("── SEVERITY DISTRIBUTION ──────────────────────────────")
            lines.append("")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in sev_counts:
                    bar = "█" * sev_counts[sev]
                    lines.append(f"  {sev:10s} : {bar} ({sev_counts[sev]})")
            lines.append("")

        # Score breakdown
        lines.append("── SCORE BREAKDOWN ────────────────────────────────────")
        lines.append("")
        for item in self.scorer.breakdown:
            lines.append(
                f"  {item['rule']:25s} +{item['points']:3d}  {item['process']}"
            )
        lines.append(f"\n  {'TOTAL':25s}  {self.scorer.total_score:3d}/100")
        lines.append("")

        # Classification explanation
        lines.append("── RISK ASSESSMENT ────────────────────────────────────")
        lines.append("")
        if self.scorer.classification == "NORMAL":
            lines.append("  The memory image shows no significant indicators of")
            lines.append("  compromise. Standard baseline activity observed.")
        elif self.scorer.classification == "SUSPICIOUS":
            lines.append("  The memory image contains indicators that warrant")
            lines.append("  further investigation. Some artifacts may be benign")
            lines.append("  but should be validated by an analyst.")
        else:
            lines.append("  The memory image contains strong indicators of")
            lines.append("  compromise. Immediate incident response actions")
            lines.append("  are recommended. Isolate the host and preserve")
            lines.append("  all forensic evidence.")
        lines.append("")
        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)

    # ── Public API ───────────────────────────────────────────────────────

    def generate(self) -> None:
        """Write both report files and display a summary."""
        separator("Report Generation")

        # Suspicious findings
        findings_path = RESULTS_DIR / "suspicious_findings.txt"
        findings_path.write_text(self._build_findings_report(), encoding="utf-8")
        console.print(f"[green]✔ Findings report saved:[/green] {findings_path}")

        # Final report
        report_path = RESULTS_DIR / "final_report.txt"
        report_path.write_text(self._build_final_report(), encoding="utf-8")
        console.print(f"[green]✔ Final report saved  :[/green] {report_path}")

        # Terminal preview
        console.print()
        color = self.scorer.color
        console.print(f"[bold {color}]{'═' * 50}[/bold {color}]")
        console.print(f"[bold {color}]  THREAT SCORE  : {self.scorer.total_score}/100[/bold {color}]")
        console.print(f"[bold {color}]  CLASSIFICATION: {self.scorer.classification}[/bold {color}]")
        console.print(f"[bold {color}]  FINDINGS      : {len(self.findings)}[/bold {color}]")
        console.print(f"[bold {color}]{'═' * 50}[/bold {color}]")
        console.print()

        logger.info("Reports generated successfully")
