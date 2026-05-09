"""
report_generator.py -- Forensic report generator (v1.2).

Produces comprehensive result files:
  - suspicious_findings.txt -- detailed list of every finding
  - final_report.txt        -- executive summary + all analysis sections

v1.2 additions:
  - Process Relationship Summary with tree visualization
  - Correlated Attack Chains section
  - Top 5 Suspicious Processes ranked by effective_score
  - Most Severe Behaviors section
"""

from utils import console, RESULTS_DIR, setup_logging, separator, timestamp

logger = setup_logging()


class ReportGenerator:
    """Generate human-readable forensic reports from analysis results."""

    def __init__(
        self,
        findings: list,
        scorer,
        correlator=None,
        ioc_extractor=None,
        process_analyzer=None,
    ) -> None:
        """
        Parameters
        ----------
        findings : list[Finding]
        scorer : ThreatScorer (after .calculate())
        correlator : CorrelationEngine, optional
        ioc_extractor : IOCExtractor, optional
        process_analyzer : ProcessAnalyzer, optional (v1.2)
        """
        self.findings = findings
        self.scorer = scorer
        self.correlator = correlator
        self.ioc_extractor = ioc_extractor
        self.process_analyzer = process_analyzer

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
                f"--- Finding #{idx} {'---' * 16}",
                f"  Rule ID       : {f.rule_id}",
                f"  Category      : {f.category}",
                f"  Severity      : {f.severity}",
                f"  Confidence    : {f.confidence}",
                f"  Base Score    : +{f.score}",
                f"  Effective Scr : +{f.effective_score}",
                f"  MITRE ATT&CK  : {f.mitre_id} ({f.mitre_technique})" if f.mitre_id else "",
                f"  Process       : {f.process}",
                f"  Description   : {f.description}",
                f"  Evidence      : {f.evidence}",
                f"  Recommendation: {f.recommendation}",
                "",
            ])

        return "\n".join(line for line in lines if line is not None)

    def _build_executive_summary(self) -> list[str]:
        """Build the executive summary section."""
        lines = [
            "== EXECUTIVE SUMMARY ==========================================",
            "",
            f"  Total Findings      : {len(self.findings)}",
            f"  Threat Score        : {self.scorer.total_score}/100",
            f"  Risk Classification : {self.scorer.classification}",
            "",
        ]

        # Count by confidence
        conf_counts: dict[str, int] = {}
        for f in self.findings:
            conf_counts[f.confidence] = conf_counts.get(f.confidence, 0) + 1

        if conf_counts:
            lines.append("  Detection Confidence Breakdown:")
            for conf in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if conf in conf_counts:
                    lines.append(f"    {conf:10s}: {conf_counts[conf]} finding(s)")
            lines.append("")

        # Count by category
        cat_counts: dict[str, int] = {}
        for f in self.findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        if cat_counts:
            lines.append("  Finding Categories:")
            for cat, count in sorted(cat_counts.items()):
                lines.append(f"    {cat:15s}: {count} finding(s)")
            lines.append("")

        return lines

    def _build_mitre_section(self) -> list[str]:
        """Build the MITRE ATT&CK summary."""
        mitre_map: dict[str, set[str]] = {}
        for f in self.findings:
            if f.mitre_id:
                mitre_map.setdefault(f.mitre_id, set()).add(f.mitre_technique)

        if not mitre_map:
            return []

        lines = [
            "== MITRE ATT&CK MAPPING =======================================",
            "",
            f"  {'ID':14s} {'Technique':50s} {'Count':5s}",
            f"  {'-'*14} {'-'*50} {'-'*5}",
        ]

        mitre_count: dict[str, int] = {}
        for f in self.findings:
            if f.mitre_id:
                mitre_count[f.mitre_id] = mitre_count.get(f.mitre_id, 0) + 1

        for mid in sorted(mitre_map.keys()):
            techniques = ", ".join(sorted(mitre_map[mid]))
            count = mitre_count.get(mid, 0)
            lines.append(f"  {mid:14s} {techniques:50s} {count}")

        lines.append("")
        return lines

    def _build_process_relationship_section(self) -> list[str]:
        """Build the process relationship summary with tree visualization."""
        if not self.process_analyzer:
            return []

        rels = self.process_analyzer.relationships
        chains = self.process_analyzer.get_attack_chains()

        if not rels and not chains:
            return []

        lines = [
            "== PROCESS RELATIONSHIPS ======================================",
            "",
        ]

        if rels:
            lines.append("  Suspicious Parent-Child Relationships:")
            lines.append("")
            for idx, rel in enumerate(rels, 1):
                lines.append(f"  {idx}. [{rel.severity}] {rel.description}")
                lines.append(f"     Parent: {rel.parent_name} (PID: {rel.parent_pid})")
                lines.append(f"     Child : {rel.child_name} (PID: {rel.child_pid})")
                lines.append(f"     MITRE : {rel.mitre_id} ({rel.mitre_technique})")
                if rel.chain:
                    lines.append(f"     Chain : {' -> '.join(rel.chain)}")
                lines.append("")

        # Process tree
        tree_text = self.process_analyzer.get_tree_text()
        if tree_text:
            lines.append("  Process Tree:")
            lines.append("")
            lines.append(tree_text)
            lines.append("")

        return lines

    def _build_attack_chains_section(self) -> list[str]:
        """Build the correlated attack chains section."""
        if not self.process_analyzer:
            return []

        chains = self.process_analyzer.get_attack_chains()
        if not chains:
            return []

        lines = [
            "== CORRELATED ATTACK CHAINS ===================================",
            "",
        ]

        for idx, chain in enumerate(chains, 1):
            depth = chain["depth"]
            chain_str = " -> ".join(chain["chain"])
            lines.append(f"  Chain #{idx} (depth: {depth}):")
            lines.append(f"    {chain_str}")
            lines.append("")

        return lines

    def _build_top_suspicious_section(self) -> list[str]:
        """Build top 5 suspicious processes ranked by effective score."""
        if not self.correlator:
            return []

        groups = self.correlator.get_groups()
        if not groups:
            return []

        # Rank by total effective score per group
        ranked = sorted(
            groups.values(),
            key=lambda g: sum(f.effective_score for f in g.findings),
            reverse=True,
        )[:5]

        lines = [
            "== TOP SUSPICIOUS PROCESSES ===================================",
            "",
        ]

        for idx, group in enumerate(ranked, 1):
            total_eff = sum(f.effective_score for f in group.findings)
            indicators = ", ".join(sorted(group.indicator_types))
            lines.append(f"  {idx}. {group.process}")
            lines.append(f"     Confidence : {group.confidence} ({group.multiplier}x)")
            lines.append(f"     Eff. Score  : +{total_eff}")
            lines.append(f"     Indicators  : {indicators}")
            lines.append(f"     Findings    : {len(group.findings)}")
            mitre = ", ".join(sorted(group.mitre_ids)) if group.mitre_ids else "N/A"
            lines.append(f"     MITRE IDs   : {mitre}")
            lines.append("")

        return lines

    def _build_most_severe_section(self) -> list[str]:
        """Build most severe behaviors section."""
        if not self.findings:
            return []

        # Sort by effective_score descending
        severe = sorted(self.findings, key=lambda f: f.effective_score, reverse=True)[:5]

        lines = [
            "== MOST SEVERE BEHAVIORS ======================================",
            "",
        ]

        for idx, f in enumerate(severe, 1):
            mitre_str = f" [{f.mitre_id}]" if f.mitre_id else ""
            lines.append(f"  {idx}. [{f.severity}] [{f.confidence}]{mitre_str} +{f.effective_score}")
            lines.append(f"     {f.description}")
            lines.append(f"     Process: {f.process}")
            lines.append(f"     Evidence: {f.evidence[:100]}")
            lines.append("")

        return lines

    def _build_correlation_section(self) -> list[str]:
        """Build the behavioral correlation summary."""
        if not self.correlator:
            return []

        groups = self.correlator.get_groups()
        if not groups:
            return []

        lines = [
            "== BEHAVIORAL CORRELATION =====================================",
            "",
        ]

        for proc, group in sorted(
            groups.items(),
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                x[1].confidence, 4
            ),
        ):
            indicators = ", ".join(sorted(group.indicator_types))
            mitre = ", ".join(sorted(group.mitre_ids)) if group.mitre_ids else "N/A"
            lines.extend([
                f"  Process: {proc}",
                f"    Findings   : {len(group.findings)}",
                f"    Indicators : {indicators}",
                f"    Confidence : {group.confidence} ({group.multiplier}x multiplier)",
                f"    MITRE IDs  : {mitre}",
                "",
            ])

        return lines

    def _build_ioc_section(self) -> list[str]:
        """Build the IOC summary section."""
        if not self.ioc_extractor:
            return []

        summary = self.ioc_extractor.get_summary()
        if not summary:
            return []

        lines = [
            "== IOC SUMMARY ================================================",
            "",
        ]

        for category, count in sorted(summary.items()):
            lines.append(f"  {category:20s}: {count} indicator(s)")

        lines.append("")
        lines.append(f"  Full IOC list saved to: results/iocs.txt")
        lines.append("")
        return lines

    def _build_category_section(self) -> list[str]:
        """Build findings by category."""
        categories: dict[str, list] = {}
        for f in self.findings:
            categories.setdefault(f.category, []).append(f)

        if not categories:
            return []

        lines = [
            "== FINDINGS BY CATEGORY =======================================",
            "",
        ]
        for cat, items in categories.items():
            lines.append(f"  [{cat.upper()}] -- {len(items)} finding(s)")
            for item in items:
                mitre_str = f" [{item.mitre_id}]" if item.mitre_id else ""
                lines.append(
                    f"    [{item.severity}] [{item.confidence}]{mitre_str} "
                    f"{item.description}"
                )
                lines.append(f"      Process : {item.process}")
                lines.append(f"      Evidence: {item.evidence}")
                lines.append(f"      Action  : {item.recommendation}")
                lines.append("")

        return lines

    def _build_severity_section(self) -> list[str]:
        """Build severity distribution."""
        sev_counts: dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        if not sev_counts:
            return []

        lines = [
            "== SEVERITY DISTRIBUTION ======================================",
            "",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in sev_counts:
                bar = "#" * sev_counts[sev]
                lines.append(f"  {sev:10s} : {bar} ({sev_counts[sev]})")
        lines.append("")
        return lines

    def _build_score_section(self) -> list[str]:
        """Build score breakdown."""
        lines = [
            "== SCORE BREAKDOWN ============================================",
            "",
        ]

        if self.scorer.category_scores:
            lines.append("  Category Caps:")
            for cat, score in sorted(self.scorer.category_scores.items()):
                cap = self.scorer.category_caps.get(cat, 100)
                lines.append(f"    {cat:15s}: {score:3d}/{cap}")
            lines.append("")

        lines.append("  Per-Rule Scores:")
        for item in self.scorer.breakdown:
            lines.append(
                f"    {item['rule']:25s} +{item['effective_score']:3d} "
                f"({item['confidence']:8s}) {item.get('mitre_id', ''):12s} "
                f"{item['process'][:30]}"
            )
        lines.append(f"\n  {'TOTAL':25s}  {self.scorer.total_score:3d}/100")
        lines.append("")
        return lines

    def _build_risk_section(self) -> list[str]:
        """Build risk assessment."""
        lines = [
            "== RISK ASSESSMENT ============================================",
            "",
        ]
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
        return lines

    def _build_final_report(self) -> str:
        """Create the final_report.txt content."""
        lines = [
            "=" * 70,
            "  DFIR AUTOMATED FORENSIC REPORT  (v1.2)",
            f"  Generated: {timestamp()}",
            "=" * 70,
            "",
        ]

        lines.extend(self._build_executive_summary())
        lines.extend(self._build_most_severe_section())
        lines.extend(self._build_top_suspicious_section())
        lines.extend(self._build_mitre_section())
        lines.extend(self._build_process_relationship_section())
        lines.extend(self._build_attack_chains_section())
        lines.extend(self._build_correlation_section())
        lines.extend(self._build_ioc_section())
        lines.extend(self._build_category_section())
        lines.extend(self._build_severity_section())
        lines.extend(self._build_score_section())
        lines.extend(self._build_risk_section())

        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)

    # ── Public API ───────────────────────────────────────────────────────

    def generate(self) -> None:
        """Write all report files and display a summary."""
        separator("Report Generation")

        # Suspicious findings
        findings_path = RESULTS_DIR / "suspicious_findings.txt"
        findings_path.write_text(self._build_findings_report(), encoding="utf-8")
        console.print(f"[green][+] Findings report saved:[/green] {findings_path}")

        # Final report
        report_path = RESULTS_DIR / "final_report.txt"
        report_path.write_text(self._build_final_report(), encoding="utf-8")
        console.print(f"[green][+] Final report saved  :[/green] {report_path}")

        # Terminal preview
        console.print()
        color = self.scorer.color
        console.print(f"[bold {color}]{'=' * 50}[/bold {color}]")
        console.print(f"[bold {color}]  THREAT SCORE  : {self.scorer.total_score}/100[/bold {color}]")
        console.print(f"[bold {color}]  CLASSIFICATION: {self.scorer.classification}[/bold {color}]")
        console.print(f"[bold {color}]  FINDINGS      : {len(self.findings)}[/bold {color}]")

        # Show confidence distribution
        conf_counts: dict[str, int] = {}
        for f in self.findings:
            conf_counts[f.confidence] = conf_counts.get(f.confidence, 0) + 1
        if conf_counts:
            conf_str = " | ".join(
                f"{k}: {v}" for k, v in sorted(conf_counts.items())
            )
            console.print(f"[bold {color}]  CONFIDENCE    : {conf_str}[/bold {color}]")

        console.print(f"[bold {color}]{'=' * 50}[/bold {color}]")
        console.print()

        logger.info("Reports generated successfully")
