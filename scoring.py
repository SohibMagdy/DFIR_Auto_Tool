"""
scoring.py -- Smart threat scoring engine (v1.1).

Aggregates findings using correlation-weighted effective_scores,
applies per-category caps, deduplicates score inflation, and
produces a realistic threat score.

v1.1 changes:
  - Category score caps (Memory: 40, Process: 35, Network: 25)
  - Uses effective_score (set by correlator) instead of raw score
  - Duplicate rule suppression: only highest score per rule_id per category
  - Realistic normalization clamped to 0-100
"""

from utils import console, load_rules, RESULTS_DIR, setup_logging, separator

logger = setup_logging()


class ThreatScorer:
    """Calculate and classify the aggregate threat score."""

    def __init__(self) -> None:
        self.rules = load_rules()
        self.total_score: int = 0
        self.classification: str = "NORMAL"
        self.color: str = "green"
        self.breakdown: list[dict] = []
        self.category_scores: dict[str, int] = {}
        self.category_caps: dict[str, int] = self.rules.get("scoring_caps", {
            "Memory": 40, "Process": 35, "Network": 25,
        })

    def calculate(self, findings: list) -> int:
        """Calculate the threat score from correlated findings.

        Uses effective_score (set by the correlator) which factors in
        the confidence multiplier. Applies per-category caps to prevent
        single-category inflation.

        Parameters
        ----------
        findings : list[Finding]

        Returns
        -------
        int
            Clamped total threat score (0-100).
        """
        separator("Threat Scoring")

        # ── De-duplicate: keep highest effective_score per (rule_id, category) ──
        best_per_rule: dict[str, dict] = {}  # "rule|category" -> breakdown dict

        for f in findings:
            key = f"{f.rule_id}|{f.category}"
            eff = f.effective_score if f.effective_score else f.score
            entry = {
                "rule": f.rule_id,
                "process": f.process,
                "category": f.category,
                "raw_score": f.score,
                "effective_score": eff,
                "confidence": f.confidence,
                "mitre_id": f.mitre_id,
            }
            if key not in best_per_rule or eff > best_per_rule[key]["effective_score"]:
                best_per_rule[key] = entry

        self.breakdown = list(best_per_rule.values())

        # ── Sum per category with caps ───────────────────────────────────
        cat_totals: dict[str, int] = {}
        for item in self.breakdown:
            cat = item["category"]
            cat_totals.setdefault(cat, 0)
            cat_totals[cat] += item["effective_score"]

        # Apply caps
        for cat, total in cat_totals.items():
            cap = self.category_caps.get(cat, 100)
            capped = min(total, cap)
            self.category_scores[cat] = capped
            if total > cap:
                logger.info(
                    "Category '%s' capped: %d -> %d", cat, total, capped
                )

        self.total_score = min(sum(self.category_scores.values()), 100)

        # ── Classify ─────────────────────────────────────────────────────
        thresholds = self.rules["scoring_thresholds"]
        if self.total_score <= thresholds["normal"]["max"]:
            self.classification = thresholds["normal"]["label"]
            self.color = thresholds["normal"]["color"]
        elif self.total_score <= thresholds["suspicious"]["max"]:
            self.classification = thresholds["suspicious"]["label"]
            self.color = thresholds["suspicious"]["color"]
        else:
            self.classification = thresholds["highly_suspicious"]["label"]
            self.color = thresholds["highly_suspicious"]["color"]

        # ── Display ──────────────────────────────────────────────────────
        console.print(
            f"[bold {self.color}]Threat Score : {self.total_score}/100[/bold {self.color}]"
        )
        console.print(
            f"[bold {self.color}]Classification: {self.classification}[/bold {self.color}]\n"
        )

        if self.category_scores:
            console.print("[dim]Category breakdown (with caps):[/dim]")
            for cat, score in sorted(self.category_scores.items()):
                cap = self.category_caps.get(cat, 100)
                console.print(f"  [dim]{cat:10s}: {score:3d}/{cap}[/dim]")
            console.print()

        if self.breakdown:
            console.print("[dim]Score details (de-duplicated, highest per rule):[/dim]")
            for item in self.breakdown:
                conf = item["confidence"]
                mitre = item["mitre_id"] or ""
                console.print(
                    f"  [dim]  {item['rule']:25s} "
                    f"+{item['effective_score']:3d} "
                    f"({conf:8s}) "
                    f"{mitre:12s} "
                    f"{item['process'][:30]}[/dim]"
                )
            console.print()

        self._save()
        logger.info("Threat score: %d -- %s", self.total_score, self.classification)
        return self.total_score

    def _save(self) -> None:
        """Write the threat score to results/threat_score.txt."""
        path = RESULTS_DIR / "threat_score.txt"
        lines = [
            f"Threat Score : {self.total_score}/100",
            f"Classification: {self.classification}",
            "",
            "Category Breakdown:",
        ]
        for cat, score in sorted(self.category_scores.items()):
            cap = self.category_caps.get(cat, 100)
            lines.append(f"  {cat:10s}: {score:3d}/{cap}")

        lines.append("")
        lines.append("Score Details:")
        for item in self.breakdown:
            lines.append(
                f"  {item['rule']:25s} +{item['effective_score']:3d} "
                f"({item['confidence']:8s}) {item.get('mitre_id', ''):12s} "
                f"{item['process']}"
            )
        lines.append(f"\n  {'TOTAL':25s}  {self.total_score:3d}/100")
        path.write_text("\n".join(lines), encoding="utf-8")
