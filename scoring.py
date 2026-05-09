"""
scoring.py — Threat scoring engine.

Aggregates individual finding scores into an overall threat score,
classifies the threat level, and persists the result.
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

    def calculate(self, findings: list) -> int:
        """Sum scores from all findings and classify the result.

        Parameters
        ----------
        findings : list[Finding]
            Output from ``ThreatDetector.analyze()``.

        Returns
        -------
        int
            Clamped total threat score (0–100).
        """
        separator("Threat Scoring")

        for f in findings:
            self.breakdown.append({
                "rule": f.rule_id,
                "process": f.process,
                "points": f.score,
            })
            self.total_score += f.score

        # Clamp to 0–100
        self.total_score = min(self.total_score, 100)

        # Classify
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

        # Display
        console.print(f"[bold {self.color}]Threat Score : {self.total_score}/100[/bold {self.color}]")
        console.print(f"[bold {self.color}]Classification: {self.classification}[/bold {self.color}]\n")

        if self.breakdown:
            console.print("[dim]Score breakdown:[/dim]")
            for item in self.breakdown:
                console.print(f"  [dim]• {item['rule']:25s} +{item['points']:3d}  ({item['process']})[/dim]")
            console.print()

        # Persist
        self._save()

        logger.info("Threat score: %d — %s", self.total_score, self.classification)
        return self.total_score

    def _save(self) -> None:
        """Write the threat score to results/threat_score.txt."""
        path = RESULTS_DIR / "threat_score.txt"
        lines = [
            f"Threat Score : {self.total_score}/100",
            f"Classification: {self.classification}",
            "",
            "Breakdown:",
        ]
        for item in self.breakdown:
            lines.append(f"  {item['rule']:25s} +{item['points']:3d}  ({item['process']})")
        path.write_text("\n".join(lines), encoding="utf-8")
