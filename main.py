"""
main.py — DFIR Automation Tool entry point.

Orchestrates the full forensic analysis pipeline:
  1. Check plugin availability
  2. Run Volatility 3 plugins against a memory dump
  3. Parse raw outputs into structured data
  4. Detect suspicious indicators
  5. Calculate threat score
  6. Generate forensic reports
"""

import sys
import argparse
import time

from utils import (
    console,
    display_banner,
    init_directories,
    setup_logging,
    separator,
    timestamp,
)
from volatility_runner import VolatilityRunner
from parser import OutputParser
from detector import ThreatDetector
from scoring import ThreatScorer
from report_generator import ReportGenerator


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(
        description="DFIR Automation Tool — Memory Forensics with Volatility 3",
    )
    ap.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the Windows memory dump file",
    )
    ap.add_argument(
        "--skip-vol",
        action="store_true",
        help="Skip Volatility execution (use existing output/ files)",
    )
    ap.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    return ap.parse_args()


def main() -> None:
    """Run the full DFIR analysis pipeline."""
    args = parse_args()

    # ── Setup ────────────────────────────────────────────────────────────
    import logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(log_level)

    init_directories()
    display_banner()

    console.print(f"[dim]Analysis started at {timestamp()}[/dim]")
    console.print(f"[dim]Memory dump: {args.file}[/dim]\n")
    pipeline_start = time.time()

    # ── Stage 1: Volatility Execution ────────────────────────────────────
    if args.skip_vol:
        console.print("[yellow]⏭ Skipping Volatility execution (--skip-vol)[/yellow]\n")
    else:
        try:
            runner = VolatilityRunner(args.file)
            results = runner.run_all()

            # Abort if every plugin failed
            if all(r["status"] == "error" for r in results.values()):
                console.print("[bold red]✖ All plugins failed. Aborting.[/bold red]")
                sys.exit(1)

            # Report skipped / unavailable plugins gracefully
            for name, info in results.items():
                if info["status"] in ("error", "warning"):
                    console.print(
                        f"[yellow]⚠ Plugin '{name}' had issues — "
                        f"detection will proceed with available data[/yellow]"
                    )

        except FileNotFoundError:
            console.print("[bold red]✖ Cannot proceed without a valid memory dump.[/bold red]")
            sys.exit(1)
        except Exception as exc:
            logger.exception("Unexpected error during Volatility execution")
            console.print(f"[bold red]✖ Fatal error: {exc}[/bold red]")
            sys.exit(1)

    # ── Stage 2: Parse Outputs ───────────────────────────────────────────
    separator("Output Parsing")
    parser = OutputParser()
    parsed_data = parser.parse_all()

    # ── Stage 3: Detect Threats ──────────────────────────────────────────
    detector = ThreatDetector()
    findings = detector.analyze(parsed_data, raw_text=parser.raw_text)

    # ── Stage 4: Score ───────────────────────────────────────────────────
    scorer = ThreatScorer()
    scorer.calculate(findings)

    # ── Stage 5: Generate Reports ────────────────────────────────────────
    reporter = ReportGenerator(findings, scorer)
    reporter.generate()

    # ── Done ─────────────────────────────────────────────────────────────
    elapsed = round(time.time() - pipeline_start, 2)
    separator("Pipeline Complete")
    console.print(f"[bold green]✔ Analysis finished in {elapsed}s[/bold green]")
    console.print("[dim]Check the results/ directory for full reports.[/dim]\n")


if __name__ == "__main__":
    main()
