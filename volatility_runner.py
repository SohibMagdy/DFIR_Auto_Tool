"""
volatility_runner.py — Volatility 3 plugin execution engine.

Handles subprocess invocation of Volatility 3 plugins, captures output,
and writes raw results to individual text files inside the output/ directory.
"""

import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from utils import (
    console,
    OUTPUT_DIR,
    VOL_COMMAND,
    setup_logging,
    separator,
    timestamp,
)

logger = setup_logging()


class VolatilityRunner:
    """Execute Volatility 3 plugins against a memory dump and persist output."""

    # ── Plugin registry ──────────────────────────────────────────────────
    # Maps a friendly name to (volatility plugin name, output filename).
    PLUGINS: dict[str, tuple[str, str]] = {
        "System Info":      ("windows.info",     "windows_info.txt"),
        "Command Lines":    ("windows.cmdline",  "windows_cmdline.txt"),
        "Network Stat":     ("windows.netstat",  "windows_netstat.txt"),
        "Network Scan":     ("windows.netscan",  "windows_netscan.txt"),
        "Malfind":          ("windows.malfind",  "windows_malfind.txt"),
        "Process Scan":     ("windows.psscan",   "windows_psscan.txt"),
    }

    # Plugins that may be unavailable in some Volatility builds
    OPTIONAL_PLUGINS: set[str] = {"Network Scan", "Network Stat"}

    def __init__(self, memory_dump: str) -> None:
        """
        Parameters
        ----------
        memory_dump : str
            Absolute or relative path to the Windows memory dump file.
        """
        self.memory_dump = Path(memory_dump).resolve()
        self.results: dict[str, dict] = {}  # plugin_name -> {status, output_path, duration, error}

        if not self.memory_dump.exists():
            console.print(f"[bold red]✖ Memory dump not found: {self.memory_dump}[/bold red]")
            raise FileNotFoundError(f"Memory dump not found: {self.memory_dump}")

        logger.info("VolatilityRunner initialized — dump: %s", self.memory_dump)

    # ── Private helpers ──────────────────────────────────────────────────

    def _build_command(self, plugin: str) -> list[str]:
        """Build the subprocess command list for a given plugin."""
        return [
            VOL_COMMAND,
            "-f", str(self.memory_dump),
            plugin,
        ]

    def _run_single_plugin(
        self, friendly_name: str, plugin: str, output_file: str
    ) -> dict:
        """Run one plugin, write its output, and return a status dict."""
        output_path = OUTPUT_DIR / output_file
        cmd = self._build_command(plugin)
        start = time.time()

        try:
            logger.info("Running plugin: %s (%s)", friendly_name, plugin)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 min timeout per plugin
            )
            duration = round(time.time() - start, 2)

            # Combine stdout + stderr (Volatility may write progress to stderr)
            output = result.stdout
            if result.stderr:
                output += f"\n--- stderr ---\n{result.stderr}"

            # Persist raw output
            output_path.write_text(output, encoding="utf-8")

            if result.returncode != 0:
                logger.warning(
                    "Plugin %s exited with code %d", plugin, result.returncode
                )
                return {
                    "status": "warning",
                    "output_path": str(output_path),
                    "duration": duration,
                    "error": f"Exit code {result.returncode}",
                }

            logger.info("Plugin %s completed in %.2fs", plugin, duration)
            return {
                "status": "success",
                "output_path": str(output_path),
                "duration": duration,
                "error": None,
            }

        except subprocess.TimeoutExpired:
            duration = round(time.time() - start, 2)
            logger.error("Plugin %s timed out after %ds", plugin, 600)
            return {
                "status": "timeout",
                "output_path": str(output_path) if output_path.exists() else None,
                "duration": duration,
                "error": "Execution timed out (600s)",
            }

        except FileNotFoundError:
            logger.error(
                "Volatility command '%s' not found — is it installed and on PATH?",
                VOL_COMMAND,
            )
            return {
                "status": "error",
                "output_path": None,
                "duration": 0,
                "error": f"Command '{VOL_COMMAND}' not found on PATH",
            }

        except Exception as exc:
            duration = round(time.time() - start, 2)
            logger.error("Plugin %s failed: %s", plugin, exc)
            return {
                "status": "error",
                "output_path": None,
                "duration": duration,
                "error": str(exc),
            }

    # ── Public API ───────────────────────────────────────────────────────

    def run_all(self) -> dict[str, dict]:
        """Execute every registered plugin with a Rich progress display.

        Optional plugins that fail are reported but do not count as
        fatal errors.

        Returns
        -------
        dict
            Mapping of friendly plugin name → status dict.
        """
        separator("Volatility 3 — Plugin Execution")
        console.print(f"[dim]Memory dump:[/dim] [bold]{self.memory_dump}[/bold]")
        console.print(f"[dim]Timestamp  :[/dim] [bold]{timestamp()}[/bold]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            overall = progress.add_task("Running plugins...", total=len(self.PLUGINS))

            for friendly_name, (plugin, out_file) in self.PLUGINS.items():
                progress.update(overall, description=f"Running: {friendly_name}")
                result = self._run_single_plugin(friendly_name, plugin, out_file)
                self.results[friendly_name] = result

                # If an optional plugin failed, log it but keep going
                if (result["status"] in ("error", "warning")
                        and friendly_name in self.OPTIONAL_PLUGINS):
                    logger.info(
                        "Optional plugin '%s' unavailable — skipped gracefully",
                        friendly_name,
                    )

                progress.advance(overall)

        self._display_summary()
        return self.results

    def run_single(self, friendly_name: str) -> Optional[dict]:
        """Run a single plugin by its friendly name.

        Returns None if the friendly name is not recognized.
        """
        if friendly_name not in self.PLUGINS:
            console.print(f"[bold red]✖ Unknown plugin: {friendly_name}[/bold red]")
            return None

        plugin, out_file = self.PLUGINS[friendly_name]
        result = self._run_single_plugin(friendly_name, plugin, out_file)
        self.results[friendly_name] = result
        return result

    def _display_summary(self) -> None:
        """Print a summary table of all plugin execution results."""
        separator("Execution Summary")

        table = Table(
            title="Plugin Results",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
        )
        table.add_column("Plugin", style="bold white", min_width=18)
        table.add_column("Status", justify="center", min_width=10)
        table.add_column("Duration", justify="right", min_width=10)
        table.add_column("Details", style="dim")

        status_styles = {
            "success": "[bold green]✔ SUCCESS[/bold green]",
            "warning": "[bold yellow]⚠ WARNING[/bold yellow]",
            "timeout": "[bold red]⏱ TIMEOUT[/bold red]",
            "error":   "[bold red]✖ ERROR[/bold red]",
        }

        for name, info in self.results.items():
            table.add_row(
                name,
                status_styles.get(info["status"], info["status"]),
                f"{info['duration']}s",
                info.get("error") or "—",
            )

        console.print(table)
