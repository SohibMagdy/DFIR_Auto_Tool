"""
parser.py — Raw Volatility output parser.

Reads the text files produced by volatility_runner and converts them
into structured Python data that the detector can consume.

Design principle:
  Volatility 3 output formats vary wildly between plugins and versions.
  Instead of relying solely on fragile column-splitting, we use a
  **dual-mode** approach:
    1. Structured parsing (best-effort table -> list[dict])
    2. Raw text preservation (always available for regex/keyword scanning)

  The detector can use whichever representation is more reliable for
  each detection rule.
"""

import re
from pathlib import Path
from typing import Optional

from utils import OUTPUT_DIR, console, setup_logging

logger = setup_logging()


class OutputParser:
    """Parse raw Volatility 3 plugin output files into structured data."""

    def __init__(self) -> None:
        # Structured records per plugin
        self.parsed_data: dict[str, list[dict]] = {}
        # Raw text per plugin (always populated — the fallback for detection)
        self.raw_text: dict[str, str] = {}

    # ── Generic helpers ──────────────────────────────────────────────────

    @staticmethod
    def _read_file(filepath: Path) -> Optional[str]:
        """Read a file and return its content, or None if missing/empty."""
        if not filepath.exists():
            logger.warning("Output file not found: %s", filepath)
            return None
        content = filepath.read_text(encoding="utf-8", errors="replace")
        return content if content.strip() else None

    @staticmethod
    def _parse_table_output(raw: str) -> list[dict]:
        """Best-effort parse of Volatility's whitespace-delimited tables.

        Strategy:
          1. Find the header line (first line that looks like column names).
          2. Detect column boundaries from the header positions.
          3. Slice each data row by those boundaries.

        Falls back to simple whitespace splitting if boundary detection
        fails.  Returns an empty list if parsing can't find anything.
        """
        lines = raw.strip().splitlines()
        if not lines:
            return []

        # Strip Volatility progress messages (lines starting with *)
        lines = [l for l in lines if l.strip() and not l.strip().startswith("*")]
        if len(lines) < 2:
            return []

        # ── Locate header + separator ────────────────────────────────────
        header_idx = 0
        separator_idx = None

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Separator is a line of dashes / tabs
            if stripped and set(stripped.replace(" ", "").replace("\t", "")) <= {"-"}:
                separator_idx = i
                header_idx = i - 1 if i > 0 else 0
                break

        header_line = lines[header_idx]

        # ── Detect column start positions from header ────────────────────
        # Columns in Vol3 are separated by \t or multiple spaces
        col_starts: list[int] = []
        in_space = True
        for pos, ch in enumerate(header_line):
            if ch not in (" ", "\t"):
                if in_space:
                    col_starts.append(pos)
                    in_space = False
            else:
                in_space = True

        headers = []
        for j, start in enumerate(col_starts):
            end = col_starts[j + 1] if j + 1 < len(col_starts) else len(header_line)
            headers.append(header_line[start:end].strip())

        if not headers:
            return []

        # ── Parse data rows ──────────────────────────────────────────────
        data_start = (separator_idx + 1) if separator_idx is not None else (header_idx + 1)
        records: list[dict] = []

        for line in lines[data_start:]:
            stripped = line.strip()
            if not stripped:
                continue
            # Skip repeated separator lines
            if set(stripped.replace(" ", "").replace("\t", "")) <= {"-"}:
                continue
            # Skip hex-dump lines (e.g. "0x1234abcd  4d 5a 90 00 ...")
            if re.match(r"^0x[0-9a-fA-F]+\s", stripped):
                continue

            # Slice by column positions
            values = []
            for j, start in enumerate(col_starts):
                end = col_starts[j + 1] if j + 1 < len(col_starts) else len(line)
                val = line[start:end].strip() if start < len(line) else ""
                values.append(val)

            record = {}
            for j, header in enumerate(headers):
                record[header] = values[j] if j < len(values) else ""
            # Also store the full original line for fallback searches
            record["_raw_line"] = line
            records.append(record)

        return records

    # ── Plugin-specific parsers ──────────────────────────────────────────

    def parse_info(self) -> list[dict]:
        """Parse windows.info output (key-value pairs)."""
        raw = self._read_file(OUTPUT_DIR / "windows_info.txt")
        if not raw:
            return []

        self.raw_text["info"] = raw
        records = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("*") or line.startswith("Volatility"):
                continue
            # Vol3 info uses tab separation: "Variable\tValue"
            if "\t" in line:
                parts = line.split("\t", 1)
                records.append({"Variable": parts[0].strip(), "Value": parts[1].strip()})
            elif ":" in line:
                parts = line.split(":", 1)
                records.append({"Variable": parts[0].strip(), "Value": parts[1].strip()})

        self.parsed_data["info"] = records
        logger.info("Parsed %d info entries", len(records))
        console.print(f"  [dim]windows.info     -> {len(records)} records[/dim]")
        return records

    def parse_cmdline(self) -> list[dict]:
        """Parse windows.cmdline output.

        Vol3 cmdline format:
          PID  Process  Args
          1234 cmd.exe  cmd.exe /c whoami
        """
        raw = self._read_file(OUTPUT_DIR / "windows_cmdline.txt")
        if not raw:
            return []

        self.raw_text["cmdline"] = raw
        records = self._parse_table_output(raw)

        # Normalise common column name variants
        for rec in records:
            # Ensure we always have 'Process' and 'Args' keys
            if "Process" not in rec:
                for alt in ("Name", "ImageFileName"):
                    if alt in rec:
                        rec["Process"] = rec[alt]
                        break
            if "Args" not in rec:
                for alt in ("CommandLine", "Cmd", "Command line"):
                    if alt in rec:
                        rec["Args"] = rec[alt]
                        break
            # Fallback — use the raw line as Args for keyword searches
            if not rec.get("Args"):
                rec["Args"] = rec.get("_raw_line", "")

        self.parsed_data["cmdline"] = records
        logger.info("Parsed %d cmdline entries", len(records))
        console.print(f"  [dim]windows.cmdline  -> {len(records)} records[/dim]")
        return records

    def parse_netscan(self) -> list[dict]:
        """Parse windows.netscan output (kept for future support)."""
        raw = self._read_file(OUTPUT_DIR / "windows_netscan.txt")
        if not raw:
            logger.info("netscan output not available — skipping")
            console.print("  [dim]windows.netscan  -> [yellow]not available (skipped)[/yellow][/dim]")
            return []

        self.raw_text["netscan"] = raw
        records = self._parse_table_output(raw)
        self.parsed_data["netscan"] = records
        logger.info("Parsed %d netscan entries", len(records))
        console.print(f"  [dim]windows.netscan  -> {len(records)} records[/dim]")
        return records

    def parse_netstat(self) -> list[dict]:
        """Parse windows.netstat output."""
        raw = self._read_file(OUTPUT_DIR / "windows_netstat.txt")
        if not raw:
            logger.info("netstat output not available — skipping")
            console.print("  [dim]windows.netstat  -> [yellow]not available (skipped)[/yellow][/dim]")
            return []

        self.raw_text["netstat"] = raw
        records = self._parse_table_output(raw)
        self.parsed_data["netstat"] = records
        logger.info("Parsed %d netstat entries", len(records))
        console.print(f"  [dim]windows.netstat  -> {len(records)} records[/dim]")
        return records

    def parse_malfind(self) -> list[dict]:
        """Parse windows.malfind output.

        Malfind output is complex — each entry spans multiple lines:
          - A table row with PID, Process, Start VPN, End VPN, Protection, etc.
          - Followed by hex dump lines and/or disassembly

        We parse both the table rows AND capture the full raw text for
        each entry block so the detector can search hex dumps for MZ headers.
        """
        raw = self._read_file(OUTPUT_DIR / "windows_malfind.txt")
        if not raw:
            return []

        self.raw_text["malfind"] = raw

        # ── Strategy 1: table parse for structured fields ────────────────
        records = self._parse_table_output(raw)

        # Normalise column names
        for rec in records:
            if "Process" not in rec:
                for alt in ("Name", "ImageFileName"):
                    if alt in rec:
                        rec["Process"] = rec[alt]
                        break

        # ── Strategy 2: block-based parsing ──────────────────────────────
        # Some Vol3 malfind outputs use block format instead of clean tables.
        # We'll also extract per-process blocks and attach hex content.
        if not records:
            # Fallback: treat entire lines as potential record sources
            lines = raw.splitlines()
            current_record = None
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                # Detect data rows that look like: PID  Process  ...  Protection
                # A heuristic: starts with a number (PID)
                if re.match(r"^\d+\s+\S+", stripped) and "PAGE_" in raw:
                    if current_record:
                        records.append(current_record)
                    parts = stripped.split()
                    current_record = {
                        "PID": parts[0] if len(parts) > 0 else "",
                        "Process": parts[1] if len(parts) > 1 else "",
                        "_raw_line": stripped,
                        "_hex_block": "",
                    }
                elif current_record and re.match(r"^0x[0-9a-fA-F]", stripped):
                    current_record["_hex_block"] += stripped + "\n"
                elif current_record:
                    current_record["_raw_line"] += " " + stripped

            if current_record:
                records.append(current_record)

        # Enrich all records with raw-text flags
        for rec in records:
            raw_line = rec.get("_raw_line", "")
            protection = rec.get("Protection", "")
            combined = f"{raw_line} {protection}"
            rec["is_rwx"] = "PAGE_EXECUTE_READWRITE" in combined

        self.parsed_data["malfind"] = records
        logger.info("Parsed %d malfind entries", len(records))
        console.print(f"  [dim]windows.malfind  -> {len(records)} records[/dim]")
        return records

    def parse_psscan(self) -> list[dict]:
        """Parse windows.psscan output."""
        raw = self._read_file(OUTPUT_DIR / "windows_psscan.txt")
        if not raw:
            return []

        self.raw_text["psscan"] = raw
        records = self._parse_table_output(raw)

        for rec in records:
            if "Process" not in rec:
                for alt in ("ImageFileName", "Name"):
                    if alt in rec:
                        rec["Process"] = rec[alt]
                        break

        self.parsed_data["psscan"] = records
        logger.info("Parsed %d psscan entries", len(records))
        console.print(f"  [dim]windows.psscan   -> {len(records)} records[/dim]")
        return records

    # ── Aggregate ────────────────────────────────────────────────────────

    def parse_all(self) -> dict[str, list[dict]]:
        """Run every parser and return the consolidated data dict."""
        console.print("[bold cyan][*] Parsing plugin outputs...[/bold cyan]\n")

        self.parse_info()
        self.parse_cmdline()
        self.parse_netstat()
        self.parse_netscan()
        self.parse_malfind()
        self.parse_psscan()

        total = sum(len(v) for v in self.parsed_data.values())
        console.print(
            f"\n[green]✔ Parsed {total} total records across "
            f"{len(self.parsed_data)} plugins[/green]"
        )

        # Show raw text availability
        raw_plugins = [k for k, v in self.raw_text.items() if v]
        if raw_plugins:
            console.print(
                f"[dim]  Raw text available for: {', '.join(raw_plugins)}[/dim]\n"
            )

        return self.parsed_data
