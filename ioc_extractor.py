"""
ioc_extractor.py -- Indicator of Compromise extraction engine.

Scans raw Volatility output files for actionable IOCs and saves them
to results/iocs.txt for use in threat intel feeds and SIEM rules.
"""

import re
from pathlib import Path

from utils import console, RESULTS_DIR, OUTPUT_DIR, setup_logging, separator

logger = setup_logging()


class IOCExtractor:
    """Extract IOCs from raw Volatility output and parsed findings."""

    def __init__(self) -> None:
        self.iocs: dict[str, set[str]] = {
            "executables": set(),
            "scripts": set(),
            "command_lines": set(),
            "ip_addresses": set(),
            "ports": set(),
            "temp_paths": set(),
            "urls": set(),
        }

    # ── Extraction methods ───────────────────────────────────────────────

    def _extract_executables(self, raw_cmdline: str, raw_psscan: str) -> None:
        """Extract unique executable names."""
        exe_re = re.compile(r"\b(\S+\.exe)\b", re.IGNORECASE)
        for text in (raw_cmdline, raw_psscan):
            for m in exe_re.finditer(text):
                name = m.group(1)
                if "\\" in name:
                    name = name.rsplit("\\", 1)[-1]
                if "/" in name:
                    name = name.rsplit("/", 1)[-1]
                if len(name) > 4:  # skip noise like ".exe"
                    self.iocs["executables"].add(name)

    def _extract_scripts(self, raw_cmdline: str) -> None:
        """Extract script file references."""
        script_re = re.compile(
            r"\b(\S+\.(?:vbs|vbe|wsf|ps1|bat|cmd|js|hta))\b", re.IGNORECASE
        )
        for m in script_re.finditer(raw_cmdline):
            self.iocs["scripts"].add(m.group(1))

    def _extract_command_lines(self, raw_cmdline: str) -> None:
        """Extract suspicious command lines."""
        suspicious_keywords = [
            "powershell", "invoke-", "downloadstring", "iex(",
            "wscript", "cscript", "cmd /c", "cmd.exe /c",
            "certutil", "bitsadmin", "regsvr32", "mshta",
            "%temp%", "\\temp\\", "bypass", "-enc ", "-encoded",
            "hidden", "-nop ", "-noni", "wget", "curl",
        ]
        for line in raw_cmdline.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in suspicious_keywords):
                # Clean up: extract just the args portion
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    self.iocs["command_lines"].add(parts[-1].strip())
                elif line.strip():
                    self.iocs["command_lines"].add(line.strip())

    def _extract_ip_addresses(self, raw_netstat: str, raw_netscan: str) -> None:
        """Extract IP addresses from network output."""
        ip_re = re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        )
        # Exclude common local/loopback addresses
        exclude = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "*"}

        for text in (raw_netstat, raw_netscan):
            for m in ip_re.finditer(text):
                ip = m.group(1)
                if ip not in exclude and not ip.startswith("0."):
                    self.iocs["ip_addresses"].add(ip)

    def _extract_ports(self, raw_netstat: str, raw_netscan: str) -> None:
        """Extract non-standard ports."""
        common_ports = {80, 443, 135, 139, 445, 53, 88, 389, 636, 0}
        port_re = re.compile(r":(\d{1,5})\b")

        for text in (raw_netstat, raw_netscan):
            for m in port_re.finditer(text):
                try:
                    port = int(m.group(1))
                except ValueError:
                    continue
                if port not in common_ports and 1 <= port <= 65535:
                    self.iocs["ports"].add(str(port))

    def _extract_temp_paths(self, raw_cmdline: str) -> None:
        """Extract suspicious Temp/AppData paths."""
        path_re = re.compile(
            r"((?:[A-Za-z]:\\|\\\\)(?:\S*(?:Temp|AppData|tmp)\S*))", re.IGNORECASE
        )
        for m in path_re.finditer(raw_cmdline):
            self.iocs["temp_paths"].add(m.group(1))

    # ── Public API ───────────────────────────────────────────────────────

    def extract(self, raw_text: dict = None) -> dict[str, set[str]]:
        """Run all extraction methods.

        Parameters
        ----------
        raw_text : dict
            Raw file contents from OutputParser.raw_text.
        """
        separator("IOC Extraction")
        console.print("[bold cyan][*] Extracting indicators of compromise...[/bold cyan]\n")

        if raw_text is None:
            raw_text = {}

        raw_cmdline = raw_text.get("cmdline", "") or self._read_raw("windows_cmdline.txt")
        raw_psscan  = raw_text.get("psscan", "")  or self._read_raw("windows_psscan.txt")
        raw_netstat = raw_text.get("netstat", "") or self._read_raw("windows_netstat.txt")
        raw_netscan = raw_text.get("netscan", "") or self._read_raw("windows_netscan.txt")

        self._extract_executables(raw_cmdline, raw_psscan)
        self._extract_scripts(raw_cmdline)
        self._extract_command_lines(raw_cmdline)
        self._extract_ip_addresses(raw_netstat, raw_netscan)
        self._extract_ports(raw_netstat, raw_netscan)
        self._extract_temp_paths(raw_cmdline)

        # Display summary
        total = sum(len(v) for v in self.iocs.values())
        for category, items in self.iocs.items():
            if items:
                console.print(f"  [dim]{category:16s} -> {len(items)} IOC(s)[/dim]")
        console.print(f"\n[green][+] Extracted {total} total IOCs[/green]")

        # Save
        self._save()

        logger.info("IOC extraction complete -- %d IOCs", total)
        return self.iocs

    @staticmethod
    def _read_raw(filename: str) -> str:
        """Read raw output file directly."""
        path = OUTPUT_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return ""

    def _save(self) -> None:
        """Save IOCs to results/iocs.txt."""
        path = RESULTS_DIR / "iocs.txt"
        lines = [
            "=" * 60,
            "  INDICATORS OF COMPROMISE (IOCs)",
            "=" * 60,
            "",
        ]

        section_titles = {
            "executables": "EXECUTABLE FILES",
            "scripts": "SCRIPT FILES",
            "command_lines": "SUSPICIOUS COMMAND LINES",
            "ip_addresses": "IP ADDRESSES",
            "ports": "NON-STANDARD PORTS",
            "temp_paths": "SUSPICIOUS TEMP PATHS",
            "urls": "URLS",
        }

        for key, title in section_titles.items():
            items = self.iocs.get(key, set())
            if items:
                lines.append(f"--- {title} ---")
                for item in sorted(items):
                    lines.append(f"  {item}")
                lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green][+] IOCs saved to:[/green] {path}")

    def get_summary(self) -> dict[str, int]:
        """Return a count summary for reporting."""
        return {k: len(v) for k, v in self.iocs.items() if v}
