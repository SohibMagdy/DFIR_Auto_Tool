"""
ioc_extractor.py -- Indicator of Compromise extraction engine (v1.2).

Scans raw Volatility output files for actionable IOCs and saves them
to results/iocs.txt for use in threat intel feeds and SIEM rules.

v1.2 changes:
  - Structured IOCEntry objects with PID, process, category enrichment
  - Cross-references IOCs with findings for severity-based categorization
  - Enhanced output format with process ownership
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from utils import console, RESULTS_DIR, OUTPUT_DIR, setup_logging, separator

logger = setup_logging()


@dataclass
class IOCEntry:
    """Structured IOC with enrichment metadata."""
    value: str
    ioc_type: str           # executable, script, ip, port, path, command_line
    source: str = ""        # cmdline, psscan, malfind, netscan, etc.
    process: str = ""       # Owning process name
    pid: str = ""           # Associated PID
    related_cmdline: str = ""  # Full command line if available
    category: str = "informational"  # informational, suspicious, malicious


class IOCExtractor:
    """Extract IOCs from raw Volatility output and parsed findings."""

    def __init__(self) -> None:
        self.entries: list[IOCEntry] = []
        # Legacy dict for backward compatibility with summary
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

    def _extract_executables(self, parsed_cmdline: list, raw_psscan: str) -> None:
        """Extract unique executable names with process/PID enrichment."""
        seen: set[str] = set()

        # From structured cmdline records (best -- has PID + process)
        for rec in parsed_cmdline:
            args = rec.get("Args", rec.get("_raw_line", ""))
            exe_re = re.compile(r"\b(\S+\.exe)\b", re.IGNORECASE)
            for m in exe_re.finditer(args):
                name = m.group(1)
                if "\\" in name:
                    name = name.rsplit("\\", 1)[-1]
                if "/" in name:
                    name = name.rsplit("/", 1)[-1]
                if len(name) <= 4 or name.lower() in seen:
                    continue
                seen.add(name.lower())
                self.iocs["executables"].add(name)
                self.entries.append(IOCEntry(
                    value=name, ioc_type="executable", source="cmdline",
                    process=rec.get("Process", ""), pid=rec.get("PID", ""),
                    related_cmdline=args[:200],
                ))

        # From raw psscan
        exe_re = re.compile(r"\b(\S+\.exe)\b", re.IGNORECASE)
        for m in exe_re.finditer(raw_psscan):
            name = m.group(1)
            if "\\" in name:
                name = name.rsplit("\\", 1)[-1]
            if "/" in name:
                name = name.rsplit("/", 1)[-1]
            if len(name) > 4 and name.lower() not in seen:
                seen.add(name.lower())
                self.iocs["executables"].add(name)
                self.entries.append(IOCEntry(
                    value=name, ioc_type="executable", source="psscan",
                ))

    def _extract_scripts(self, parsed_cmdline: list, raw_cmdline: str) -> None:
        """Extract script file references with process context."""
        script_re = re.compile(
            r"\b(\S+\.(?:vbs|vbe|wsf|ps1|bat|cmd|js|hta))\b", re.IGNORECASE
        )
        seen: set[str] = set()

        for rec in parsed_cmdline:
            args = rec.get("Args", rec.get("_raw_line", ""))
            for m in script_re.finditer(args):
                script = m.group(1)
                if script.lower() not in seen:
                    seen.add(script.lower())
                    self.iocs["scripts"].add(script)
                    self.entries.append(IOCEntry(
                        value=script, ioc_type="script", source="cmdline",
                        process=rec.get("Process", ""), pid=rec.get("PID", ""),
                        related_cmdline=args[:200],
                        category="suspicious",
                    ))

        # Raw fallback
        for m in script_re.finditer(raw_cmdline):
            script = m.group(1)
            if script.lower() not in seen:
                seen.add(script.lower())
                self.iocs["scripts"].add(script)
                self.entries.append(IOCEntry(
                    value=script, ioc_type="script", source="cmdline",
                    category="suspicious",
                ))

    def _extract_command_lines(self, parsed_cmdline: list) -> None:
        """Extract suspicious command lines with process ownership."""
        suspicious_keywords = [
            "powershell", "invoke-", "downloadstring", "iex(",
            "wscript", "cscript", "cmd /c", "cmd.exe /c",
            "certutil", "bitsadmin", "regsvr32", "mshta",
            "%temp%", "\\temp\\", "bypass", "-enc ", "-encoded",
            "hidden", "-nop ", "-noni", "wget", "curl",
        ]
        for rec in parsed_cmdline:
            args = rec.get("Args", rec.get("_raw_line", ""))
            lower = args.lower()
            if any(kw in lower for kw in suspicious_keywords):
                self.iocs["command_lines"].add(args.strip()[:200])
                self.entries.append(IOCEntry(
                    value=args.strip()[:200], ioc_type="command_line",
                    source="cmdline",
                    process=rec.get("Process", ""), pid=rec.get("PID", ""),
                    related_cmdline=args[:200],
                    category="suspicious",
                ))

    def _extract_ip_addresses(self, raw_netstat: str, raw_netscan: str,
                              parsed_netstat: list, parsed_netscan: list) -> None:
        """Extract IP addresses with process ownership from parsed records."""
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        exclude = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "*"}
        seen: set[str] = set()

        # From structured records (has process ownership)
        for records, source in [(parsed_netstat, "netstat"), (parsed_netscan, "netscan")]:
            for rec in records:
                for key in ("ForeignAddr", "Foreign Addr", "LocalAddr", "Local Addr"):
                    addr = rec.get(key, "")
                    for m in ip_re.finditer(addr):
                        ip = m.group(1)
                        if ip not in exclude and not ip.startswith("0.") and ip not in seen:
                            seen.add(ip)
                            self.iocs["ip_addresses"].add(ip)
                            self.entries.append(IOCEntry(
                                value=ip, ioc_type="ip", source=source,
                                process=rec.get("Owner", rec.get("Process", "")),
                                pid=rec.get("PID", ""),
                            ))

        # Raw fallback
        for text, source in [(raw_netstat, "netstat"), (raw_netscan, "netscan")]:
            for m in ip_re.finditer(text):
                ip = m.group(1)
                if ip not in exclude and not ip.startswith("0.") and ip not in seen:
                    seen.add(ip)
                    self.iocs["ip_addresses"].add(ip)
                    self.entries.append(IOCEntry(
                        value=ip, ioc_type="ip", source=source,
                    ))

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

    def _extract_temp_paths(self, parsed_cmdline: list) -> None:
        """Extract suspicious Temp/AppData paths with process ownership."""
        path_re = re.compile(
            r"((?:[A-Za-z]:\\|\\\\)(?:\S*(?:Temp|AppData|tmp)\S*))", re.IGNORECASE
        )
        seen: set[str] = set()

        for rec in parsed_cmdline:
            args = rec.get("Args", rec.get("_raw_line", ""))
            for m in path_re.finditer(args):
                path = m.group(1)
                if path not in seen:
                    seen.add(path)
                    self.iocs["temp_paths"].add(path)
                    self.entries.append(IOCEntry(
                        value=path, ioc_type="path", source="cmdline",
                        process=rec.get("Process", ""), pid=rec.get("PID", ""),
                        related_cmdline=args[:200],
                        category="suspicious",
                    ))

    def _enrich_from_findings(self, findings: list) -> None:
        """Cross-reference IOC entries with findings for severity-based categorization."""
        # Build a lookup of flagged process names
        malicious_procs: set[str] = set()
        for f in findings:
            if f.severity in ("HIGH", "CRITICAL") or f.confidence in ("HIGH", "CRITICAL"):
                proc_norm = f.process.lower().split("(")[0].strip()
                malicious_procs.add(proc_norm)

        # Upgrade IOC categories based on finding severity
        for entry in self.entries:
            proc_norm = entry.process.lower().split("(")[0].strip()
            if proc_norm in malicious_procs:
                entry.category = "malicious"
            elif entry.category == "informational" and entry.ioc_type in ("script", "command_line"):
                entry.category = "suspicious"

    # ── Public API ───────────────────────────────────────────────────────

    def extract(self, raw_text: dict = None, parsed_data: dict = None,
                findings: list = None) -> dict[str, set[str]]:
        """Run all extraction methods.

        Parameters
        ----------
        raw_text : dict
            Raw file contents from OutputParser.raw_text.
        parsed_data : dict
            Structured parsed data from OutputParser.parsed_data.
        findings : list[Finding]
            Findings from the detector for severity-based enrichment.
        """
        separator("IOC Extraction")
        console.print("[bold cyan][*] Extracting indicators of compromise...[/bold cyan]\n")

        if raw_text is None:
            raw_text = {}
        if parsed_data is None:
            parsed_data = {}

        raw_cmdline = raw_text.get("cmdline", "") or self._read_raw("windows_cmdline.txt")
        raw_psscan  = raw_text.get("psscan", "")  or self._read_raw("windows_psscan.txt")
        raw_netstat = raw_text.get("netstat", "") or self._read_raw("windows_netstat.txt")
        raw_netscan = raw_text.get("netscan", "") or self._read_raw("windows_netscan.txt")

        parsed_cmdline = parsed_data.get("cmdline", [])
        parsed_netstat = parsed_data.get("netstat", [])
        parsed_netscan = parsed_data.get("netscan", [])

        self._extract_executables(parsed_cmdline, raw_psscan)
        self._extract_scripts(parsed_cmdline, raw_cmdline)
        self._extract_command_lines(parsed_cmdline)
        self._extract_ip_addresses(raw_netstat, raw_netscan, parsed_netstat, parsed_netscan)
        self._extract_ports(raw_netstat, raw_netscan)
        self._extract_temp_paths(parsed_cmdline)

        # Enrich with finding severity
        if findings:
            self._enrich_from_findings(findings)

        # Display summary
        total = sum(len(v) for v in self.iocs.values())
        for category, items in self.iocs.items():
            if items:
                console.print(f"  [dim]{category:16s} -> {len(items)} IOC(s)[/dim]")
        console.print(f"\n[green][+] Extracted {total} total IOCs ({len(self.entries)} enriched entries)[/green]")

        # Save
        self._save()

        logger.info("IOC extraction complete -- %d IOCs, %d enriched", total, len(self.entries))
        return self.iocs

    @staticmethod
    def _read_raw(filename: str) -> str:
        """Read raw output file directly."""
        path = OUTPUT_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return ""

    def _save(self) -> None:
        """Save IOCs to results/iocs.txt with enriched format."""
        path = RESULTS_DIR / "iocs.txt"
        lines = [
            "=" * 60,
            "  INDICATORS OF COMPROMISE (IOCs)",
            "=" * 60,
            "",
        ]

        # Group entries by type for structured output
        type_titles = {
            "executable": "EXECUTABLE FILES",
            "script": "SCRIPT FILES",
            "command_line": "SUSPICIOUS COMMAND LINES",
            "ip": "IP ADDRESSES",
            "path": "SUSPICIOUS TEMP PATHS",
        }

        entries_by_type: dict[str, list[IOCEntry]] = {}
        for entry in self.entries:
            entries_by_type.setdefault(entry.ioc_type, []).append(entry)

        for ioc_type, title in type_titles.items():
            entries = entries_by_type.get(ioc_type, [])
            if entries:
                lines.append(f"--- {title} ---")
                # Deduplicate by value
                seen = set()
                for entry in entries:
                    if entry.value in seen:
                        continue
                    seen.add(entry.value)
                    lines.append(f"  {entry.value}")
                    if entry.process:
                        lines.append(f"    Process  : {entry.process}")
                    if entry.pid:
                        lines.append(f"    PID      : {entry.pid}")
                    if entry.related_cmdline and entry.ioc_type not in ("command_line",):
                        lines.append(f"    CmdLine  : {entry.related_cmdline[:150]}")
                    lines.append(f"    Category : {entry.category}")
                    lines.append(f"    Source   : {entry.source}")
                    lines.append("")
                lines.append("")

        # Add raw ports (not enriched)
        if self.iocs.get("ports"):
            lines.append("--- NON-STANDARD PORTS ---")
            for port in sorted(self.iocs["ports"]):
                lines.append(f"  {port}")
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green][+] IOCs saved to:[/green] {path}")

    def get_summary(self) -> dict[str, int]:
        """Return a count summary for reporting."""
        return {k: len(v) for k, v in self.iocs.items() if v}

    def get_entries(self) -> list[IOCEntry]:
        """Return enriched IOC entries for reporting."""
        return self.entries
