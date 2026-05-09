"""
detector.py -- Threat detection engine (v1.1).

Applies detection rules against parsed Volatility output to identify
suspicious and malicious indicators.

v1.1 changes:
  - Whitelist integration for false positive reduction
  - MITRE ATT&CK ID mapping on every finding
  - Improved deduplication (prefers named over Unknown)
  - confidence and effective_score fields on Finding
  - Removed hardcoded process-specific detectors (now handled by correlator)
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from rich.table import Table

from utils import console, load_rules, setup_logging, separator, OUTPUT_DIR
from whitelist import should_suppress, normalize_process_name

logger = setup_logging()


# ─── Severity ordering (for sorting) ────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}


@dataclass
class Finding:
    """Represents a single suspicious finding."""
    rule_id: str
    category: str
    description: str
    severity: str
    score: int
    process: str = ""
    evidence: str = ""
    recommendation: str = ""
    mitre_id: str = ""
    mitre_technique: str = ""
    # Set by the correlator after detection
    confidence: str = "LOW"
    effective_score: int = 0
    correlation_group: str = ""


class ThreatDetector:
    """Scan parsed Volatility data for indicators of compromise."""

    def __init__(self) -> None:
        self.rules: dict = load_rules()
        self.findings: list[Finding] = []
        self._dedup: dict[str, int] = {}  # dedup_key -> index in findings list

    # ── Helper ───────────────────────────────────────────────────────────

    def _make_dedup_key(self, rule_id: str, proc: str) -> str:
        """Build a normalized dedup key."""
        proc_norm = normalize_process_name(proc)
        proc_norm = proc_norm.replace(".exe", "").strip()
        proc_key = proc_norm[:6] if len(proc_norm) >= 6 else proc_norm
        return f"{rule_id}|{proc_key}"

    def _add(self, rule_id, cat, rule, proc="", evidence="", rec=""):
        """Add a finding with whitelist check and smart dedup."""
        # ── Whitelist check ──────────────────────────────────────────────
        if should_suppress(rule_id, proc, evidence):
            return

        # ── Dedup: prefer named processes over "Unknown" ─────────────────
        dedup_key = self._make_dedup_key(rule_id, proc)

        # Check if "Unknown" variant already exists for this rule
        unknown_key = f"{rule_id}|unkno"
        if dedup_key == unknown_key and dedup_key in self._dedup:
            return  # Already have Unknown, don't add another
        if dedup_key != unknown_key and unknown_key in self._dedup:
            # Replace the Unknown finding with this named one
            idx = self._dedup[unknown_key]
            del self._dedup[unknown_key]
            self._dedup[dedup_key] = idx
            # Will be overwritten below
        elif dedup_key in self._dedup:
            return  # Already have a named finding for this

        # ── Extract MITRE info from rule ─────────────────────────────────
        mitre_id = rule.get("mitre_id", "")
        mitre_technique = rule.get("mitre_technique", "")

        finding = Finding(
            rule_id=rule_id, category=cat,
            description=rule["description"], severity=rule["severity"],
            score=rule["score"], process=proc, evidence=evidence,
            recommendation=rec,
            mitre_id=mitre_id, mitre_technique=mitre_technique,
            effective_score=rule["score"],  # Will be adjusted by correlator
        )

        # Insert or replace
        if dedup_key in self._dedup:
            self.findings[self._dedup[dedup_key]] = finding
        else:
            self._dedup[dedup_key] = len(self.findings)
            self.findings.append(finding)

        # Live terminal output
        sev = rule["severity"]
        color = SEVERITY_COLORS.get(sev, "white")
        mitre_str = f" [{mitre_id}]" if mitre_id else ""
        console.print(f"  [{color}][{sev}]{mitre_str}[/{color}] {rule['description']}")
        if proc:
            console.print(f"         [dim]Process : {proc}[/dim]")

    @staticmethod
    def _read_raw(filename: str) -> str:
        """Read raw output file directly."""
        path = OUTPUT_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return ""

    # ═══════════════════════════════════════════════════════════════════════
    #  DETECTION METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_rwx_memory(self, records: list[dict], raw: str) -> None:
        """Detect PAGE_EXECUTE_READWRITE memory regions."""
        rule = self.rules["memory_indicators"]["rwx_memory"]

        # Structured records
        for rec in records:
            combined = " ".join(str(v) for v in rec.values())
            if "PAGE_EXECUTE_READWRITE" in combined:
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                pid = rec.get("PID", "?")
                self._add("rwx_memory", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"PAGE_EXECUTE_READWRITE in: {rec.get('_raw_line', combined)[:150]}",
                          "Dump the suspicious memory region and scan with YARA / antivirus.")

        # Raw text line scan
        if "PAGE_EXECUTE_READWRITE" in raw:
            for line in raw.splitlines():
                if "PAGE_EXECUTE_READWRITE" not in line:
                    continue
                m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = m.group(1) if m else "Unknown"
                pid_m = re.search(r"^(\d+)\s", line.strip())
                pid = pid_m.group(1) if pid_m else "?"
                self._add("rwx_memory", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"Line: {line.strip()[:150]}",
                          "Dump the suspicious memory region and scan with YARA / antivirus.")

    def _detect_process_injection(self, records: list[dict], raw: str) -> None:
        """Detect MZ headers and PE signatures in memory."""
        rule = self.rules["memory_indicators"]["process_injection"]
        keywords = ["MZ header", "This program cannot be run", "4d 5a"]

        # Structured records
        for rec in records:
            combined = " ".join(str(v) for v in rec.values())
            hex_block = rec.get("_hex_block", "")
            full_text = f"{combined} {hex_block}"
            if any(kw.lower() in full_text.lower() for kw in keywords):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                pid = rec.get("PID", "?")
                self._add("process_injection", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          "MZ/PE header found in executable memory region",
                          "Extract and reverse-engineer the injected code.")

        # Hex dump line scan
        for line in raw.splitlines():
            stripped = line.strip().lower()
            if re.match(r"^0x[0-9a-f]+", stripped):
                if "4d 5a" in stripped or "4d5a" in stripped:
                    # Try to find which process this hex belongs to
                    # by looking at the preceding lines
                    self._add("process_injection", "Memory", rule,
                              "Unknown (hex dump)",
                              f"Hex line: {line.strip()[:120]}",
                              "Extract and reverse-engineer the injected code.")

    def _detect_wscript(self, records: list[dict], raw: str) -> None:
        """Detect wscript.exe / cscript.exe execution."""
        rule = self.rules["process_indicators"]["wscript_execution"]
        keywords = [k.lower() for k in rule["keywords"]]

        for rec in records:
            combined = " ".join(str(v) for v in rec.values()).lower()
            if any(kw in combined for kw in keywords):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("wscript_execution", "Process", rule, proc,
                          f"Command line: {args[:150]}",
                          "Investigate the script for obfuscation or payloads.")

        for line in raw.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in keywords):
                proc_m = re.search(r"(wscript\.exe|cscript\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "wscript/cscript"
                self._add("wscript_execution", "Process", rule, proc,
                          f"Line: {line.strip()[:150]}",
                          "Investigate the script for obfuscation or payloads.")

    def _detect_vbs_scripts(self, records: list[dict], raw: str) -> None:
        """Detect VBScript references."""
        rule = self.rules["process_indicators"]["vbs_script"]
        keywords = [k.lower() for k in rule["keywords"]]

        for rec in records:
            combined = " ".join(str(v) for v in rec.values()).lower()
            if any(kw in combined for kw in keywords):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("vbs_script", "Process", rule, proc,
                          f"Script reference: {args[:150]}",
                          "Retrieve and deobfuscate the VBS script.")

        vbs_regex = re.compile(r"(\S+\.(?:vbs|vbe|wsf))", re.IGNORECASE)
        for line in raw.splitlines():
            m = vbs_regex.search(line)
            if m:
                proc_m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "Unknown"
                self._add("vbs_script", "Process", rule, proc,
                          f"Script: {m.group(1)} in: {line.strip()[:120]}",
                          "Retrieve and deobfuscate the VBS script.")

    def _detect_temp_execution(self, records: list[dict], raw: str) -> None:
        """Flag processes running from Temp/AppData directories."""
        rule = self.rules["process_indicators"]["temp_execution"]
        temp_regex = re.compile(
            r"(?:\\|/)(?:Temp|AppData|tmp)(?:\\|/)", re.IGNORECASE
        )
        temp_raw_regex = re.compile(
            r"(%TEMP%|\\Temp\\|\\AppData\\|\\tmp\\|/tmp/)", re.IGNORECASE
        )

        for rec in records:
            combined = " ".join(str(v) for v in rec.values())
            if temp_regex.search(combined):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("temp_execution", "Process", rule, proc,
                          f"Suspicious path: {args[:150]}",
                          "Verify binary hash against known-good sources.")

        for line in raw.splitlines():
            if temp_raw_regex.search(line):
                proc_m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "Unknown"
                self._add("temp_execution", "Process", rule, proc,
                          f"Line: {line.strip()[:150]}",
                          "Verify binary hash against known-good sources.")

    def _detect_random_names(self, records, raw_cmdline: str, raw_psscan: str) -> None:
        """Detect executables with randomized names."""
        rule = self.rules["process_indicators"]["random_executable"]

        legit_names = {
            "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
            "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
            "taskhostw.exe", "taskhost.exe", "dwm.exe", "conhost.exe",
            "cmd.exe", "powershell.exe", "rundll32.exe", "dllhost.exe",
            "msiexec.exe", "spoolsv.exe", "searchindexer.exe",
            "wmiprvse.exe", "wscript.exe", "cscript.exe", "notepad.exe",
            "regedit.exe", "taskmgr.exe", "mmc.exe", "ctfmon.exe",
            "system.exe", "registry.exe", "fontdrvhost.exe",
            "runtimebroker.exe", "applicationframehost.exe",
            "shellexperiencehost.exe", "sihost.exe", "lsaiso.exe",
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "onedrive.exe", "teams.exe", "outlook.exe", "excel.exe",
            "winword.exe", "powerpnt.exe", "msdtc.exe", "sppsvc.exe",
            "securityhealthservice.exe", "sgrmbroker.exe",
        }

        def _is_random(name: str) -> bool:
            base = name.lower().replace(".exe", "")
            if len(base) < 4 or name.lower() in legit_names:
                return False
            vowels = set("aeiou")
            v_count = sum(1 for c in base if c in vowels)
            c_count = sum(1 for c in base if c.isalpha() and c not in vowels)
            if c_count > 0 and v_count > 0 and c_count / v_count > 4.0 and len(base) >= 6:
                return True
            upper_in_mid = sum(1 for c in base[1:] if c.isupper())
            if upper_in_mid >= 2 and len(base) >= 6:
                return True
            if v_count == 0 and len(base) >= 5:
                return True
            return False

        seen: set[str] = set()
        exe_regex = re.compile(r"\b(\S+\.exe)\b", re.IGNORECASE)
        for m in exe_regex.finditer(f"{raw_cmdline}\n{raw_psscan}"):
            name = m.group(1)
            if "\\" in name:
                name = name.rsplit("\\", 1)[-1]
            if "/" in name:
                name = name.rsplit("/", 1)[-1]
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            if _is_random(name):
                self._add("random_executable", "Process", rule, name,
                          f"Randomised executable name: {name}",
                          "Check file origin, digital signature, and VirusTotal hash.")

    def _detect_hidden_processes(self, psscan_recs, cmdline_recs) -> None:
        """Flag processes in psscan not present in cmdline."""
        rule = self.rules["process_indicators"]["hidden_process"]
        cmdline_pids = {str(r.get("PID", "")).strip() for r in cmdline_recs if r.get("PID")}

        for rec in psscan_recs:
            pid = str(rec.get("PID", "")).strip()
            proc = rec.get("Process", rec.get("ImageFileName", rec.get("Name", "Unknown")))
            exit_time = rec.get("ExitTime", rec.get("Exit", "")).strip()
            if pid and pid not in cmdline_pids and not exit_time:
                self._add("hidden_process", "Process", rule,
                          f"{proc} (PID: {pid})",
                          "Present in psscan but not in active process listings",
                          "Cross-reference with pslist/pstree for rootkit indicators.")

    def _detect_suspicious_network(self, records: list[dict], raw: str) -> None:
        """Flag connections on commonly abused ports."""
        rule = self.rules["network_indicators"]["suspicious_ports"]
        bad_ports = set(rule["ports"])

        for rec in records:
            for port_key in ("ForeignPort", "Foreign Port", "LocalPort", "Local Port"):
                try:
                    port = int(rec.get(port_key, ""))
                except (ValueError, TypeError):
                    continue
                if port in bad_ports:
                    proc = rec.get("Owner", rec.get("Process", "Unknown"))
                    pid = rec.get("PID", "?")
                    state = rec.get("State", "")
                    self._add("suspicious_port", "Network", rule,
                              f"{proc} (PID: {pid})",
                              f"Port {port} -- State: {state}",
                              "Investigate remote endpoint with threat intel feeds.")

    # ═══════════════════════════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════

    def analyze(self, parsed_data: dict, raw_text: dict = None) -> list[Finding]:
        """Run all detection checks and return findings."""
        separator("Threat Detection Engine")
        console.print("[bold cyan][*] Analyzing for indicators of compromise...[/bold cyan]\n")

        if raw_text is None:
            raw_text = {}

        raw_malfind = raw_text.get("malfind", "") or self._read_raw("windows_malfind.txt")
        raw_cmdline = raw_text.get("cmdline", "") or self._read_raw("windows_cmdline.txt")
        raw_netstat = raw_text.get("netstat", "") or self._read_raw("windows_netstat.txt")
        raw_netscan = raw_text.get("netscan", "") or self._read_raw("windows_netscan.txt")
        raw_psscan  = raw_text.get("psscan", "")  or self._read_raw("windows_psscan.txt")

        malfind_recs = parsed_data.get("malfind", [])
        cmdline_recs = parsed_data.get("cmdline", [])
        netstat_recs = parsed_data.get("netstat", [])
        netscan_recs = parsed_data.get("netscan", [])
        psscan_recs  = parsed_data.get("psscan", [])

        # Debug info
        console.print("[dim]  Data available for detection:[/dim]")
        console.print(f"[dim]    malfind : {len(malfind_recs)} records, {len(raw_malfind)} chars raw[/dim]")
        console.print(f"[dim]    cmdline : {len(cmdline_recs)} records, {len(raw_cmdline)} chars raw[/dim]")
        console.print(f"[dim]    netstat : {len(netstat_recs)} records, {len(raw_netstat)} chars raw[/dim]")
        console.print(f"[dim]    netscan : {len(netscan_recs)} records, {len(raw_netscan)} chars raw[/dim]")
        console.print(f"[dim]    psscan  : {len(psscan_recs)} records, {len(raw_psscan)} chars raw[/dim]")
        console.print()
        console.print("[bold white]  Scanning for threats...[/bold white]\n")

        # Run all detectors
        self._detect_rwx_memory(malfind_recs, raw_malfind)
        self._detect_process_injection(malfind_recs, raw_malfind)
        self._detect_wscript(cmdline_recs, raw_cmdline)
        self._detect_vbs_scripts(cmdline_recs, raw_cmdline)
        self._detect_temp_execution(cmdline_recs, raw_cmdline)
        self._detect_random_names(cmdline_recs, raw_cmdline, raw_psscan)
        self._detect_hidden_processes(psscan_recs, cmdline_recs)
        self._detect_suspicious_network(netstat_recs, raw_netstat)
        self._detect_suspicious_network(netscan_recs, raw_netscan)

        # Summary
        console.print()
        if self.findings:
            self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            self._display_findings_table()
        else:
            console.print("[bold green][+] No suspicious indicators detected[/bold green]\n")

        logger.info("Detection complete -- %d findings", len(self.findings))
        return self.findings

    def _display_findings_table(self) -> None:
        """Print a summary table of all findings."""
        table = Table(
            title=f"[!] {len(self.findings)} Suspicious Indicator(s) Detected",
            show_header=True,
            header_style="bold bright_red",
            border_style="red",
            title_style="bold red",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", justify="center", min_width=10)
        table.add_column("Category", min_width=10)
        table.add_column("Rule", min_width=20)
        table.add_column("Process", min_width=18)
        table.add_column("MITRE", min_width=10)
        table.add_column("Score", justify="right", width=6)

        for idx, f in enumerate(self.findings, 1):
            sev_color = SEVERITY_COLORS.get(f.severity, "white")
            table.add_row(
                str(idx),
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.category,
                f.rule_id,
                f.process[:28] if f.process else "--",
                f.mitre_id or "--",
                f"+{f.score}",
            )

        console.print(table)
        console.print()
