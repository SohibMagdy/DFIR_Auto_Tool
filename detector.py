"""
detector.py — Threat detection engine.

Applies detection rules against parsed Volatility output to identify
suspicious and malicious indicators.

Architecture:
  Every detection method uses a **dual-mode** approach:
    1. Scan structured records (parsed dicts) for known field values
    2. Scan raw text of the output file for keyword/regex matches

  This guarantees detection even when the table parser cannot perfectly
  split Volatility 3's output into columns.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from rich.table import Table

from utils import console, load_rules, setup_logging, separator, OUTPUT_DIR

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
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    score: int
    process: str = ""
    evidence: str = ""
    recommendation: str = ""


class ThreatDetector:
    """Scan parsed Volatility data for indicators of compromise.

    Accepts both parsed_data (structured records) and raw_text
    (raw file contents) from the OutputParser.
    """

    def __init__(self) -> None:
        self.rules: dict = load_rules()
        self.findings: list[Finding] = []
        self._dedup: set[str] = set()  # prevent duplicate findings

    # ── Helper ───────────────────────────────────────────────────────────

    def _add(self, rule_id, cat, rule, proc="", evidence="", rec=""):
        """Add a finding, de-duplicating by (rule_id, normalized_process)."""
        # Normalize process name for dedup:
        #   - strip PID suffix like "(PID: 1234)"
        #   - strip .exe extension
        #   - lowercase
        #   - take first 6 chars to handle column-truncation variants
        #     (e.g. "explore" vs "explorer.exe" both become "explor")
        import re as _re
        proc_norm = _re.sub(r"\s*\(PID:.*?\)", "", proc).strip().lower()
        proc_norm = proc_norm.replace(".exe", "").strip()
        # Remove any trailing whitespace/tab artifacts
        proc_norm = proc_norm.split()[0] if proc_norm.split() else proc_norm
        # Use first 6 chars as the key to handle truncation
        proc_key = proc_norm[:6] if len(proc_norm) >= 6 else proc_norm
        dedup_key = f"{rule_id}|{proc_key}"
        if dedup_key in self._dedup:
            return
        self._dedup.add(dedup_key)

        self.findings.append(Finding(
            rule_id=rule_id, category=cat,
            description=rule["description"], severity=rule["severity"],
            score=rule["score"], process=proc, evidence=evidence,
            recommendation=rec,
        ))
        # Live terminal output per finding
        sev = rule["severity"]
        color = SEVERITY_COLORS.get(sev, "white")
        console.print(f"  [{color}][{sev}][/{color}] {rule['description']}")
        if proc:
            console.print(f"         [dim]Process : {proc}[/dim]")
        if evidence:
            short_ev = (evidence[:120] + "...") if len(evidence) > 120 else evidence
            console.print(f"         [dim]Evidence: {short_ev}[/dim]")

    @staticmethod
    def _read_raw(filename: str) -> str:
        """Read raw output file directly (fallback when raw_text dict is incomplete)."""
        path = OUTPUT_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return ""

    # ═══════════════════════════════════════════════════════════════════════
    #  DETECTION METHODS — each uses dual-mode (structured + raw text)
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_rwx_memory(self, records: list[dict], raw: str) -> None:
        """Detect PAGE_EXECUTE_READWRITE memory regions."""
        rule = self.rules["memory_indicators"]["rwx_memory"]

        # ── Mode 1: structured records ───────────────────────────────────
        for rec in records:
            combined = " ".join(str(v) for v in rec.values())
            if "PAGE_EXECUTE_READWRITE" in combined:
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                pid = rec.get("PID", "?")
                self._add("rwx_memory", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"PAGE_EXECUTE_READWRITE in: {rec.get('_raw_line', combined)[:150]}",
                          "Dump the suspicious memory region and scan with YARA / antivirus.")

        # ── Mode 2: raw text scan ────────────────────────────────────────
        for match in re.finditer(
            r"(\d+)\s+(\S+\.exe)\s+.*?PAGE_EXECUTE_READWRITE",
            raw, re.IGNORECASE
        ):
            pid, proc = match.group(1), match.group(2)
            self._add("rwx_memory", "Memory", rule,
                      f"{proc} (PID: {pid})",
                      f"Raw match: {match.group(0)[:150]}",
                      "Dump the suspicious memory region and scan with YARA / antivirus.")

        # ── Mode 3: simple keyword scan in every line ────────────────────
        if "PAGE_EXECUTE_READWRITE" in raw:
            for line in raw.splitlines():
                if "PAGE_EXECUTE_READWRITE" not in line:
                    continue
                # Try to extract process name from the line
                m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = m.group(1) if m else "Unknown"
                pid_m = re.search(r"^(\d+)\s", line.strip())
                pid = pid_m.group(1) if pid_m else "?"
                self._add("rwx_memory", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"Line: {line.strip()[:150]}",
                          "Dump the suspicious memory region and scan with YARA / antivirus.")

    def _detect_process_injection(self, records: list[dict], raw: str) -> None:
        """Detect MZ headers and PE signatures in memory (process injection)."""
        rule = self.rules["memory_indicators"]["process_injection"]

        keywords = ["MZ header", "This program cannot be run", "4d 5a"]

        # ── Mode 1: structured records ───────────────────────────────────
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

        # ── Mode 2: raw text scan for MZ header patterns ─────────────────
        # MZ in hex dump: "4d 5a" or "MZ"
        mz_patterns = [
            r"(\d+)\s+(\S+\.exe)\s+.*?(?:MZ|4d\s*5a)",
            r"(MZ).*?(PAGE_EXECUTE)",
        ]
        for pat in mz_patterns:
            for match in re.finditer(pat, raw, re.IGNORECASE | re.DOTALL):
                full = match.group(0)
                proc_m = re.search(r"(\S+\.exe)", full, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "Unknown"
                pid_m = re.search(r"^(\d+)", full.strip())
                pid = pid_m.group(1) if pid_m else "?"
                self._add("process_injection", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"MZ/PE header in memory: {full[:100]}",
                          "Extract and reverse-engineer the injected code.")

        # ── Mode 3: line-by-line hex dump scan ───────────────────────────
        for line in raw.splitlines():
            stripped = line.strip().lower()
            if re.match(r"^0x[0-9a-f]+", stripped):
                if "4d 5a" in stripped or "4d5a" in stripped:
                    self._add("process_injection", "Memory", rule,
                              "Unknown (hex dump)",
                              f"Hex line: {line.strip()[:120]}",
                              "Extract and reverse-engineer the injected code.")

    def _detect_wscript(self, records: list[dict], raw: str) -> None:
        """Detect wscript.exe / cscript.exe execution."""
        rule = self.rules["process_indicators"]["wscript_execution"]
        keywords = [k.lower() for k in rule["keywords"]]

        # ── Structured ───────────────────────────────────────────────────
        for rec in records:
            combined = " ".join(str(v) for v in rec.values()).lower()
            if any(kw in combined for kw in keywords):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("wscript_execution", "Process", rule, proc,
                          f"Command line: {args[:150]}",
                          "Investigate the script for obfuscation or payloads.")

        # ── Raw text ─────────────────────────────────────────────────────
        for line in raw.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in keywords):
                proc_m = re.search(r"(wscript\.exe|cscript\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "wscript/cscript"
                self._add("wscript_execution", "Process", rule, proc,
                          f"Line: {line.strip()[:150]}",
                          "Investigate the script for obfuscation or payloads.")

    def _detect_vbs_scripts(self, records: list[dict], raw: str) -> None:
        """Detect VBScript references (.vbs, .vbe, .wsf)."""
        rule = self.rules["process_indicators"]["vbs_script"]
        keywords = [k.lower() for k in rule["keywords"]]

        # ── Structured ───────────────────────────────────────────────────
        for rec in records:
            combined = " ".join(str(v) for v in rec.values()).lower()
            if any(kw in combined for kw in keywords):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("vbs_script", "Process", rule, proc,
                          f"Script reference: {args[:150]}",
                          "Retrieve and deobfuscate the VBS script.")

        # ── Raw text ─────────────────────────────────────────────────────
        vbs_regex = re.compile(r"(\S+\.(?:vbs|vbe|wsf))", re.IGNORECASE)
        for line in raw.splitlines():
            m = vbs_regex.search(line)
            if m:
                script_name = m.group(1)
                proc_m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "Unknown"
                self._add("vbs_script", "Process", rule, proc,
                          f"Script: {script_name} — Line: {line.strip()[:120]}",
                          "Retrieve and deobfuscate the VBS script.")

    def _detect_temp_execution(self, records: list[dict], raw: str) -> None:
        """Flag processes running from Temp/AppData/tmp directories."""
        rule = self.rules["process_indicators"]["temp_execution"]
        # Use regex for more flexible matching (case-insensitive, various separators)
        temp_regex = re.compile(
            r"(?:\\|/)(?:Temp|AppData|tmp)(?:\\|/)", re.IGNORECASE
        )

        # ── Structured ───────────────────────────────────────────────────
        for rec in records:
            combined = " ".join(str(v) for v in rec.values())
            if temp_regex.search(combined):
                proc = rec.get("Process", rec.get("Name", "Unknown"))
                args = rec.get("Args", rec.get("_raw_line", ""))
                self._add("temp_execution", "Process", rule, proc,
                          f"Suspicious path: {args[:150]}",
                          "Verify binary hash against known-good sources.")

        # ── Raw text ─────────────────────────────────────────────────────
        # Also match %TEMP% environment variable references
        temp_raw_regex = re.compile(
            r"(%TEMP%|\\Temp\\|\\AppData\\|\\tmp\\|/tmp/)", re.IGNORECASE
        )
        for line in raw.splitlines():
            if temp_raw_regex.search(line):
                proc_m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                proc = proc_m.group(1) if proc_m else "Unknown"
                self._add("temp_execution", "Process", rule, proc,
                          f"Line: {line.strip()[:150]}",
                          "Verify binary hash against known-good sources.")

    def _detect_random_names(self, records: list[dict], raw_cmdline: str, raw_psscan: str) -> None:
        """Detect executables with randomized / meaningless names.

        Heuristics:
          1. Mixed-case gibberish with no real English words (e.g. UWkpjFjDzM.exe)
          2. Very long lowercase-only names (e.g. abcdefghij.exe)
          3. Hash-like 32-char hex names
          4. High consonant-to-vowel ratio (not a real word)
        """
        rule = self.rules["process_indicators"]["random_executable"]

        # Patterns that catch randomised names
        random_patterns = [
            # Mixed case gibberish: 5+ chars with unusual case mixing, ending in .exe
            re.compile(r"\b([A-Za-z]{5,}\.exe)\b"),
            # Original rule pattern
            re.compile(r"\b([a-z]{8,}\.exe)\b", re.IGNORECASE),
            # Hash-like: 32 hex chars
            re.compile(r"\b([A-Fa-f0-9]{32}\.exe)\b"),
        ]

        # Known legitimate process names to exclude
        legit_names = {
            "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
            "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
            "taskhostw.exe", "taskhost.exe", "dwm.exe", "conhost.exe",
            "cmd.exe", "powershell.exe", "rundll32.exe", "dllhost.exe",
            "msiexec.exe", "spoolsv.exe", "searchindexer.exe",
            "wmiprvse.exe", "wscript.exe", "cscript.exe", "notepad.exe",
            "regedit.exe", "taskmgr.exe", "mmc.exe", "ctfmon.exe",
            "system.exe", "registry.exe", "fontdrvhost.exe",
            "searchprotocolhost.exe", "searchfilterhost.exe",
            "runtimebroker.exe", "applicationframehost.exe",
            "shellexperiencehost.exe", "sihost.exe", "lsaiso.exe",
            "securityhealthservice.exe", "sgrmbroker.exe",
            "microsoftedge.exe", "microsoftedgecp.exe",
            "microsoftedgesh.exe", "chrome.exe", "firefox.exe",
            "onedrive.exe", "teams.exe", "outlook.exe", "excel.exe",
            "word.exe", "msedge.exe", "iexplore.exe",
        }

        def _is_random(name: str) -> bool:
            """Heuristic: is this executable name random-looking?"""
            base = name.lower().replace(".exe", "")
            if len(base) < 4:
                return False
            if name.lower() in legit_names:
                return False

            vowels = set("aeiou")
            consonants = set("bcdfghjklmnpqrstvwxyz")
            v_count = sum(1 for c in base if c in vowels)
            c_count = sum(1 for c in base if c in consonants)

            # Very high consonant-to-vowel ratio → likely random
            if c_count > 0 and v_count > 0:
                ratio = c_count / v_count
                if ratio > 4.0 and len(base) >= 6:
                    return True

            # Mixed case in the middle (e.g. UWkpjFjDzM) — legitimate names are
            # usually all-lower, all-upper, or PascalCase with clear boundaries
            upper_in_mid = sum(1 for c in base[1:] if c.isupper())
            if upper_in_mid >= 2 and len(base) >= 6:
                return True

            # All consonants, no vowels at all
            if v_count == 0 and len(base) >= 5:
                return True

            return False

        seen: set[str] = set()
        combined_raw = f"{raw_cmdline}\n{raw_psscan}"

        # Extract all .exe names from raw text
        exe_regex = re.compile(r"\b(\S+\.exe)\b", re.IGNORECASE)
        for m in exe_regex.finditer(combined_raw):
            name = m.group(1)
            # Clean up path — take just the filename
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

    def _detect_hidden_processes(self, psscan_records: list[dict],
                                  cmdline_records: list[dict]) -> None:
        """Flag processes in psscan not present in cmdline (potentially hidden)."""
        rule = self.rules["process_indicators"]["hidden_process"]

        cmdline_pids = set()
        for rec in cmdline_records:
            pid = rec.get("PID", "")
            if pid:
                cmdline_pids.add(str(pid).strip())

        for rec in psscan_records:
            pid = str(rec.get("PID", "")).strip()
            proc = rec.get("Process", rec.get("ImageFileName",
                   rec.get("Name", "Unknown")))
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

        # ── Structured ───────────────────────────────────────────────────
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
                              f"Port {port} — State: {state}",
                              "Investigate remote endpoint with threat intel feeds.")

        # ── Raw text — search for port numbers ───────────────────────────
        for port in bad_ports:
            port_regex = re.compile(rf"[:\s]{port}(?:\s|$)")
            for line in raw.splitlines():
                if port_regex.search(line):
                    proc_m = re.search(r"(\S+\.exe)", line, re.IGNORECASE)
                    proc = proc_m.group(1) if proc_m else "Unknown"
                    self._add("suspicious_port", "Network", rule, proc,
                              f"Port {port} in: {line.strip()[:120]}",
                              "Investigate remote endpoint with threat intel feeds.")

    def _detect_suspicious_svchost(self, raw_malfind: str, raw_cmdline: str) -> None:
        """Detect svchost.exe anomalies — RWX memory is suspicious for svchost."""
        rule_info = {
            "description": "svchost.exe with suspicious memory — possible process hollowing",
            "severity": "CRITICAL",
            "score": 40,
        }
        if "svchost.exe" in raw_malfind.lower() and "PAGE_EXECUTE_READWRITE" in raw_malfind:
            self._add("svchost_suspicious", "Memory", rule_info,
                      "svchost.exe",
                      "svchost.exe found in malfind with RWX memory protection",
                      "Verify svchost.exe parent (should be services.exe) and check for hollowing.")

    def _detect_suspicious_explorer(self, raw_malfind: str) -> None:
        """Detect explorer.exe injection indicators."""
        rule_info = {
            "description": "explorer.exe with executable memory — possible process injection",
            "severity": "CRITICAL",
            "score": 45,
        }
        if "explorer.exe" in raw_malfind.lower() and "PAGE_EXECUTE_READWRITE" in raw_malfind:
            self._add("explorer_injection", "Memory", rule_info,
                      "explorer.exe",
                      "explorer.exe found in malfind with executable memory regions",
                      "Dump injected memory from explorer.exe and analyze for shellcode.")

    def _detect_suspicious_wmiprvse(self, raw_malfind: str) -> None:
        """Detect WmiPrvSE.exe suspicious memory."""
        rule_info = {
            "description": "WmiPrvSE.exe with suspicious memory — possible WMI-based attack",
            "severity": "HIGH",
            "score": 35,
        }
        if "wmiprvse.exe" in raw_malfind.lower() and "PAGE_EXECUTE_READWRITE" in raw_malfind:
            self._add("wmiprvse_suspicious", "Memory", rule_info,
                      "WmiPrvSE.exe",
                      "WmiPrvSE.exe found in malfind with RWX memory",
                      "Investigate WMI event subscriptions and lateral movement.")

    # ═══════════════════════════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════

    def analyze(self, parsed_data: dict, raw_text: dict = None) -> list[Finding]:
        """Run all detection checks and return findings.

        Parameters
        ----------
        parsed_data : dict
            Structured records from OutputParser.parsed_data
        raw_text : dict, optional
            Raw file contents from OutputParser.raw_text.
            If not provided, files are read directly from output/.
        """
        separator("Threat Detection Engine")
        console.print("[bold cyan][*] Analyzing for indicators of compromise...[/bold cyan]\n")

        if raw_text is None:
            raw_text = {}

        # Load raw text — either from parser or directly from files
        raw_malfind = raw_text.get("malfind", "") or self._read_raw("windows_malfind.txt")
        raw_cmdline = raw_text.get("cmdline", "") or self._read_raw("windows_cmdline.txt")
        raw_netstat = raw_text.get("netstat", "") or self._read_raw("windows_netstat.txt")
        raw_netscan = raw_text.get("netscan", "") or self._read_raw("windows_netscan.txt")
        raw_psscan  = raw_text.get("psscan", "")  or self._read_raw("windows_psscan.txt")

        # Structured data
        malfind_recs = parsed_data.get("malfind", [])
        cmdline_recs = parsed_data.get("cmdline", [])
        netstat_recs = parsed_data.get("netstat", [])
        netscan_recs = parsed_data.get("netscan", [])
        psscan_recs  = parsed_data.get("psscan", [])

        # ── Debug: show what we're working with ──────────────────────────
        console.print("[dim]  Data available for detection:[/dim]")
        console.print(f"[dim]    malfind : {len(malfind_recs)} records, {len(raw_malfind)} chars raw[/dim]")
        console.print(f"[dim]    cmdline : {len(cmdline_recs)} records, {len(raw_cmdline)} chars raw[/dim]")
        console.print(f"[dim]    netstat : {len(netstat_recs)} records, {len(raw_netstat)} chars raw[/dim]")
        console.print(f"[dim]    netscan : {len(netscan_recs)} records, {len(raw_netscan)} chars raw[/dim]")
        console.print(f"[dim]    psscan  : {len(psscan_recs)} records, {len(raw_psscan)} chars raw[/dim]")
        console.print()

        # ── Run all detectors ────────────────────────────────────────────
        console.print("[bold white]  Scanning for threats...[/bold white]\n")

        self._detect_rwx_memory(malfind_recs, raw_malfind)
        self._detect_process_injection(malfind_recs, raw_malfind)
        self._detect_wscript(cmdline_recs, raw_cmdline)
        self._detect_vbs_scripts(cmdline_recs, raw_cmdline)
        self._detect_temp_execution(cmdline_recs, raw_cmdline)
        self._detect_random_names(cmdline_recs, raw_cmdline, raw_psscan)
        self._detect_hidden_processes(psscan_recs, cmdline_recs)
        self._detect_suspicious_network(netstat_recs, raw_netstat)
        self._detect_suspicious_network(netscan_recs, raw_netscan)

        # Process-specific detections
        self._detect_suspicious_svchost(raw_malfind, raw_cmdline)
        self._detect_suspicious_explorer(raw_malfind)
        self._detect_suspicious_wmiprvse(raw_malfind)

        # ── Summary ──────────────────────────────────────────────────────
        console.print()
        if self.findings:
            # Sort by severity
            self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            self._display_findings_table()
        else:
            console.print("[bold green]✔ No suspicious indicators detected[/bold green]\n")

        logger.info("Detection complete — %d findings", len(self.findings))
        return self.findings

    def _display_findings_table(self) -> None:
        """Print a professional summary table of all findings."""
        table = Table(
            title=f"⚠ {len(self.findings)} Suspicious Indicator(s) Detected",
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
        table.add_column("Score", justify="right", width=6)

        for idx, f in enumerate(self.findings, 1):
            sev_color = SEVERITY_COLORS.get(f.severity, "white")
            table.add_row(
                str(idx),
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.category,
                f.rule_id,
                f.process[:30] if f.process else "—",
                f"+{f.score}",
            )

        console.print(table)
        console.print()
