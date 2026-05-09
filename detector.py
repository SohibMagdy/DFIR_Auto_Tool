"""
detector.py -- Threat detection engine (v1.2).

Applies detection rules against parsed Volatility output to identify
suspicious and malicious indicators.

v1.2 changes:
  - Malfind block context: no more "Unknown (PID: ?)" for MZ headers
  - Multi-factor randomness scoring (entropy, consonant ratio, etc.)
  - Process relationship findings integrated via process_analyzer
  - Extended whitelist used instead of duplicate legit_names set
"""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from rich.table import Table

from utils import console, load_rules, setup_logging, separator, OUTPUT_DIR
from whitelist import (
    should_suppress, normalize_process_name,
    WHITELISTED_PROCESSES, is_whitelisted_process,
)

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


# ── Extended legit names for random-name detection ───────────────────────────
# Uses WHITELISTED_PROCESSES plus Windows service/utility names that have
# consonant-heavy patterns but are legitimate.
EXTENDED_LEGIT_NAMES: set[str] = WHITELISTED_PROCESSES | {
    "wmpnetwk.exe", "sppextcomobj.exe", "dashost.exe", "dfsrs.exe",
    "dfssvc.exe", "lsm.exe", "trustedinstaller.exe", "tiworker.exe",
    "musnotification.exe", "compattelrunner.exe", "gamebarpresencewriter.exe",
    "officebackgroundtaskhandler.exe", "phoneexperiencehost.exe",
    "microsoftedgeupdate.exe", "msedgewebview2.exe", "crashpad_handler.exe",
    "dllhost.exe", "jusched.exe", "jucheck.exe", "werfault.exe",
    "ngentask.exe", "ngen.exe", "crossgen.exe", "vshost.exe",
    "consent.exe", "logonui.exe", "utilman.exe", "credentialuibroker.exe",
    "compressedmemory.exe", "vssvc.exe", "mscorsvw.exe",
    "backgroundtransferhost.exe", "lockapp.exe", "yourphone.exe",
    "systemsettingsbroker.exe", "windows.immersivecontrolpanel.exe",
}


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

    def _detect_rwx_memory(self, records: list[dict], raw: str,
                           malfind_blocks: list[dict]) -> None:
        """Detect PAGE_EXECUTE_READWRITE memory regions.

        v1.2: Uses malfind_blocks for process-context-aware detection.
        """
        rule = self.rules["memory_indicators"]["rwx_memory"]

        # ── Primary: malfind blocks (v1.2 -- context-aware) ──────────────
        for block in malfind_blocks:
            if block.get("is_rwx"):
                proc = block["process"]
                pid = block["pid"]
                self._add("rwx_memory", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"PAGE_EXECUTE_READWRITE at {block.get('start_vpn', '?')}",
                          "Dump the suspicious memory region and scan with YARA / antivirus.")

        # ── Fallback: structured records (if blocks unavailable) ─────────
        if not malfind_blocks:
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

    def _detect_process_injection(self, records: list[dict], raw: str,
                                  malfind_blocks: list[dict]) -> None:
        """Detect MZ headers and PE signatures in memory.

        v1.2: Uses malfind_blocks to attribute MZ findings to the
        correct owning process instead of 'Unknown (hex dump)'.
        """
        rule = self.rules["memory_indicators"]["process_injection"]

        # ── Primary: malfind blocks (v1.2 -- no more Unknown) ────────────
        for block in malfind_blocks:
            if block.get("has_mz"):
                proc = block["process"]
                pid = block["pid"]
                self._add("process_injection", "Memory", rule,
                          f"{proc} (PID: {pid})",
                          f"MZ/PE header in memory at {block.get('start_vpn', '?')}",
                          "Extract and reverse-engineer the injected code.")

        # ── Fallback: structured records ─────────────────────────────────
        if not malfind_blocks:
            keywords = ["MZ header", "This program cannot be run", "4d 5a"]
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
        """Detect executables with randomized names using multi-factor scoring.

        v1.2: Replaces simple heuristics with a multi-factor randomness
        score combining entropy, consonant ratio, digit mixing, and
        consecutive consonant analysis.
        """
        rule = self.rules["process_indicators"]["random_executable"]

        def _shannon_entropy(s: str) -> float:
            """Calculate Shannon entropy of a string."""
            if not s:
                return 0.0
            freq = {}
            for c in s:
                freq[c] = freq.get(c, 0) + 1
            length = len(s)
            return -sum(
                (count / length) * math.log2(count / length)
                for count in freq.values()
            )

        def _calc_randomness_score(name: str) -> float:
            """Return 0.0-1.0 randomness score using multiple heuristics."""
            base = name.lower().replace(".exe", "")
            if len(base) < 4:
                return 0.0

            score = 0.0
            vowels = set("aeiou")

            # 1. Shannon entropy (high entropy = random)
            # Natural English words: ~3.0-3.5 bits, random: ~4.0+
            entropy = _shannon_entropy(base)
            if entropy > 4.0:
                score += 0.30
            elif entropy > 3.5:
                score += 0.15

            # 2. Consonant/vowel ratio (natural ~1.5, random ~3.0+)
            v_count = sum(1 for c in base if c in vowels)
            c_count = sum(1 for c in base if c.isalpha() and c not in vowels)
            if v_count > 0:
                ratio = c_count / v_count
                if ratio > 4.0:
                    score += 0.25
                elif ratio > 3.0:
                    score += 0.15
            elif c_count >= 4:
                # No vowels at all with 4+ consonants
                score += 0.30

            # 3. Consecutive consonants (>4 = suspicious)
            max_consecutive = 0
            current = 0
            for c in base:
                if c.isalpha() and c not in vowels:
                    current += 1
                    max_consecutive = max(max_consecutive, current)
                else:
                    current = 0
            if max_consecutive >= 5:
                score += 0.20
            elif max_consecutive >= 4:
                score += 0.10

            # 4. Mixed-case mid-word (rAnDoM is suspicious, CamelCase is not)
            if len(name.replace(".exe", "")) >= 6:
                upper_in_mid = sum(1 for c in name[1:-4] if c.isupper())
                lower_in_mid = sum(1 for c in name[1:-4] if c.islower())
                if upper_in_mid >= 3 and lower_in_mid >= 3:
                    score += 0.15

            # 5. Digit mixing (abc123xyz = suspicious for executables)
            has_digits = any(c.isdigit() for c in base)
            has_alpha = any(c.isalpha() for c in base)
            if has_digits and has_alpha:
                digit_ratio = sum(1 for c in base if c.isdigit()) / len(base)
                if 0.2 < digit_ratio < 0.6:
                    score += 0.15

            # 6. Name length (very long random names)
            if len(base) >= 12:
                score += 0.10

            return min(score, 1.0)

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

            # Skip known legitimate names
            if name.lower() in EXTENDED_LEGIT_NAMES:
                continue
            if is_whitelisted_process(name):
                continue

            randomness = _calc_randomness_score(name)
            if randomness >= 0.55:  # Threshold for flagging
                self._add("random_executable", "Process", rule, name,
                          f"Randomised name (score: {randomness:.2f}): {name}",
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
    #  PROCESS RELATIONSHIP INTEGRATION
    # ═══════════════════════════════════════════════════════════════════════

    def integrate_process_relationships(self, relationships) -> None:
        """Convert ProcessRelationship objects into Finding objects.

        Called after process_analyzer.analyze() to merge relationship
        findings into the main findings list.
        """
        for rel in relationships:
            rule = {
                "description": rel.description,
                "severity": rel.severity,
                "score": rel.score,
                "mitre_id": rel.mitre_id,
                "mitre_technique": rel.mitre_technique,
            }
            chain_str = " -> ".join(rel.chain) if rel.chain else ""
            self._add(
                rel.rule_id, "Relationship", rule,
                f"{rel.parent_name} (PID: {rel.parent_pid})",
                f"{rel.parent_name} -> {rel.child_name} ({rel.child_pid})"
                + (f" | Chain: {chain_str}" if chain_str else ""),
                "Investigate the full execution chain for lateral movement or payload delivery.",
            )

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
        malfind_blocks = parsed_data.get("malfind_blocks", [])
        cmdline_recs = parsed_data.get("cmdline", [])
        netstat_recs = parsed_data.get("netstat", [])
        netscan_recs = parsed_data.get("netscan", [])
        psscan_recs  = parsed_data.get("psscan", [])

        # Debug info
        console.print("[dim]  Data available for detection:[/dim]")
        console.print(f"[dim]    malfind : {len(malfind_recs)} records, {len(malfind_blocks)} blocks, {len(raw_malfind)} chars raw[/dim]")
        console.print(f"[dim]    cmdline : {len(cmdline_recs)} records, {len(raw_cmdline)} chars raw[/dim]")
        console.print(f"[dim]    netstat : {len(netstat_recs)} records, {len(raw_netstat)} chars raw[/dim]")
        console.print(f"[dim]    netscan : {len(netscan_recs)} records, {len(raw_netscan)} chars raw[/dim]")
        console.print(f"[dim]    psscan  : {len(psscan_recs)} records, {len(raw_psscan)} chars raw[/dim]")
        console.print()
        console.print("[bold white]  Scanning for threats...[/bold white]\n")

        # Run all detectors
        self._detect_rwx_memory(malfind_recs, raw_malfind, malfind_blocks)
        self._detect_process_injection(malfind_recs, raw_malfind, malfind_blocks)
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
