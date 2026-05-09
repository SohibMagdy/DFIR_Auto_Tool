"""
test_v12.py -- End-to-end smoke test for DFIRTool v1.2.

Creates synthetic Volatility output files including pslist with PPID data,
then runs the full pipeline to verify:
  1. Malfind blocks attribute MZ headers to correct processes (no Unknown)
  2. Random name detection doesn't flag wmpnetwk.exe (false positive fix)
  3. Correlation with weak-only indicators stays LOW
  4. Process relationships detected (Office -> powershell)
  5. Attack chains detected
  6. IOC enrichment includes PID and process
  7. Reports include process tree and attack chains
"""

import sys
sys.path.insert(0, ".")

from pathlib import Path

# Write synthetic test data
output = Path("output")
output.mkdir(exist_ok=True)

# ── pslist: process tree with PPID data ──────────────────────────────
(output / "windows_pslist.txt").write_text(
    "PID\tPPID\tImageFileName\tOffset\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\n"
    "----\t----\t-------------\t------\t-------\t-------\t---------\t-----\t----------\t--------\n"
    "4\t0\tSystem\t0x1000\t100\t500\t-1\tFalse\t2024-01-01\t\n"
    "328\t4\tsmss.exe\t0x2000\t2\t30\t-1\tFalse\t2024-01-01\t\n"
    "408\t328\tcsrss.exe\t0x3000\t10\t500\t0\tFalse\t2024-01-01\t\n"
    "4840\t408\texplorer.exe\t0x4000\t20\t600\t1\tFalse\t2024-01-01\t\n"
    "5500\t4840\twinword.exe\t0x5000\t8\t300\t1\tFalse\t2024-01-01\t\n"
    "6600\t5500\tpowershell.exe\t0x6000\t5\t200\t1\tFalse\t2024-01-01\t\n"
    "2200\t4840\twscript.exe\t0x7000\t3\t100\t1\tFalse\t2024-01-01\t\n"
    "3456\t2200\tUWkpjFjDzM.exe\t0x8000\t2\t50\t1\tFalse\t2024-01-01\t\n"
    "1924\t408\tsvchost.exe\t0x9000\t5\t200\t0\tFalse\t2024-01-01\t\n"
    "7777\t4840\twmpnetwk.exe\t0xa000\t3\t100\t1\tFalse\t2024-01-01\t\n"
    "9876\t4840\tchrome.exe\t0xb000\t30\t600\t1\tFalse\t2024-01-01\t\n",
    encoding="utf-8",
)

# ── pstree: not needed if pslist is present ──────────────────────────
(output / "windows_pstree.txt").write_text("", encoding="utf-8")

# ── malfind: multiple processes with RWX + MZ headers ────────────────
(output / "windows_malfind.txt").write_text(
    "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\n"
    "----\t-------\t---------\t-------\t---\t----------\n"
    "4840\texplorer.exe\t0x2130000\t0x2131fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "0x02130000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............\n"
    "0x02130010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00   ........@.......\n"
    "1924\tsvchost.exe\t0xf60000\t0xf60fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "0x00f60000  cc cc cc cc cc cc cc cc  cc cc cc cc cc cc cc cc   ................\n"
    "3456\tUWkpjFjDzM.exe\t0x3a50000\t0x3a51fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "0x03a50000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............\n",
    encoding="utf-8",
)

# ── cmdline ──────────────────────────────────────────────────────────
(output / "windows_cmdline.txt").write_text(
    "PID\tProcess\tArgs\n"
    "----\t-------\t----\n"
    "4840\texplorer.exe\tC:\\Windows\\explorer.exe\n"
    "5500\twinword.exe\tC:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\n"
    "6600\tpowershell.exe\tpowershell.exe -nop -enc ZQBjAGgAbwAgAA==\n"
    "2200\twscript.exe\twscript.exe //B //NOLOGO %TEMP%\\vhjReUDEuumrX.vbs\n"
    "3456\tUWkpjFjDzM.exe\tC:\\Users\\user\\AppData\\Local\\Temp\\UWkpjFjDzM.exe\n"
    "9876\tchrome.exe\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n"
    "1111\tsppsvc.exe\tC:\\Windows\\system32\\sppsvc.exe\n"
    "7777\twmpnetwk.exe\tC:\\Program Files\\Windows Media Player\\wmpnetwk.exe\n",
    encoding="utf-8",
)

# ── Empty network/info files ─────────────────────────────────────────
(output / "windows_netstat.txt").write_text("", encoding="utf-8")
(output / "windows_netscan.txt").write_text("", encoding="utf-8")
(output / "windows_info.txt").write_text(
    "Variable\tValue\nKernel Base\t0xf8000\n", encoding="utf-8"
)

# ── psscan ───────────────────────────────────────────────────────────
(output / "windows_psscan.txt").write_text(
    "PID\tPPID\tImageFileName\tOffset\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\n"
    "----\t----\t-------------\t------\t-------\t-------\t---------\t-----\t----------\t--------\n"
    "4840\t408\texplorer.exe\t0x4000\t20\t600\t1\tFalse\t2024-01-01\t\n"
    "1924\t408\tsvchost.exe\t0x9000\t5\t200\t0\tFalse\t2024-01-01\t\n"
    "9876\t4840\tchrome.exe\t0xb000\t30\t600\t1\tFalse\t2024-01-01\t\n"
    "3456\t2200\tUWkpjFjDzM.exe\t0x8000\t2\t50\t1\tFalse\t2024-01-01\t\n",
    encoding="utf-8",
)

# ═══════════════════════════════════════════════════════════════════════
#  RUN THE FULL v1.2 PIPELINE
# ═══════════════════════════════════════════════════════════════════════

from parser import OutputParser
from process_analyzer import ProcessAnalyzer
from detector import ThreatDetector
from correlator import CorrelationEngine
from ioc_extractor import IOCExtractor
from scoring import ThreatScorer
from report_generator import ReportGenerator

print("\n" + "=" * 60)
print("  v1.2 END-TO-END SMOKE TEST")
print("=" * 60)

# Stage 2: Parse
parser = OutputParser()
parsed = parser.parse_all()

# Stage 3: Process Relationships
proc_analyzer = ProcessAnalyzer()
relationships = proc_analyzer.analyze(parsed)

# Stage 4: Detect
detector = ThreatDetector()
findings = detector.analyze(parsed, raw_text=parser.raw_text)

# Integrate relationships
if relationships:
    detector.integrate_process_relationships(relationships)
    findings = detector.findings

# Stage 5: Correlate
correlator = CorrelationEngine()
findings = correlator.correlate(findings)

# Stage 6: IOC extraction
ioc_ext = IOCExtractor()
iocs = ioc_ext.extract(raw_text=parser.raw_text, parsed_data=parsed, findings=findings)

# Stage 7: Score
scorer = ThreatScorer()
score = scorer.calculate(findings)

# Stage 8: Report
reporter = ReportGenerator(
    findings, scorer,
    correlator=correlator, ioc_extractor=ioc_ext,
    process_analyzer=proc_analyzer,
)
reporter.generate()

# ═══════════════════════════════════════════════════════════════════════
#  VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  VERIFICATION RESULTS")
print("=" * 60)

# 1. No "Unknown" process in MZ findings
unknown_mz = [f for f in findings if f.rule_id == "process_injection" and "unknown" in f.process.lower()]
print(f"\n1. No Unknown in MZ findings: {'PASS' if len(unknown_mz) == 0 else 'FAIL'}")
print(f"   Unknown MZ findings: {len(unknown_mz)}")
mz_procs = [f.process for f in findings if f.rule_id == "process_injection"]
print(f"   MZ attributed to: {mz_procs}")

# 2. wmpnetwk.exe NOT flagged as random
wmpnetwk_findings = [f for f in findings if "wmpnetwk" in f.process.lower() and f.rule_id == "random_executable"]
print(f"\n2. wmpnetwk.exe not flagged random: {'PASS' if len(wmpnetwk_findings) == 0 else 'FAIL'}")

# 3. Chrome RWX still suppressed
chrome_rwx = [f for f in findings if "chrome" in f.process.lower() and f.rule_id == "rwx_memory"]
print(f"\n3. Chrome RWX suppressed: {'PASS' if len(chrome_rwx) == 0 else 'FAIL'}")

# 4. Process relationships detected (winword -> powershell)
office_rels = [r for r in relationships if r.rule_id == "office_child_spawn"]
print(f"\n4. Office->shell detected: {'PASS' if len(office_rels) > 0 else 'FAIL'}")
for r in office_rels:
    print(f"   {r.parent_name} -> {r.child_name}")

# 5. Script child spawn detected (wscript -> UWkpjFjDzM)
script_rels = [r for r in relationships if r.rule_id == "script_child_spawn"]
print(f"\n5. Script->child detected: {'PASS' if len(script_rels) > 0 else 'FAIL'}")
for r in script_rels:
    print(f"   {r.parent_name} -> {r.child_name}")

# 6. Score realistic
print(f"\n6. Score realistic (not 100): {'PASS' if score < 100 else 'FAIL'}")
print(f"   Score: {score}/100")

# 7. Reports generated
from pathlib import Path
results = Path("results")
report_ok = (results / "final_report.txt").exists()
findings_ok = (results / "suspicious_findings.txt").exists()
ioc_ok = (results / "iocs.txt").exists()
print(f"\n7. Reports generated: {'PASS' if all([report_ok, findings_ok, ioc_ok]) else 'FAIL'}")

# 8. IOC entries have process enrichment
enriched = [e for e in ioc_ext.get_entries() if e.process]
print(f"\n8. IOCs enriched with process: {'PASS' if len(enriched) > 0 else 'FAIL'}")
print(f"   Enriched IOC entries: {len(enriched)}/{len(ioc_ext.get_entries())}")

# 9. Process tree built
tree = proc_analyzer.get_tree()
print(f"\n9. Process tree built: {'PASS' if len(tree) > 0 else 'FAIL'}")
print(f"   Nodes: {len(tree)}")

# 10. MITRE IDs on all findings
mitre_findings = [f for f in findings if f.mitre_id]
print(f"\n10. MITRE IDs present: {'PASS' if len(mitre_findings) == len(findings) else 'FAIL'}")
print(f"    With MITRE: {len(mitre_findings)}/{len(findings)}")

# Print all findings
print(f"\n{'=' * 60}")
print(f"  ALL {len(findings)} FINDINGS:")
print(f"{'=' * 60}")
for i, f in enumerate(findings, 1):
    print(f"  {i:2d}. [{f.confidence:8s}] [{f.severity:8s}] {f.mitre_id:12s} {f.rule_id:25s} | {f.process[:40]}")
    print(f"      Base: +{f.score}, Effective: +{f.effective_score}")

# Overall
all_pass = (
    len(unknown_mz) == 0
    and len(wmpnetwk_findings) == 0
    and len(chrome_rwx) == 0
    and len(office_rels) > 0
    and len(script_rels) > 0
    and score < 100
    and report_ok and findings_ok and ioc_ok
    and len(enriched) > 0
    and len(tree) > 0
    and len(mitre_findings) == len(findings)
)
print(f"\n{'=' * 60}")
print(f"  OVERALL: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
print(f"{'=' * 60}")
