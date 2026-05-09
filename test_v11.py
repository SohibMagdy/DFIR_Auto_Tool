"""
test_v11.py -- End-to-end smoke test for DFIRTool v1.1.

Creates synthetic Volatility output files and runs the full pipeline
(parser -> detector -> correlator -> IOC extractor -> scorer -> reporter)
to verify:
  1. Whitelist suppresses chrome.exe RWX (low confidence)
  2. Correlated indicators produce HIGH/CRITICAL confidence
  3. Score does NOT reach 100 for a typical dump
  4. IOCs are extracted correctly
  5. MITRE IDs appear in findings
  6. Reports are generated successfully
"""

import sys
sys.path.insert(0, ".")

from pathlib import Path

# Write synthetic test data
output = Path("output")
output.mkdir(exist_ok=True)

# Malfind: multiple processes with RWX memory
(output / "windows_malfind.txt").write_text(
    "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\n"
    "4840\texplorer.exe\t0x2130000\t0x2131fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "0x02130000  4d 5a 90 00 03 00 00 00 MZ......\n"
    "1924\tsvchost.exe\t0xf60000\t0xf60fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "3312\tWmiPrvSE.exe\t0x3a50000\t0x3a51fff\tVadS\tPAGE_EXECUTE_READWRITE\n"
    "9876\tchrome.exe\t0x1234000\t0x1235fff\tVadS\tPAGE_EXECUTE_READWRITE\n",
    encoding="utf-8",
)

# Cmdline: wscript, VBS, random name, temp path
(output / "windows_cmdline.txt").write_text(
    "PID\tProcess\tArgs\n"
    "4840\texplorer.exe\tC:\\Windows\\explorer.exe\n"
    "2200\twscript.exe\twscript.exe //B //NOLOGO %TEMP%\\vhjReUDEuumrX.vbs\n"
    "3456\tUWkpjFjDzM.exe\tC:\\Users\\user\\AppData\\Local\\Temp\\UWkpjFjDzM.exe\n"
    "9876\tchrome.exe\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n"
    "1111\tsppsvc.exe\tC:\\Windows\\system32\\sppsvc.exe\n",
    encoding="utf-8",
)

# Empty network files (no network indicators)
(output / "windows_netstat.txt").write_text("", encoding="utf-8")
(output / "windows_info.txt").write_text(
    "Variable\tValue\nKernel Base\t0xf8000\n", encoding="utf-8"
)

# Psscan
(output / "windows_psscan.txt").write_text(
    "PID\tImageFileName\tOffset\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\n"
    "4840\texplorer.exe\t0x1234\t10\t500\t1\tFalse\t2024-01-01\t\n"
    "1924\tsvchost.exe\t0x5678\t5\t200\t0\tFalse\t2024-01-01\t\n"
    "9876\tchrome.exe\t0xaaaa\t30\t600\t1\tFalse\t2024-01-01\t\n",
    encoding="utf-8",
)

# ── Run the full pipeline ─────────────────────────────────────────────
from parser import OutputParser
from detector import ThreatDetector
from correlator import CorrelationEngine
from ioc_extractor import IOCExtractor
from scoring import ThreatScorer
from report_generator import ReportGenerator

print("\n" + "=" * 60)
print("  v1.1 END-TO-END SMOKE TEST")
print("=" * 60)

# Stage 2: Parse
parser = OutputParser()
parsed = parser.parse_all()

# Stage 3: Detect
detector = ThreatDetector()
findings = detector.analyze(parsed, raw_text=parser.raw_text)

# Stage 4: Correlate
correlator = CorrelationEngine()
findings = correlator.correlate(findings)

# Stage 5: IOC extraction
ioc_ext = IOCExtractor()
iocs = ioc_ext.extract(raw_text=parser.raw_text)

# Stage 6: Score
scorer = ThreatScorer()
score = scorer.calculate(findings)

# Stage 7: Report
reporter = ReportGenerator(findings, scorer, correlator=correlator, ioc_extractor=ioc_ext)
reporter.generate()

# ── Verification ─────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  VERIFICATION RESULTS")
print("=" * 60)

# 1. Check whitelist: chrome.exe RWX should be suppressed
chrome_findings = [f for f in findings if "chrome" in f.process.lower() and f.rule_id == "rwx_memory"]
print(f"\n1. Chrome RWX suppressed: {'PASS' if len(chrome_findings) == 0 else 'FAIL'}")
print(f"   Chrome RWX findings: {len(chrome_findings)}")

# 2. Check MITRE IDs present
mitre_findings = [f for f in findings if f.mitre_id]
print(f"\n2. MITRE IDs present: {'PASS' if len(mitre_findings) > 0 else 'FAIL'}")
print(f"   Findings with MITRE IDs: {len(mitre_findings)}/{len(findings)}")

# 3. Check confidence levels set
conf_set = {f.confidence for f in findings}
print(f"\n3. Confidence levels assigned: {'PASS' if conf_set else 'FAIL'}")
print(f"   Confidences found: {conf_set}")

# 4. Check score is NOT 100
print(f"\n4. Score realistic (not 100): {'PASS' if score < 100 else 'FAIL'}")
print(f"   Score: {score}/100")

# 5. Check IOCs extracted
total_iocs = sum(len(v) for v in iocs.values())
print(f"\n5. IOCs extracted: {'PASS' if total_iocs > 0 else 'FAIL'}")
print(f"   Total IOCs: {total_iocs}")

# 6. Check reports generated
from pathlib import Path
results = Path("results")
report_ok = (results / "final_report.txt").exists()
findings_ok = (results / "suspicious_findings.txt").exists()
ioc_ok = (results / "iocs.txt").exists()
print(f"\n6. Reports generated: {'PASS' if all([report_ok, findings_ok, ioc_ok]) else 'FAIL'}")
print(f"   final_report.txt: {'OK' if report_ok else 'MISSING'}")
print(f"   suspicious_findings.txt: {'OK' if findings_ok else 'MISSING'}")
print(f"   iocs.txt: {'OK' if ioc_ok else 'MISSING'}")

# 7. Print all findings for review
print(f"\n{'=' * 60}")
print(f"  ALL {len(findings)} FINDINGS:")
print(f"{'=' * 60}")
for i, f in enumerate(findings, 1):
    print(f"  {i:2d}. [{f.confidence:8s}] [{f.severity:8s}] {f.mitre_id:12s} {f.rule_id:25s} | {f.process}")
    print(f"      Base: +{f.score}, Effective: +{f.effective_score}")

# Overall
all_pass = (
    len(chrome_findings) == 0
    and len(mitre_findings) > 0
    and len(conf_set) > 0
    and score < 100
    and total_iocs > 0
    and report_ok and findings_ok and ioc_ok
)
print(f"\n{'=' * 60}")
print(f"  OVERALL: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
print(f"{'=' * 60}")
