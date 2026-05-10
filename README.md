<p align="center">
  <img src="https://img.shields.io/badge/DFIR-Auto_Tool-00d4ff?style=for-the-badge&logo=windows-terminal&logoColor=white" alt="DFIR Auto Tool"/>
</p>

<h1 align="center">🔬 DFIR Auto Tool</h1>

<p align="center">
  <b>Advanced Automated Memory Forensics & Behavioral Threat Intelligence Framework</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2-blue?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Volatility-3-critical?style=flat-square" alt="Volatility 3"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=flat-square" alt="MITRE"/>
  <img src="https://img.shields.io/badge/Platform-Kali_Linux_%7C_Windows-green?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-Educational-yellow?style=flat-square" alt="License"/>
</p>

<p align="center">
  <i>Developed by <b>Eng. Sohib Magdy</b></i>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Detection Engine](#-detection-engine)
- [Behavioral Correlation Engine](#-behavioral-correlation-engine)
- [Process Relationship Analysis](#-process-relationship-analysis)
- [Execution Chain Analysis](#-execution-chain-analysis)
- [IOC Extraction](#-ioc-extraction)
- [MITRE ATT\&CK Mapping](#-mitre-attck-mapping)
- [Supported Volatility Plugins](#-supported-volatility-plugins)
- [Threat Scoring](#-threat-scoring)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Screenshots](#-screenshots)
- [Future Improvements](#-future-improvements)
- [Author](#-author)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

**DFIR Auto Tool** is a professional-grade automated memory forensics framework built on top of **Volatility 3**. It performs end-to-end analysis of Windows memory dumps — from raw plugin execution to behavioral threat intelligence, execution chain correlation, and structured IOC extraction.

Unlike basic memory triage scripts, DFIR Auto Tool applies **multi-layer behavioral heuristics**, **parent-child process relationship analysis**, and **cross-indicator correlation** to produce actionable, confidence-weighted threat assessments with full **MITRE ATT&CK** mapping.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ██████╗ ███████╗██╗██████╗                                    │
│   ██╔══██╗██╔════╝██║██╔══██╗    DFIR Auto Tool v1.2            │
│   ██║  ██║█████╗  ██║██████╔╝    Memory Forensics Framework     │
│   ██║  ██║██╔══╝  ██║██╔══██╗    Behavioral Threat Intelligence │
│   ██████╔╝██║     ██║██║  ██║    Volatility 3 Powered           │
│   ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝                                  │
│                                                                 │
│   Developed by Eng. Sohib Magdy                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why DFIR Auto Tool?

| Problem | Solution |
|---------|----------|
| Manual Volatility analysis is time-consuming | Automated 8-stage pipeline with rich terminal output |
| Raw plugin output lacks context | Structured parsing with process-context-aware attribution |
| Isolated indicators produce false positives | Multi-indicator behavioral correlation engine |
| No visibility into attack chains | Parent-child process tree analysis with PPID data |
| Findings lack threat intel context | MITRE ATT&CK mapping on every finding |
| Scattered IOCs across multiple outputs | Centralized IOC extraction with process enrichment |

---

## ✨ Key Features

### 🧠 Intelligent Detection
- **Process Injection Detection** — MZ/PE header identification in executable memory regions
- **RWX Memory Analysis** — PAGE_EXECUTE_READWRITE region flagging with process attribution
- **Randomized Name Detection** — Multi-factor scoring (Shannon entropy, consonant ratio, digit mixing)
- **Hidden Process Discovery** — Cross-referencing psscan vs. active process listings

### 🔗 Behavioral Analysis
- **Parent-Child Process Relationships** — PPID-based tree construction from pslist/pstree
- **Suspicious Spawn Detection** — Office → shell, browser → cmd, svchost → temp executable
- **Execution Chain Scoring** — Multi-hop chain analysis with behavioral pattern matching
- **Process Spawning Storm Detection** — Abnormal child process proliferation flagging

### 📊 Correlation & Scoring
- **Multi-Indicator Behavioral Correlation** — Groups findings by process with strength-tiered confidence
- **Confidence Levels** — LOW / MEDIUM / HIGH / CRITICAL based on indicator diversity
- **Category-Capped Scoring** — Prevents single-category score inflation (Memory: 40, Process: 35, Network: 25)
- **Effective Score Weighting** — Confidence multipliers adjust raw scores (0.3x → 1.5x)

### 📄 Reporting & IOCs
- **Structured Forensic Reports** — Executive summary, severity distribution, risk assessment
- **Process Tree Visualization** — Text-based ancestry tree in reports
- **Enriched IOC Extraction** — Process-attributed IOCs with PID, command line, and severity classification
- **MITRE ATT&CK Mapping** — Every finding linked to technique IDs and tactic names

---

## 🏗 Architecture

DFIR Auto Tool follows an **8-stage sequential pipeline** architecture. Each stage produces structured data consumed by subsequent stages, enabling progressive enrichment and cross-correlation.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DFIR Auto Tool Pipeline                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────────┐    │
│  │  Memory Dump │───▶│  Stage 1     │───▶│  Stage 2              │    │
│  │  (.mem/.raw) │    │  Volatility  │    │  Output Parsing       │    │
│  └─────────────┘    │  Execution   │    │  (Structured + Raw)   │    │
│                     └──────────────┘    └───────────┬───────────┘    │
│                                                     │                │
│                     ┌──────────────────────────────┐ │                │
│                     │  Stage 3                     │◀┘                │
│                     │  Process Relationship        │                  │
│                     │  Analysis (PPID Tree)        │                  │
│                     └──────────────┬───────────────┘                  │
│                                    │                                  │
│                     ┌──────────────▼───────────────┐                  │
│                     │  Stage 4                     │                  │
│                     │  Threat Detection Engine     │                  │
│                     │  (Rule-Based + Heuristic)    │                  │
│                     └──────────────┬───────────────┘                  │
│                                    │                                  │
│                     ┌──────────────▼───────────────┐                  │
│                     │  Stage 5                     │                  │
│                     │  Behavioral Correlation      │                  │
│                     │  (Cross-Process Grouping)    │                  │
│                     └──────────────┬───────────────┘                  │
│                                    │                                  │
│  ┌─────────────────┐  ┌───────────▼──────────┐  ┌────────────────┐  │
│  │  Stage 6        │  │  Stage 7             │  │  Stage 8       │  │
│  │  IOC Extraction │  │  Threat Scoring      │  │  Report Gen    │  │
│  │  (Enriched)     │  │  (Category-Capped)   │  │  (Final)       │  │
│  └─────────────────┘  └──────────────────────┘  └────────────────┘  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Module Map

| Module | Role | Key Capability |
|--------|------|----------------|
| `volatility_runner.py` | Plugin execution | Subprocess management, timeout handling, optional plugin support |
| `parser.py` | Output parsing | Dual-mode (structured + raw), malfind block context association |
| `process_analyzer.py` | Process intelligence | PPID tree construction, parent-child rules, attack chain detection |
| `detector.py` | Threat detection | RWX/MZ/scripting/random-name/hidden-process/network indicators |
| `correlator.py` | Behavioral correlation | Cross-process indicator grouping, strength-tiered confidence |
| `ioc_extractor.py` | IOC extraction | Process-enriched executables, scripts, IPs, paths, command lines |
| `scoring.py` | Threat scoring | Category caps, confidence multipliers, classification |
| `report_generator.py` | Report generation | Executive summary, process tree, attack chains, MITRE mapping |
| `whitelist.py` | False positive reduction | Process/path whitelisting with suppressible rule tiers |
| `utils.py` | Shared utilities | Logging, directories, banner, Rich console |

---

## 🛡 Detection Engine

The detection engine (`detector.py`) applies **rule-based** and **heuristic** analysis across multiple indicator categories:

### Memory Indicators

| Indicator | Description | MITRE ID | Severity |
|-----------|-------------|----------|----------|
| `rwx_memory` | PAGE_EXECUTE_READWRITE region detected | T1055 | MEDIUM |
| `process_injection` | MZ/PE header in executable memory | T1055.012 | HIGH |

### Process Indicators

| Indicator | Description | MITRE ID | Severity |
|-----------|-------------|----------|----------|
| `wscript_execution` | wscript/cscript execution | T1059.005 | MEDIUM |
| `vbs_script` | VBScript file reference | T1059.005 | MEDIUM |
| `temp_execution` | Process running from Temp/AppData | T1204.002 | LOW |
| `random_executable` | Randomized executable name (multi-factor) | T1036.005 | HIGH |
| `hidden_process` | Process in psscan but not active listings | T1564.001 | HIGH |

### Network Indicators

| Indicator | Description | MITRE ID | Severity |
|-----------|-------------|----------|----------|
| `suspicious_port` | Connection on commonly abused port | T1105 | MEDIUM |

### Multi-Factor Random Name Scoring

The random executable detector uses **6 heuristic factors** instead of simple pattern matching:

```
┌───────────────────────────────────────────────────┐
│          Random Name Scoring (0.0 - 1.0)          │
├───────────────────────────────────────────────────┤
│  1. Shannon Entropy        (>4.0 bits → +0.30)    │
│  2. Consonant/Vowel Ratio  (>4.0     → +0.25)    │
│  3. Consecutive Consonants (≥5       → +0.20)    │
│  4. Mixed-Case Mid-Word   (≥3 each  → +0.15)    │
│  5. Digit Mixing Ratio    (0.2-0.6  → +0.15)    │
│  6. Name Length            (≥12 char → +0.10)    │
├───────────────────────────────────────────────────┤
│  Threshold: ≥ 0.55 → FLAGGED                     │
│  Extended whitelist prevents false positives       │
└───────────────────────────────────────────────────┘
```

---

## 🔗 Behavioral Correlation Engine

The correlation engine (`correlator.py`) groups findings by process and evaluates **indicator diversity** using strength tiers:

```
Indicator Strength Tiers:
  STRONG   → memory_injection, scripting, random_name, process_spawn
  MODERATE → temp_exec, network, hidden_proc
  WEAK     → memory_rwx (common in JIT/.NET)
```

### Confidence Escalation Logic

| Confidence | Criteria | Multiplier |
|------------|----------|------------|
| **CRITICAL** | 4+ categories with ≥1 STRONG, or injection + temp + (network/scripting/spawn) | 1.5x |
| **HIGH** | 3+ categories with ≥1 STRONG, or injection + STRONG combo | 1.0x |
| **MEDIUM** | 2+ categories with ≥1 STRONG, or 2 MODERATE | 0.7x |
| **LOW** | Single category, or weak-only combinations | 0.3x |

> **Key Design Principle:** Two WEAK indicators never escalate to MEDIUM. Behavioral context determines severity, not volume.

---

## 🌲 Process Relationship Analysis

The process analyzer (`process_analyzer.py`) builds an accurate process tree from **pslist/pstree PPID data** and detects suspicious parent-child relationships:

### Suspicious Relationship Rules

| Rule | Parent → Child | MITRE | Severity |
|------|---------------|-------|----------|
| `office_child_spawn` | WINWORD.exe → powershell.exe | T1566.001 | HIGH |
| `script_child_spawn` | wscript.exe → non-system executable | T1059.005 | HIGH |
| `explorer_temp_child` | explorer.exe → temp-located executable | T1204.002 | MEDIUM |
| `explorer_random_child` | explorer.exe → random-name executable | T1036.005 | HIGH |
| `svchost_shell_spawn` | svchost.exe → cmd.exe / powershell.exe | T1055 | HIGH |
| `svchost_temp_child` | svchost.exe → temp-located executable | T1055 | HIGH |
| `powershell_child_spawn` | powershell.exe → non-system executable | T1059.001 | HIGH |
| `browser_shell_spawn` | chrome.exe → cmd.exe | T1189 | MEDIUM |
| `process_spawning_storm` | any process → 5+ unique children | T1059 | MEDIUM |

---

## ⛓ Execution Chain Analysis

### Sample Attack Chain Visualization

```
╔══════════════════════════════════════════════════════════════╗
║              DETECTED ATTACK CHAIN (Depth: 4)                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  WINWORD.exe (PID: 5500)                                     ║
║       │                                                      ║
║       └──▶ wscript.exe (PID: 2200)                           ║
║                 │                                            ║
║                 └──▶ UWkpjFjDzM.exe (PID: 3456)  [!RANDOM]  ║
║                           │                                  ║
║                           └──▶ RWX Memory @ 0x3a50000        ║
║                                MZ Header Detected            ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Chain Risk : CRITICAL                                       ║
║  Pattern    : office_to_script_to_exec                       ║
║  MITRE      : T1566.001 → T1059.005 → T1036.005 → T1055     ║
╚══════════════════════════════════════════════════════════════╝
```

### Chain Scoring Model

```
Chain Score = min(depth_bonus + pattern_bonus + memory_bonus, 25)

  Depth Bonus   :  3-hop → +5  |  4-hop → +8  |  5-hop → +10
  Pattern Bonus :  Matched behavioral pattern → +12 to +20
  Memory Bonus  :  Process in chain has RWX/MZ → +8
  Max Cap       :  25 (prevents chain inflation)
```

> Chain scoring prioritizes **behavioral context** over depth alone. `chrome → chrome_helper` stays LOW, while `WINWORD → wscript → temp.exe` escalates to HIGH/CRITICAL.

---

## 🧩 IOC Extraction

The IOC extractor (`ioc_extractor.py`) produces **process-enriched** indicators of compromise:

| IOC Type | Source | Enrichment |
|----------|--------|------------|
| Executable Files | cmdline, psscan | Process name, PID, command line |
| Script Files | cmdline | Process owner, category (suspicious/malicious) |
| Suspicious Commands | cmdline | PowerShell encoded, certutil, bypass flags |
| IP Addresses | netstat, netscan | Owning process, PID |
| Temp/AppData Paths | cmdline | Process context, full path |
| Non-Standard Ports | netstat, netscan | Port number |

IOC categories are automatically upgraded based on finding severity:
- **Informational** → default for observed artifacts
- **Suspicious** → linked to a detection finding
- **Malicious** → linked to a HIGH/CRITICAL confidence finding

---

## 🗺 MITRE ATT&CK Mapping

Every detection finding is mapped to the MITRE ATT&CK framework:

| Technique ID | Name | Detection Rules |
|-------------|------|-----------------|
| T1055 | Process Injection | `rwx_memory`, `svchost_shell_spawn`, `svchost_temp_child` |
| T1055.012 | Process Hollowing | `process_injection` |
| T1059.001 | PowerShell | `powershell_child_spawn` |
| T1059.005 | Visual Basic | `wscript_execution`, `vbs_script`, `script_child_spawn` |
| T1036.005 | Masquerading | `random_executable`, `explorer_random_child` |
| T1105 | Ingress Tool Transfer | `suspicious_port` |
| T1189 | Drive-by Compromise | `browser_shell_spawn` |
| T1204.002 | Malicious File Execution | `temp_execution`, `explorer_temp_child` |
| T1564.001 | Hidden Files/Directories | `hidden_process` |
| T1566.001 | Spearphishing Attachment | `office_child_spawn` |

---

## 🔌 Supported Volatility Plugins

| Plugin | Status | Purpose |
|--------|--------|---------|
| `windows.info` | **Required** | System information |
| `windows.cmdline` | **Required** | Process command lines |
| `windows.malfind` | **Required** | Injected/suspicious memory regions |
| `windows.psscan` | **Required** | Full process scan (including hidden) |
| `windows.pslist` | Optional | Process list with PPID (for process tree) |
| `windows.pstree` | Optional | Indented process tree with PPID |
| `windows.netstat` | Optional | Active network connections |
| `windows.netscan` | Optional | Network connection scan |

> **Graceful Degradation:** Optional plugins that fail or are unavailable are skipped cleanly. The pipeline continues with available data. Process relationship analysis requires pslist or pstree for accurate PPID data.

---

## 📊 Threat Scoring

```
┌──────────────────────────────────────────────────┐
│             THREAT SCORING ENGINE                │
├──────────────────────────────────────────────────┤
│                                                  │
│  Category Caps (prevents inflation):             │
│    Memory       : max 40 points                  │
│    Process      : max 35 points                  │
│    Network      : max 25 points                  │
│    Relationship : max 30 points                  │
│    Chain        : max 25 points                  │
│                                                  │
│  Confidence Multipliers:                         │
│    LOW      : 0.3x (isolated weak indicators)    │
│    MEDIUM   : 0.7x (moderate correlation)        │
│    HIGH     : 1.0x (strong multi-indicator)      │
│    CRITICAL : 1.5x (confirmed attack pattern)    │
│                                                  │
│  Classification:                                 │
│    0-30   : NORMAL          (green)              │
│    31-60  : SUSPICIOUS      (yellow)             │
│    61-100 : HIGHLY SUSPICIOUS (red)              │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## ⚙ Installation

### Prerequisites

- **Python 3.10+**
- **Volatility 3** installed and accessible via command line
- **Kali Linux** or **Windows** operating system

### Setup

```bash
# Clone the repository
git clone https://github.com/SohibMagdy/DFIR_Auto_Tool.git
cd DFIR_Auto_Tool

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux / Kali:
source venv/bin/activate
# Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

```
rich>=13.0
```

---

## 🚀 Usage

### Full Analysis (with Volatility execution)

```bash
python main.py -f /path/to/memory_dump.mem
```

### Skip Volatility (use pre-existing output files)

```bash
python main.py -f /path/to/memory_dump.mem --skip-vol
```

### Verbose Logging

```bash
python main.py -f /path/to/memory_dump.mem -v
```

### Run Smoke Tests

```bash
python test_v12.py
```

### Output Structure

```
DFIRTool/
├── output/                    # Raw Volatility plugin outputs
│   ├── windows_pslist.txt
│   ├── windows_pstree.txt
│   ├── windows_malfind.txt
│   ├── windows_cmdline.txt
│   ├── windows_psscan.txt
│   ├── windows_netstat.txt
│   └── windows_netscan.txt
├── results/                   # Analysis results
│   ├── final_report.txt       # Complete forensic report
│   ├── suspicious_findings.txt
│   ├── threat_score.txt
│   └── iocs.txt               # Extracted IOCs
└── logs/
    └── dfir_tool.log          # Audit log
```

---

## 📄 Sample Output

### Terminal Output (Rich-formatted)

```
─────────────── Threat Detection Engine ───────────────

[*] Analyzing for indicators of compromise...

  [HIGH] [T1055.012] MZ/PE header found in executable memory region
         Process : explorer.exe (PID: 4840)
  [HIGH] [T1036.005] Executable with randomized name detected
         Process : UWkpjFjDzM.exe
  [MEDIUM] [T1055] PAGE_EXECUTE_READWRITE memory region detected
         Process : UWkpjFjDzM.exe (PID: 3456)
  [MEDIUM] [T1059.005] wscript.exe / cscript.exe execution detected
         Process : wscript.exe

─────────────── Behavioral Correlation Engine ───────────────

  ┌─────────────────────────────────────────────────────────┐
  │ Process    │ Findings │ Indicators        │ Confidence  │
  ├─────────────────────────────────────────────────────────┤
  │ uwkpjf     │ 3        │ memory, random    │ HIGH        │
  │ explor     │ 2        │ memory, injection │ MEDIUM      │
  │ wscript    │ 1        │ scripting         │ LOW         │
  └─────────────────────────────────────────────────────────┘

─────────────── Threat Scoring ───────────────

  Threat Score : 62/100
  Classification: HIGHLY SUSPICIOUS

  ══════════════════════════════════════════════
    THREAT SCORE  : 62/100
    CLASSIFICATION: HIGHLY SUSPICIOUS
    FINDINGS      : 8
    CONFIDENCE    : CRITICAL: 1 | HIGH: 3 | LOW: 4
  ══════════════════════════════════════════════
```

### Report Excerpt

```
======================================================================
  DFIR AUTOMATED FORENSIC REPORT  (v1.2)
  Generated: 2026-05-10 17:45:00
======================================================================

== EXECUTIVE SUMMARY ==========================================

  Total Findings      : 8
  Threat Score        : 62/100
  Risk Classification : HIGHLY SUSPICIOUS

  Detection Confidence Breakdown:
    CRITICAL  : 1 finding(s)
    HIGH      : 3 finding(s)
    MEDIUM    : 2 finding(s)
    LOW       : 2 finding(s)

== PROCESS RELATIONSHIPS ======================================

  Suspicious Parent-Child Relationships:

  1. [HIGH] Office application spawning suspicious child process
     Parent: winword.exe (PID: 5500)
     Child : powershell.exe (PID: 6600)
     MITRE : T1566.001 (Phishing: Spearphishing Attachment)
     Chain : System (PID: 4) -> smss.exe -> csrss.exe ->
             explorer.exe -> winword.exe -> powershell.exe

  Process Tree:

  System (PID: 4)
  `-- smss.exe (PID: 328)
      `-- csrss.exe (PID: 408)
          `-- explorer.exe (PID: 4840)
              |-- winword.exe (PID: 5500)
              |   `-- powershell.exe (PID: 6600)  [!SUSPICIOUS]
              `-- wscript.exe (PID: 2200)
                  `-- UWkpjFjDzM.exe (PID: 3456)  [!SUSPICIOUS]
```

---

## 📸 Screenshots

> Add your screenshots below after running the tool.

### Pipeline Execution
<!-- ![Pipeline Execution](screenshots/pipeline_execution.png) -->
`📷 screenshots/pipeline_execution.png`

### Process Tree Analysis
<!-- ![Process Tree](screenshots/process_tree.png) -->
`📷 screenshots/process_tree.png`

### Behavioral Correlation Summary
<!-- ![Correlation](screenshots/correlation_summary.png) -->
`📷 screenshots/correlation_summary.png`

### Threat Score Classification
<!-- ![Threat Score](screenshots/threat_score.png) -->
`📷 screenshots/threat_score.png`

### Final Report
<!-- ![Final Report](screenshots/final_report.png) -->
`📷 screenshots/final_report.png`

---

## 🔮 Future Improvements

| Feature | Description | Status |
|---------|-------------|--------|
| YARA Integration | Custom YARA rule scanning against extracted memory regions | 🔜 Planned |
| Timeline Analysis | Temporal correlation of process creation and network events | 🔜 Planned |
| HTML/PDF Reports | Interactive reports with collapsible sections and charts | 🔜 Planned |
| VirusTotal API | Automated hash lookups for suspicious executables | 🔜 Planned |
| Sigma Rules | Integration with Sigma detection rule format | 💡 Concept |
| Multi-Dump Comparison | Diff analysis across multiple memory snapshots | 💡 Concept |
| Plugin Auto-Discovery | Dynamic detection of available Volatility plugins | 💡 Concept |
| REST API Mode | Headless analysis mode for SOC integration | 💡 Concept |

---

## 👨‍💻 Author

<p align="center">
  <b>Developed by Eng. Sohib Magdy</b>
</p>

<p align="center">
  Digital Forensics & Incident Response Researcher<br/>
  Cybersecurity Engineering
</p>

<p align="center">
  <a href="https://github.com/SohibMagdy">
    <img src="https://img.shields.io/badge/GitHub-SohibMagdy-181717?style=for-the-badge&logo=github" alt="GitHub"/>
  </a>
</p>

---

## ⚠ Disclaimer

> **This project is intended for educational and authorized DFIR/security research purposes only.**
>
> The tool is designed to assist digital forensics investigators and incident responders in analyzing memory dumps from systems under their authorized control. Do not use this tool on systems or data without explicit written authorization from the system owner.
>
> The author assumes no liability for misuse of this tool. Always comply with applicable local, state, and federal laws when conducting digital forensics investigations.

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_with-Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Powered_by-Volatility_3-FF6B6B?style=flat-square" alt="Volatility"/>
  <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK-EE0000?style=flat-square" alt="MITRE"/>
</p>

<p align="center">
  <sub>⭐ Star this repository if you find it useful for your DFIR workflow</sub>
</p>
