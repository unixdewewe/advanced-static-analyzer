# Advanced Universal Static Malware Analysis & Forensics Tool (v2.0)

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-D22128?style=flat&logo=apache&logoColor=white)](https://github.com/unixdewewe/advanced-static-analyzer)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717?style=flat&logo=github&logoColor=white)](https://github.com/unixdewewe/advanced-static-analyzer)

This project provides a professional, Python-based static file forensics and malware triage tool designed to analyze any file format for potential malicious content safely and efficiently. The tool performs universal static analysis techniques including format-agnostic classification, archive/container inspection, sliding-window chunk entropy analysis, PE structure inspection, multi-provider threat intelligence API querying, MITRE ATT&CK technique mapping, YARA rule matching, Mandiant FLOSS string decoding, and IOC regex parsing to help security analysts quickly triage threats.

```bash
(venv) static-analyzer.exe .\samples\6cbc38b79a107e48cc0c657726b04be203f2b5ddd32c2a3e083c3acb8cdd9365.exe --yara-rules .\rules\industry_grade_rules.yar --threat-intel --api-key YOUR_API_b28106ceac844738efbd1_KEY
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│      _        _   _         _                _                                                 │
│  ___| |_ __ _| |_(_) ___   / \   _ __   __ _| |_   _ _______ _ __                              │
│ / __| __/ _` | __| |/ __| / _ \ | '_ \ / _` | | | | |_  / _ \ '__|                             │
│ \__ \ || (_| | |_| | (__ / ___ \| | | | (_| | | |_| |/ /  __/ |                                │
│ |___/\__\__,_|\__|_|\___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|                                │
│                                                |___/                                           │
│                                                                                                │
│ ──────────────────────────────────────────────────────────────────────                         │
│  Version      : v2.0                                                                           │
│  Author       : Rashid Dewewe                                                                  │
│  Repository   : https://github.com/unixdewewe/advanced-static-analyzer                         │
│  Target File  : .\samples\6cbc38b79a107e48cc0c657726b04be203f2b5ddd32c2a3e083c3acb8cdd9365.exe │
│                                                                                                │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

[*] Cryptographic Fingerprints
  MD5     : 5849a31cee6d06c9250755fba7aa04ec
  SHA1    : c7594752950151b344dd59b1c0cff53a9c9ed3fe
  SHA256  : 6cbc38b79a107e48cc0c657726b04be203f2b5ddd32c2a3e083c3acb8cdd9365

[*] File Identification & Header Analysis
  Size: 174182 bytes
  File Classification: Windows PE Executable (.exe, .dll, .sys)
  Magic Details: PE32+ executable (console) x86-64, for MS Windows
  Header Hex (16 bytes): 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
  Header ASCII: MZ..............

[*] Querying Threat Intelligence (Virustotal)...
  Provider: VirusTotal
  Status: Found in Database
  Detections: 51 / 76 engines flagged as malicious

[*] PE Sections & Entropy Analysis
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Section Name ┃ Virtual Address ┃ Raw Size ┃ Entropy ┃ Flags / Status ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ .text        │ 0x1000          │ 20992    │ 5.57    │ Normal         │
│ .data        │ 0x7000          │ 512      │ 0.82    │ Normal         │
│ .rdata       │ 0x8000          │ 13312    │ 5.56    │ Normal         │
│ .pdata       │ 0xc000          │ 1024     │ 3.8     │ Normal         │
│ .xdata       │ 0xd000          │ 1024     │ 3.46    │ Normal         │
│ .bss         │ 0xe000          │ 0        │ 0.0     │ Normal         │
│ .idata       │ 0xf000          │ 4096     │ 4.13    │ Normal         │
│ .tls         │ 0x10000         │ 512      │ 0.0     │ Normal         │
│ .rsrc        │ 0x11000         │ 1536     │ 4.78    │ Normal         │
│ .reloc       │ 0x12000         │ 512      │ 1.47    │ Normal         │
│ /4           │ 0x13000         │ 1536     │ 1.39    │ Normal         │
│ /19          │ 0x14000         │ 45056    │ 5.87    │ Normal         │
│ /31          │ 0x1f000         │ 9216     │ 4.7     │ Normal         │
│ /45          │ 0x22000         │ 8192     │ 4.79    │ Normal         │
│ /57          │ 0x24000         │ 2560     │ 3.75    │ Normal         │
│ /70          │ 0x25000         │ 1024     │ 4.05    │ Normal         │
│ /81          │ 0x26000         │ 6656     │ 4.85    │ Normal         │
│ /97          │ 0x28000         │ 5120     │ 5.05    │ Normal         │
│ /113         │ 0x2a000         │ 512      │ 3.8     │ Normal         │
└──────────────┴─────────────────┴──────────┴─────────┴────────────────┘

[*] Running YARA Scan using rules: .\rules\industry_grade_rules.yar
  [+] Match Rule: Universal_High_Entropy_Packed_Payload (Namespace: default)

[*] Correlated MITRE ATT&CK Techniques
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Detection Source                            ┃ Technique ID ┃ Technique Name                                                          ┃ Tactic          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ YARA: Universal_High_Entropy_Packed_Payload │ T1027.002    │ Detects files containing packer signatures, strong obfuscation, or      │ Defense Evasion │
│                                             │              │ compiled binary frameworks                                              │                 │
└─────────────────────────────────────────────┴──────────────┴─────────────────────────────────────────────────────────────────────────┴─────────────────┘

[*] Extracted Indicators of Compromise (IOCs)
  DOMAINS_AND_SUBDOMAINS:
    - pdata.startup
    - s.tmp
    - s.blackout
    - text.startup
    - xdata.startup
    - gpedit.msc
    - wipe.tmp
  NETWORK_TIMEOUTS_RETRIES_SECONDS:
    - 0
  EXECUTED_COMMANDS:
    - powershell.exe
    - shadows /all /quiet >nul 2>&1
    - show_final_message
    - powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -
  FILE_DIRECTORY_ACCESS:
    - C:\Windows\System32\systray.exe
    - C:\wipe.tmp
    - C:\System
    - C:\Windows\lock.png
    - C:\Program
    - C:\M\B\src\build-UCRT64
    - C:\ProgramData
    - C:\ProgramData\Microsoft\Windows
    - C:\VBox_GAs
    - C:\Windows\System32\gpedit.msc
    ... and 7 more.
  PERMISSION_MODIFICATIONS:
    - icacls "%s" /inheritance:d /c /q >nul 2>&1
    - icacls "%s" /deny Administrators:(F) /t /c /q >nul 2>&1
    - icacls "C:\Windows\regedit.exe" /deny Everyone:(X) /c /q
    - icacls "C:\Users" /deny Administrators:(F) /c /q >nul 2>
    - icacls "C:\Users" /deny Users:(F) /c /q >nul 2>&1
    - icacls "%s" /grant SYSTEM:F /c /q >nul 2>&1
    - icacls "C:\Users" /deny Everyone:(F) /c /q >nul 2>&1
    - icacls "%s" /grant %username%:R /c /q >nul 2>&1
    - icacls "C:\Windows\System32" /inheritance:d /c /q >nul 2
    - icacls "C:\Windows\System32" /deny Administrators:(X) /c
    ... and 14 more.
  KERNEL_SYSTEM_CALLS:
    - NtCurrentTeb
  REGISTRY_KEYS:
    - HKEY_CURRENT_USER
    - HKEY_LOCAL_MACHINE
```

## Key Features

- 🧩 **Modular OOP Architecture**: Built with a clean package structure under `src/static_analyzer/` separating metadata extraction, PE analysis, non-PE heuristics, archives, threat intelligence, and reporting.
- 🔍 **Universal File Classification & Signature Analysis**: Detects headers and classifies Windows PE Executables, Linux ELF binaries, macOS Mach-O files, ZIP/JAR/APK archives, PDF documents, and OLE Office files alongside a 16-byte hex and ASCII dump.
- ☁️ **Multi-Provider Threat Intelligence Lookup**: Queries online hash reputation databases with support for **VirusTotal** (default v3 API), **MalwareBazaar**, and **Hybrid Analysis**.
- 🛡️ **Correlated MITRE ATT&CK Mapping**: Automatically maps suspicious API imports and YARA rule hits to standard MITRE ATT&CK Technique IDs (e.g., `T1055: Process Injection`, `T1497: System Checks`).
- 🗂️ **Archive & Container Inspection**: Opens ZIP, JAR, and APK files recursively to list inner code artifacts (`.class`, `.dex`, `.exe`, `.sh`, `.bat`) and inspect uncompressed payload sizes.
- ⚠️ **Archive Vulnerability Safeguards**: Automatically flags path-traversal indicators (Zip Slip vulnerabilities) within archive headers.
- 🔑 **Cryptographic Fingerprinting**: Calculates MD5, SHA1, SHA256 hashes, and PE Import Hashes (`imphash`) when analyzing Portable Executables.
- 📈 **Universal Chunk Entropy Analysis**: Performs sliding-window entropy scanning across any file type (archives, blobs, scripts) to detect encrypted, packed, or hidden payloads.
- 🏗️ **PE Header & Section Security Scanning**: Inspects section permissions for dangerous flags (e.g., RWX) and calculates per-section Shannon entropy.
- ⚡ **Suspicious API Import Analysis**: Flags Win32 APIs associated with process injection/hollowing, anti-debugging evasion, keylogging, and C2 networking.
- 🎯 **YARA Rule Integration**: Scans files against custom rules or directories (e.g., `./rules/malware_rules.yar`) using `yara-python`.
- 🧬 **Mandiant FLOSS Integration**: Automatically invokes local `floss` binaries to uncover stack strings, decoded strings, and obfuscated artifacts, equipped with automated file size safeguards (> 16MB) to prevent timeouts.
- 📌 **IOC Parsing & String Extraction**: Extracts printable text strings and automatically parses IP addresses, URLs, email addresses, and Windows Registry keys using regular expressions.
- 📊 **Flexible Output & Reporting**: Generates rich terminal dashboards using `rich`, standalone HTML reports (`--export-html`), session logs (`analysis.log`), or standard JSON exports for SOAR pipelines.

## Project Structure

```bash
advanced-static-analyzer/
├── README.md                 # Documentation
├── requirements.txt          # Python dependencies
├── pyproject.toml            # Package configuration & CLI entry points
├── rules/                    
│   └── malware_rules.yar     # Custom YARA threat detection rules
├── samples/                  # Test binaries and archives
├── tests/                    # Unit & integration tests for classes
│   ├── __init__.py
│   ├── test_pe_analyzer.py
│   └── test_threat_intel.py
└── src/
    └── static_analyzer/      # Main package namespace
        ├── __init__.py
        ├── cli.py            # CLI argument parser & entrypoint
        ├── orchestrator.py   # TriageOrchestrator (workflow controller)
        └── modules/          # Specialized domain analyzers
            ├── __init__.py
            ├── banner.py     # ToolBanner & Reporting (HTML/JSON)
            ├── metadata.py   # FileHeaderIdentification & StringIOCExtractor
            ├── pe_analyzer.py # PEAnalyzer (Sections, Imports, MITRE API mapping)
            ├── non_pe.py     # NonPEAnalyzer (Chunk entropy, heuristics, base64 decoder)
            ├── archives.py   # ZipJarInspector (ZIP/JAR/APK recursive traversal)
            ├── floss_wrap.py # FlareFloss wrapper & size safeguards
            ├── yara_engine.py # YaraMitreAttack (Yara rule compiling & mapping)
            └── threat_intel.py # ThreatIntel (VirusTotal, MalwareBazaar, Hybrid Analysis)

```

## Prerequisites

* Python 3.8 or later
* Mandatory dependencies (specified in `requirements.txt` / `pyproject.toml`):
* `pefile`
* `python-magic`
* `rich`
* `yara-python`
* `flare-floss`


* Optional Tools:
* Mandiant FLOSS (`floss` available in system `PATH`).



---

## Sample Results

```bash
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│      _        _   _         _                _                                                 │
│  ___| |_ __ _| |_(_) ___   / \   _ __   __ _| |_   _ _______ _ __                              │
│ / __| __/ _` | __| |/ __| / _ \ | '_ \ / _` | | | | |_  / _ \ '__|                             │
│ \__ \ || (_| | |_| | (__ / ___ \| | | | (_| | | |_| |/ /  __/ |                                │
│ |___/\__\__,_|\__|_|\___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|                                │
│                                                |___/                                           │
│                                                                                                │
│ ──────────────────────────────────────────────────────────────────────                         │
│  Version      : v2.0                                                                           │
│  Author       : Rashid Dewewe                                                                  │
│  Repository   : https://github.com/unixdewewe/advanced-static-analyzer                         │
│  Target File  : .\samples\4f95ac617c436b748175dc09856e835ce7911ae9ad904b36237756e366bf727f.exe │
│                                                                                                │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

[*] Cryptographic Fingerprints
  MD5     : 80363cf53ed46bafdd5267122cecc241
  SHA1    : 9a6423c3c2b64ef5b4756fe5d9f648460d9ec1a4
  SHA256  : 4f95ac617c436b748175dc09856e835ce7911ae9ad904b36237756e366bf727f

[*] File Identification & Header Analysis
  Size: 4000000 bytes
  File Classification: Windows PE Executable (.exe, .dll, .sys)
  Magic Details: PE32+ executable (GUI) x86-64, for MS Windows
  Header Hex (16 bytes): 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
  Header ASCII: MZ..............

[*] PE Sections & Entropy Analysis
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Section Name ┃ Virtual Address ┃ Raw Size ┃ Entropy ┃ Flags / Status ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ .text        │ 0x1000          │ 123392   │ 6.47    │ Normal         │
│ .rdata       │ 0x20000         │ 58368    │ 4.65    │ Normal         │
│ .data        │ 0x2f000         │ 2855936  │ 6.98    │ Normal         │
│ .pdata       │ 0x2ea000        │ 7680     │ 5.27    │ Normal         │
│ .rsrc        │ 0x2ec000        │ 1024     │ 2.23    │ Normal         │
│ .reloc       │ 0x2ed000        │ 2560     │ 5.26    │ Normal         │
└──────────────┴─────────────────┴──────────┴─────────┴────────────────┘

[!] Suspicious API Imports Detected:
  Anti-Debugging / Evasion: IsDebuggerPresent

[*] Running YARA Scan using rules: .\rules\industry_grade_rules.yar
  [+] Match Rule: PE_Windows_Process_Injection_And_Hollowing (Namespace: default)
  [+] Match Rule: PE_Windows_Evasion_AntiDebugging_AntiVM (Namespace: default)
  [+] Match Rule: PE_Windows_Network_C2_Activity (Namespace: default)

[*] Correlated MITRE ATT&CK Techniques
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Detection Source                                 ┃ Technique ID ┃ Technique Name                                                                             ┃ Tactic              ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ IsDebuggerPresent                                │ T1497.001    │ System Checks (Anti-Debugging)                                                             │ Defense Evasion     │
│ YARA: PE_Windows_Process_Injection_And_Hollowing │ T1055        │ Detects API function combinations essential for Process Injection, Thread Hijacking, or    │ Defense Evasion     │
│                                                  │              │ Process Hollowing                                                                          │                     │
│ YARA: PE_Windows_Evasion_AntiDebugging_AntiVM    │ T1497.001    │ Detects Windows binaries scanning for sandboxes, debuggers, or virtualized analysis        │ Defense Evasion     │
│                                                  │              │ environments                                                                               │                     │
│ YARA: PE_Windows_Network_C2_Activity             │ T1071.001    │ Detects network and HTTP communication library strings typical of malware beacons          │ Command and Control │
└──────────────────────────────────────────────────┴──────────────┴────────────────────────────────────────────────────────────────────────────────────────────┴─────────────────────┘

[*] Extracted Indicators of Compromise (IOCs)
  NETWORK_ENDPOINTS_WITH_PORTS:
    - 2.0.0.1
    - 176.113.115.149
    - 185.81.68.156
    - 213.226.113.54
    - 6.0.0.0
    - 1.0.0.1
    - 213.226.113.53
    - 3.1.1.1
    - 131.0.0.0
  DOMAINS_AND_SUBDOMAINS:
    - diamotrix.online
    - s.rowid
    - diamotrix.world
    - s.xBestIndex
    - exodus.wallet
  EXECUTED_COMMANDS:
    - shViewOfFile
    - sh-honduras
    - sh-nicaragua
    - sh-ecuador
    - shared
    - shlwapi.dll
    - sh-nz
    - should reference only one column of table %T
    - should be between 1 and %d
    - SHELL32.dll
    ... and 5 more.
  FILE_DIRECTORY_ACCESS:
    - C:\inetpub
    - D:\xampp
    - E:\wamp64
    - D:\wamp64
    - C:\wamp64
    - E:\inetpub
    - C:\xampp
    - E:\Users\
    - D:\Users\
    - C:\Users\
    ... and 2 more.
  PERMISSION_MODIFICATIONS:
    - AttributesExW
    - AttributesW
    - AttributesA
  KERNEL_SYSTEM_CALLS:
    - NtOpenKey
    - NtQueryInformationProcess
    - NtCreateThreadEx
    - ZwQueryVirtualMemory
    - ZwResumeThread
    - NtUnmapViewOfSection
    - NtSetValueKey
    - NtResumeThread
    
```

---

## Installation & Setup

1. **Clone the repository:**

```bash
git clone [https://github.com/unixdewewe/advanced-static-analyzer.git](https://github.com/unixdewewe/advanced-static-analyzer.git)
cd "advanced-static-analyzer"

```

2. **Create and Activate Virtual Environment:**

* **Windows:**

```powershell
python -m venv venv
.\venv\Scripts\activate

```

* **Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate

```

3. **Install Package in Editable Mode:**

```bash
pip install -e .

```

## Usage

Once installed, you can invoke the package globally using the CLI entry point `static-analyzer`:

```powershell
static-analyzer <file_path> [options]

```

### Options & Flags

* `--yara-rules <path>`: Path to a `.yar` file or directory containing YARA rules (e.g., `.\rules\malware_rules.yar`).
* `--enable-floss`: Run Mandiant FLOSS to extract obfuscated and stack strings.
* `--threat-intel`: Query online hash reputation services for threat data.
* `--ti-provider <provider>`: Choose Threat Intelligence provider: `virustotal` (default), `malwarebazaar`, or `hybridanalysis`.
* `--api-key <key>`: Supply API key directly (or set via environment variable: `VT_API_KEY` / `HA_API_KEY`).
* `--export-html <path>`: Output formatted standalone HTML report (e.g., `report.html`).
* `--json`: Output raw analysis results in JSON format.

### Command Examples

**1. Basic Analysis with Default VirusTotal Threat Intelligence Lookup:**

```powershell
$env:VT_API_KEY="your_virustotal_api_key"
static-analyzer .\samples\malware.exe --threat-intel

```

**2. Query Threat Intel via MalwareBazaar or Hybrid Analysis:**

```powershell
# Query MalwareBazaar (API key required)
static-analyzer .\samples\sample_file.jar --threat-intel --ti-provider malwarebazaar --api-key "your_MalwareBazaar_API_key"

# Query Hybrid Analysis with inline API key
static-analyzer .\samples\malware.exe --threat-intel --ti-provider hybridanalysis --api-key "your_ha_API_key"

```

**3. Comprehensive Forensic Triage (YARA + FLOSS + Threat Intel + HTML Report Export):**

```powershell
static-analyzer .\samples\malware.exe `
  --yara-rules .\rules\malware_rules.yar `
  --enable-floss `
  --threat-intel `
  --export-html report.html

```

**4. Export Analysis Report as JSON:**

```powershell
static-analyzer .\samples\malware.exe --yara-rules .\rules\ --json > report.json

```

## Precautions

* **Safety Warning**: Always execute malware analysis within an isolated, air-gapped Virtual Machine (VM) or sandbox.
* **Legal Notice**: Ensure proper authorization and legal compliance before performing forensic analysis on target files.

---

## Acknowledgments

This tool builds upon and integrates several exceptional open-source libraries, threat intelligence platforms, and security standards widely adopted by the DFIR community:

* **[Mandiant FLOSS (FLARE Obfuscated String Solver)](https://github.com/mandiant/flare-floss)**: For uncovering obfuscated, encoded, and stack strings from binaries.
* **[YARA by VirusTotal](https://github.com/VirusTotal/yara)**: For powering pattern-matching rulesets and multi-platform binary signature detection.
* **[pefile](https://github.com/erocarrera/pefile)**: For parser handling and inspection of Portable Executable (PE) headers and structures.
* **Threat Intelligence Providers**: **[VirusTotal API v3](https://www.virustotal.com/)**, **[MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/)**, and **[Hybrid Analysis](https://www.hybrid-analysis.com/)** for cloud hash reputation lookups.
* **[MITRE ATT&CK®](https://attack.mitre.org/)**: For providing the standardized framework used to map behavioral indicators and suspicious imports to attack techniques.

## Author

**Rashid Dewewe**

BSc in Cyber Security and Digital Forensics Engineering

## License

Distributed under the Apache 2 License. See `LICENSE` for details.
