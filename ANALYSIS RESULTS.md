
## sample 1 (windows PE)

```bash
(venv) static-analyzer.exe .\samples\6cbc38b79a107e48cc0c657726b04be203f2b5ddd32c2a3e083c3acb8cdd9365.exe --yara-rules .\rules\industry_grade_rules.yar --threat-intel --api-key YOUR_b28106cea_API_c844738efbd1_KEY
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


## sample 2 (windows PE)
```
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


# sample 3 (Linux ELF)

```bash
╭────────────────────────────────────────────────────────────────────────╮
│      _        _   _         _                _                         │
│  ___| |_ __ _| |_(_) ___   / \   _ __   __ _| |_   _ _______ _ __      │
│ / __| __/ _` | __| |/ __| / _ \ | '_ \ / _` | | | | |_  / _ \ '__|     │
│ \__ \ || (_| | |_| | (__ / ___ \| | | | (_| | | |_| |/ /  __/ |        │
│ |___/\__\__,_|\__|_|\___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|        │
│                                                |___/                   │
│                                                                        │
│ ────────────────────────────────────────────────────────────────────── │
│  Version      : v2.0                                                   │
│  Author       : Rashid Dewewe                                          │
│  Repository   : https://github.com/unixdewewe/advanced-static-analyzer │
│  Target File  : .\samples\phantom_ring\agent                           │
│                                                                        │
╰────────────────────────────────────────────────────────────────────────╯

[*] Cryptographic Fingerprints
  MD5     : 6d9a243b881984aa25fc0e770dc0634c
  SHA1    : 6580406b3487c7bc32ae8024add3715131f53d24
  SHA256  : 2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5

[*] File Identification & Header Analysis
  Size: 31192 bytes
  File Classification: Linux ELF Executable / Shared Object
  Magic Details: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID=1f617f2ea259a7ec724d7bbc01627982dc2f0495, for GNU/Linux 3.2.0, not stripped
  Header Hex (16 bytes): 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00
  Header ASCII: .ELF............

[*] Universal Chunk Entropy & Non-PE Heuristic Analysis

[*] Deep ELF Binary Complete Analysis
  Architecture: 64-bit ELF (Little Endian)
  Entry Point: 0x1520
  Program Segments: 13 | Sections: 31
  Linked Shared Libraries (.so): libc.so.6, liburing.so.2, ld-linux-x86-64.so.2

[!] Uncovered 3 Decoded Base64 Payload(s):
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sample Offset / String            ┃ Decoded Size ┃ Payload Type           ┃ Preview / Extracted Content                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HEHEHHHUuHEHHEH+HEUHEHHEHHUHEH... │ 30 bytes     │ Raw Binary / Shellcode │ 1c 41 c4 1c 71 d4 b8 71 07 1c 41 fe 1c 45 07 10 │
│ /sys/kernel/debug/tracing/trac... │ 24 bytes     │ Raw Binary / Shellcode │ fe cc ac fe 47 ab 9d e9 7f 75 e6 ee 83 fb 6b 69 │
│ /sys/kernel/debug/tracing/curr... │ 24 bytes     │ Raw Binary / Shellcode │ fe cc ac fe 47 ab 9d e9 7f 75 e6 ee 83 fb 6b 69 │
└───────────────────────────────────┴──────────────┴────────────────────────┴─────────────────────────────────────────────────┘

[*] Running YARA Scan using rules: .\rules\industry_grade_rules.yar

[*] Extracted Indicators of Compromise (IOCs)
  NETWORK_ENDPOINTS_WITH_PORTS:
    - 192.168.56.1
  DOMAINS_AND_SUBDOMAINS:
    - note.gnu.property
    - note.gnu.build
    - liburing.so
    - libc.so
    - ld-linux-x86-64.so
    - gnu.hash
    - rela.dyn
    - plt.sec
    - note.ABI
    - gnu.version
    ... and 2 more.
  EXECUTED_COMMANDS:
    - shstrtab
  FILE_DIRECTORY_ACCESS:
    - /var/run/utmp
    - /usr/bin/%s
    - /usr/bin
```


# sample 4 (JAR / Archive)

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
│  Target File  : .\samples\392b555cbb1debf96622ca9827c844b6809de952fae473ad369b68e526f79b63.jar │
│                                                                                                │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

[*] Cryptographic Fingerprints
  MD5     : 18c4dc32b0ffe676b104b12475277081
  SHA1    : 49de9d42f9ebb1PbWWqgKDBDorh525uecKaGZD21FGSoCeR
  SHA256  : 392b555cbb1debf96622ca9827c844b6809de952fae473ad369b68e526f79b63

[*] File Identification & Header Analysis
  Size: 22818626 bytes
  File Classification: ZIP Archive / JAR / APK / Office OpenXML
  Magic Details: Zip archive data, at least v2.0 to extract
  Header Hex (16 bytes): 50 4B 03 04 14 00 00 00 08 00 A8 3D 65 5D 3E 8B
  Header ASCII: PK.........=e]>.

[*] Archive Contents & Inner File Inspection (JAR/ZIP/APK)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Inner File Path                                           ┃ Uncompressed Size ┃ Status / Flags             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ META-INF/MANIFEST.MF                                      │ 445               │ Normal                     │
│ net/fabric/Niilna.class                                   │ 55254             │ Executable / Code Artifact │
│ net/fabric/aOoBqKI6W$oIc.class                            │ 671               │ Executable / Code Artifact │
│ net/fabric/aOoBqKI6W$tlqyatcCfg.class                     │ 1372              │ Executable / Code Artifact │
│ net/fabric/aOoBqKI6W$szlfchHelper.class                   │ 1005              │ Executable / Code Artifact │
│ net/fabric/aOoBqKI6W.class                                │ 22844             │ Executable / Code Artifact │
│ net/fabric/qynxb_dz_dmwf.class                            │ 12220             │ Executable / Code Artifact │
│ net/fabric/FcVwQ.class                                    │ 7583              │ Executable / Code Artifact │
│ net/fabric/wlmmnh.class                                   │ 24870             │ Executable / Code Artifact │
│ META-INF/                                                 │ 0                 │ Normal                     │
│ META-INF/jars/                                            │ 0                 │ Normal                     │
│ META-INF/jars/lwjgl-shaderc-3.3.3-natives-linux.jar       │ 2666943           │ Normal                     │
│ META-INF/jars/lwjgl-shaderc-3.3.3-natives-macos-arm64.jar │ 1943635           │ Normal                     │
│ META-INF/jars/lwjgl-shaderc-3.3.3-natives-macos.jar       │ 2223583           │ Normal                     │
│ META-INF/jars/lwjgl-shaderc-3.3.3-natives-windows.jar     │ 1781262           │ Normal                     │
│ META-INF/jars/lwjgl-shaderc-3.3.3.jar                     │ 30444             │ Normal                     │
│ META-INF/jars/lwjgl-vma-3.3.3-natives-linux.jar           │ 59493             │ Normal                     │
│ META-INF/jars/lwjgl-vma-3.3.3-natives-macos-arm64.jar     │ 60133             │ Normal                     │
│ META-INF/jars/lwjgl-vma-3.3.3-natives-macos.jar           │ 64471             │ Normal                     │
│ META-INF/jars/lwjgl-vma-3.3.3-natives-windows.jar         │ 127810            │ Normal                     │
│ META-INF/jars/lwjgl-vma-3.3.3.jar                         │ 103658            │ Normal                     │
│ META-INF/jars/lwjgl-vulkan-3.3.3-natives-macos-arm64.jar  │ 1906988           │ Normal                     │
│ META-INF/jars/lwjgl-vulkan-3.3.3-natives-macos.jar        │ 2101963           │ Normal                     │
│ META-INF/jars/lwjgl-vulkan-3.3.3.jar                      │ 6064936           │ Normal                     │
│ assets/                                                   │ 0                 │ Normal                     │
└───────────────────────────────────────────────────────────┴───────────────────┴────────────────────────────┘
  ... and 1036 more inner files omitted from table.

[*] Universal Chunk Entropy & Non-PE Heuristic Analysis

[!] Non-PE / Obfuscation Anomalies Detected:
  - Detected 5546 high-entropy chunks out of 5571 (Threshold > 7.2), suggesting compression, encryption, or packed payloads.
  - Multiple large Base64-encoded blocks detected (1368 instances), suggesting obfuscated payloads.

[!] Uncovered 739 Decoded Base64 Payload(s):
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sample Offset / String            ┃ Decoded Size ┃ Payload Type           ┃ Preview / Extracted Content                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ assets/boyz/textures/capes/pur... │ 27 bytes     │ Raw Binary / Shellcode │ 6a cb 1e b6 cf db a3 2c ff b5 ec 6d ba b7 ac fd │
│ hack/boyz/client/utils/strings... │ 33 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fe eb 62 96 │
│ hack/boyz/client/features/impl... │ 36 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fd f7 9a b6 │
│ hack/boyz/client/vulkan/graphi... │ 30 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fe fb a5 91 │
│ assets/boyz/shaders/vk/compute... │ 27 bytes     │ Raw Binary / Shellcode │ 6a cb 1e b6 cf db a3 2c ff b2 16 9d 7a bb 3f be │
│ hack/boyz/client/event/EventMa... │ 24 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fd eb de 9e │
│ hack/boyz/client/utils/traject... │ 39 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fe eb 62 96 │
│ hack/boyz/client/features/impl... │ 33 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fd f7 9a b6 │
│ hack/boyz/client/utils/ChatUti... │ 24 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fe eb 62 96 │
│ hack/boyz/client/screens/click... │ 48 bytes     │ Raw Binary / Shellcode │ 85 a7 24 fd ba 32 cf f7 25 89 e9 ed fe c7 2b 79 │
└───────────────────────────────────┴──────────────┴────────────────────────┴─────────────────────────────────────────────────┘

[*] Running YARA Scan using rules: .\rules\industry_grade_rules.yar

[*] Extracted Indicators of Compromise (IOCs)
  No high-value IOCs found via regex triage.
```