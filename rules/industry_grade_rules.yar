/*
================================================================================
  ENTERPRISE MULTI-PLATFORM MALWARE TRIAGE & THREAT HUNTING RULESET
  Version: 3.1 (Unified Edition)
  Author: Security Operations & Forensic Analysis Engine
  Target Support: Windows (PE), Linux (ELF), macOS (Mach-O), Java/Android, Scripts
================================================================================
*/

import "pe"
import "elf"

// =============================================================================
// SECTION 1: CROSS-PLATFORM & GENERAL BEHAVIORAL DETECTIONS
// =============================================================================

rule Universal_High_Entropy_Packed_Payload {
    meta:
        description = "Detects files containing packer signatures, strong obfuscation, or compiled binary frameworks"
        author = "Security Forensics"
        severity = "Medium"
        mitre_id = "T1027.002"
        tactic = "Defense Evasion"
    strings:
        // Generic packed/obfuscated marker strings across platforms
        $s1 = "UPX!" ascii
        $s2 = "UPX0" ascii
        $s3 = "UPX1" ascii
        $s4 = "UPX2" ascii
        $s5 = ".themida" ascii nocase
        $s6 = ".vmp0" ascii nocase
        $s7 = ".vmp1" ascii nocase
        $s8 = "Protected by VMProtect" ascii
        $s9 = "PyInstaller_GLL" ascii
        $s10 = "Go build ID:" ascii
    condition:
        // Matches PE files with packer indicators or high section counts (>10)
        (uint16(0) == 0x5A4D and (any of ($s*) or pe.number_of_sections > 10)) or
        // Matches ELF files with packer/obfuscation strings
        (uint32(0) == 0x464C457F and any of ($s*)) or
        // Raw packed blobs or containers
        any of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8)
}

rule Ransomware_CrossPlatform_Extortion_Note {
    meta:
        description = "Detects cross-platform ransomware indicators, crypto addresses, and ransom note text"
        author = "Threat Intelligence"
        severity = "Critical"
        mitre_id = "T1486"
        tactic = "Impact"
    strings:
        $note1 = "Your files have been encrypted" ascii nocase
        $note2 = "All your files were encrypted" ascii nocase
        $note3 = "DECRYPT_INSTRUCTIONS" ascii nocase
        $note4 = "restore your files" ascii nocase
        $note5 = "recover your files" ascii nocase
        $note6 = ".onion" ascii nocase
        $note7 = "bitcoin wallet" ascii nocase
        $note8 = "Tor browser" ascii nocase
        $crypto1 = /1[a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii // Bitcoin P2PKH
        $crypto2 = /3[a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii // Bitcoin P2SH
        $crypto3 = /bc1[a-z0-9]{39,59}/ ascii        // Bitcoin Bech32
        $crypto4 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii // Monero
    condition:
        (2 of ($note*) and 1 of ($crypto*)) or 3 of ($note*)
}

// =============================================================================
// SECTION 2: LINUX (ELF) SPECIFIC THREAT DETECTIONS
// =============================================================================

rule ELF_Linux_Botnet_Mirai_Kinsing_Heuristics {
    meta:
        description = "Detects Linux ELF botnets, C2 persistence scripts, and cryptominer droppers (Mirai/Kinsing)"
        author = "Linux Security Desk"
        severity = "High"
        mitre_id = "T1059.004"
        tactic = "Execution"
    strings:
        $elf_magic = { 7F 45 4C 46 }
        
        // Common Linux persistence & anti-forensics APIs/Commands
        $cmd1 = "/bin/busybox" ascii
        $cmd2 = "/proc/net/tcp" ascii
        $cmd3 = "iptables -F" ascii nocase
        $cmd4 = "/etc/init.d/" ascii
        $cmd5 = "crontab -l" ascii
        
        // Anti-analysis & process hiding
        $api1 = "ptrace" ascii
        $api2 = "process_vm_readv" ascii
        $api3 = "prctl" ascii
        $api4 = "reboot" ascii
    condition:
        $elf_magic at 0 and (3 of ($cmd*) or all of ($api*))
}

rule ELF_Stripped_Binary_With_Raw_Sockets {
    meta:
        description = "Detects stripped Linux ELF binaries requesting raw socket access for DDOS or C2 callbacks"
        author = "Threat Hunting"
        severity = "High"
        mitre_id = "T1095"
        tactic = "Command and Control"
    strings:
        $elf_magic = { 7F 45 4C 46 }
        $sock1 = "socket" ascii
        $sock2 = "AF_INET" ascii
        $sock3 = "SOCK_RAW" ascii
        $sock4 = "ETH_P_ALL" ascii
        $exec1 = "execve" ascii
        $exec2 = "fork" ascii
    condition:
        $elf_magic at 0 and (all of ($sock*) and any of ($exec*))
}

// =============================================================================
// SECTION 3: WINDOWS (PE) SPECIFIC THREAT DETECTIONS
// =============================================================================

rule PE_Windows_Process_Injection_And_Hollowing {
    meta:
        description = "Detects API function combinations essential for Process Injection, Thread Hijacking, or Process Hollowing"
        author = "Windows Threat Analysis"
        severity = "High"
        mitre_id = "T1055"
        tactic = "Defense Evasion"
    strings:
        $mz = { 4D 5A }
        
        // Memory allocation and write
        $inj1 = "VirtualAllocEx" ascii
        $inj2 = "WriteProcessMemory" ascii
        $inj3 = "NtWriteVirtualMemory" ascii
        
        // Remote execution triggers
        $exec1 = "CreateRemoteThread" ascii
        $exec2 = "NtCreateThreadEx" ascii
        $exec3 = "QueueUserAPC" ascii
        $exec4 = "RtlCreateUserThread" ascii
        
        // Process Hollowing APIs
        $hol1 = "NtUnmapViewOfSection" ascii
        $hol2 = "ZwUnmapViewOfSection" ascii
    condition:
        $mz at 0 and (2 of ($inj*) and (1 of ($exec*) or 1 of ($hol*)))
}

rule PE_Windows_Evasion_AntiDebugging_AntiVM {
    meta:
        description = "Detects Windows binaries scanning for sandboxes, debuggers, or virtualized analysis environments"
        author = "Reverse Engineering"
        severity = "Medium"
        mitre_id = "T1497.001"
        tactic = "Defense Evasion"
    strings:
        $mz = { 4D 5A }
        
        // Debugger APIs
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        $dbg4 = "OutputDebugString" ascii
        $dbg5 = "FindWindow" ascii
        
        // Anti-VM Artifacts
        $vm1 = "VMwareVMware" ascii nocase
        $vm2 = "VBoxVideo" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "SANDBOX" ascii nocase
    condition:
        $mz at 0 and (2 of ($dbg*) or 2 of ($vm*))
}

rule PE_Windows_Network_C2_Activity {
    meta:
        description = "Detects network and HTTP communication library strings typical of malware beacons"
        author = "Security Engineering"
        severity = "Medium"
        mitre_id = "T1071.001"
        tactic = "Command and Control"
    strings:
        $mz = { 4D 5A }
        $net1 = "InternetOpenA" ascii
        $net2 = "InternetConnectA" ascii
        $net3 = "HttpOpenRequestA" ascii
        $net4 = "WSAStartup" ascii
        $url_agent = "Mozilla/4.0 (compatible; MSIE 8.0;" ascii
    condition:
        $mz at 0 and (3 of ($net*) or $url_agent)
}

rule PE_Generic_Suspicious_Shellcode_Loader {
    meta:
        description = "Heuristic detection for PE files possessing typical loader strings combined with execution commands"
        author = "Security Engineering"
        severity = "High"
        mitre_id = "T1059"
        tactic = "Execution"
    strings:
        $mz = { 4D 5A }
        $s_shell1 = "\\cmd.exe" ascii nocase
        $s_shell2 = "powershell -enc" ascii nocase
        $s_shell3 = "cmd.exe /c" ascii nocase
        $loader1 = "LoadLibraryA" ascii
        $loader2 = "GetProcAddress" ascii
    condition:
        $mz at 0 and (any of ($s_shell*) and all of ($loader*))
}

// =============================================================================
// SECTION 4: SCRIPT & NON-PE OBFUSCATION DETECTIONS
// =============================================================================

rule Script_PowerShell_Obfuscated_Command_Chain {
    meta:
        description = "Detects obfuscated PowerShell execution flags, encoded payloads, and stealth execution switches"
        author = "SOC Detection Engineering"
        severity = "High"
        mitre_id = "T1059.001"
        tactic = "Execution"
    strings:
        $ps = "powershell" ascii nocase
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-e " ascii nocase
        $enc3 = "-enc " ascii nocase
        $nop = "-NoProfile" ascii nocase
        $w1 = "-WindowStyle Hidden" ascii nocase
        $w2 = "-w hidden" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "-ep bypass" ascii nocase
        $b64_dl = "DownloadString" ascii nocase
        $b64_iwr = "Invoke-WebRequest" ascii nocase
    condition:
        $ps and (1 of ($enc*) and (1 of ($w*) or 1 of ($bypass*) or $nop) or (1 of ($b64*)))
}

rule Container_Java_Android_APK_Malicious_Dropper {
    meta:
        description = "Detects malicious container artifacts in JAR/APK files, including dynamic DEX loading and path traversal"
        author = "Mobile & Container Sec"
        severity = "High"
        mitre_id = "T1407"
        tactic = "Execution"
    strings:
        $zip_header = { 50 4B 03 04 }
        $dex = "classes.dex" ascii
        $dyn1 = "DexClassLoader" ascii
        $dyn2 = "PathClassLoader" ascii
        $traversal = "../" ascii
    condition:
        $zip_header at 0 and $dex and (any of ($dyn*) or $traversal)
}
