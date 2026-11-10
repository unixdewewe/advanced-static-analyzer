import math
import pefile

MITRE_ATTACK_MAP = {
    "VirtualAllocEx": {"id": "T1055", "tactic": "Defense Evasion, Privilege Escalation", "name": "Process Injection"},
    "WriteProcessMemory": {"id": "T1055", "tactic": "Defense Evasion, Privilege Escalation", "name": "Process Injection"},
    "CreateRemoteThread": {"id": "T1055", "tactic": "Defense Evasion, Privilege Escalation", "name": "Process Injection"},
    "NtWriteVirtualMemory": {"id": "T1055.012", "tactic": "Defense Evasion", "name": "Process Hollowing"},
    "IsDebuggerPresent": {"id": "T1497.001", "tactic": "Defense Evasion", "name": "System Checks (Anti-Debugging)"},
    "CheckRemoteDebuggerPresent": {"id": "T1497.001", "tactic": "Defense Evasion", "name": "System Checks (Anti-Debugging)"},
    "GetAsyncKeyState": {"id": "T1056.001", "tactic": "Collection", "name": "Keylogging"},
    "SetWindowsHookEx": {"id": "T1056.001", "tactic": "Collection", "name": "Keylogging"},
    "WSAStartup": {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"},
    "InternetOpen": {"id": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols"}
}

class PEAnalyzer:
    def __init__(self, file_path, pe_obj=None):
        self.file_path = file_path
        self.pe = pe_obj

    def _calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def analyze_sections(self):
        sections_info = []
        suspicious_indicators = []

        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            raw_data = section.get_data()
            entropy = self._calculate_entropy(raw_data)
            
            characteristics = section.Characteristics
            is_writable = bool(characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])
            is_executable = bool(characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])

            flags = []
            if is_writable and is_executable:
                flags.append("RWX (High Risk)")
                suspicious_indicators.append(f"Section {name} has Write & Execute permissions (common in shellcode loaders).")
            if entropy > 7.2:
                flags.append("High Entropy (Packed/Encrypted)")
                suspicious_indicators.append(f"Section {name} has high entropy ({entropy:.2f}), indicating packing or encryption.")

            sections_info.append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "flags": ", ".join(flags) if flags else "Normal"
            })

        return sections_info, suspicious_indicators

    def check_suspicious_imports(self):
        suspicious_apis = {
            "Process Injection / Hollow": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory"],
            "Anti-Debugging / Evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString", "FindWindow"],
            "Credential Access / Keylogging": ["GetAsyncKeyState", "SetWindowsHookEx", "CryptAcquireContext"],
            "Network / C2 Communication": ["WSAStartup", "InternetOpen", "HttpOpenRequest", "InternetConnect"]
        }
        
        found_apis = {category: [] for category in suspicious_apis}
        mitre_hits = []

        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            for category, apis in suspicious_apis.items():
                                if api_name in apis:
                                    found_apis[category].append(api_name)
                                    if api_name in MITRE_ATTACK_MAP:
                                        m = MITRE_ATTACK_MAP[api_name]
                                        mitre_hits.append({
                                            "source": api_name,
                                            "id": m["id"],
                                            "name": m["name"],
                                            "tactic": m["tactic"]
                                        })
        except Exception:
            pass

        return {cat: list(set(apis)) for cat, apis in found_apis.items() if apis}, mitre_hits
