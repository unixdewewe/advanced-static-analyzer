import os
import hashlib
import logging
import magic
import re

class FileHeaderIdentification:
    def __init__(self, file_path):
        self.file_path = file_path

    def identify_file_format(self, header):
        if header.startswith(b'MZ'):
            return "Windows PE Executable (.exe, .dll, .sys)"
        elif header.startswith(b'\x7FELF'):
            return "Linux ELF Executable / Shared Object"
        elif header.startswith((b'\xFE\xED\xFA\xCE', b'\xCE\xFA\xED\xFE', b'\xFE\xED\xFA\xCF', b'\xCF\xFA\xED\xFE', b'\xCA\xFE\xBA\xBE')):
            return "macOS Mach-O Binary"
        elif header.startswith(b'PK\x03\x04'):
            return "ZIP Archive / JAR / APK / Office OpenXML"
        elif header.startswith(b'%PDF'):
            return "PDF Document"
        elif header.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            return "OLE Compound Document (Legacy MS Office)"
        elif header.startswith(b'Rar!'):
            return "RAR Archive"
        else:
            return "Generic / Unknown Binary Format"

    def get_metadata(self):
        try:
            file_size = os.path.getsize(self.file_path)
            magic_type = magic.from_file(self.file_path)
            
            with open(self.file_path, 'rb') as f:
                header = f.read(64)
                hex_dump = ' '.join(f'{b:02X}' for b in header[:16])
                ascii_dump = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header[:16])

            specific_format = self.identify_file_format(header)

            return {
                "target": self.file_path,
                "size_bytes": file_size,
                "magic_type": magic_type,
                "specific_format": specific_format,
                "header_hex": hex_dump,
                "header_ascii": ascii_dump,
                "is_pe": header[:2] == b'MZ',
                "is_elf": header.startswith(b'\x7FELF'),
                "is_archive": header.startswith(b'PK\x03\x04')
            }
        except Exception as e:
            logging.error(f"Error fetching metadata: {e}")
            return {"error": str(e)}

    def generate_hashes(self, pe_obj=None):
        hashes = {}
        try:
            sha256_hash = hashlib.sha256()
            sha1_hash = hashlib.sha1()
            md5_hash = hashlib.md5()

            with open(self.file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)

            hashes['md5'] = md5_hash.hexdigest()
            hashes['sha1'] = sha1_hash.hexdigest()
            hashes['sha256'] = sha256_hash.hexdigest()

            if pe_obj:
                try:
                    hashes['imphash'] = pe_obj.get_imphash()
                except Exception:
                    hashes['imphash'] = "N/A"

            return hashes
        except Exception as e:
            return {"error": str(e)}


class StringIOCExtractor:
    """Extracts ASCII and Unicode strings, parsing advanced IOCs, ports, timeouts, commands, and domains."""
    def __init__(self, file_path):
        self.file_path = file_path

    def extract(self, min_length=4):
        extracted_strings = set()
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()

            # 1. Extract ASCII strings
            for s in content.split(b'\x00'):
                if len(s) >= min_length and all(32 <= b < 127 for b in s):
                    try:
                        extracted_strings.add(s.decode('utf-8'))
                    except UnicodeDecodeError:
                        pass

            # 2. Extract UTF-16LE Wide Strings (Windows PE wide strings)
            try:
                wide_matches = re.findall(b'(?:[\x20-\x7E]\x00){4,}', content)
                for wm in wide_matches:
                    decoded = wm.decode('utf-16le', errors='ignore')
                    if len(decoded) >= min_length:
                        extracted_strings.add(decoded)
            except Exception:
                pass

            all_text = "\n".join(extracted_strings)

            # 3. Advanced Regex Parsers
            ip_ports = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b', all_text)))
            
            # Dedicated Domain & Subdomain Regex
            raw_domains = re.findall(r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b', all_text)
            
            # Expanded blocklist of file extensions, scripts, and system tokens
            blocklist_extensions = {
                'php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'js', 'css', 
                'exe', 'dll', 'sys', 'txt', 'png', 'jpg', 'jpeg', 'xml', 
                'json', 'tar', 'zip', 'gz', 'bin', 'identifier', 'idata', 'dat'
            }
            
            filtered_domains = []
            for d in set(raw_domains):
                parts = d.split('.')
                tld = parts[-1].lower()
                
                # Exclude if TLD/extension matches script or file extension blocklist
                if tld in blocklist_extensions:
                    continue
                
                # Exclude internal system file artifacts and naming patterns
                if any(term in d.lower() for term in ['recycle', 'identifier', 'system32', 'temp']):
                    continue
                    
                if len(d) > 4:
                    filtered_domains.append(d)

            timeouts = list(set(re.findall(r'(?:timeout|sleep|delay|retry|interval)[=:\s]+(\d+)', all_text, re.IGNORECASE)))
            commands = list(set(re.findall(r'(?:cmd\.exe|powershell|sh|bash|curl|wget|certutil|bitsadmin)[^\r\n]{3,80}', all_text, re.IGNORECASE)))
            file_paths = list(set(re.findall(r'(?:[A-Za-z]:\\[^\s"\'*?<>|]+|/(?:etc|bin|sbin|usr|tmp|var|root|home|Windows|System32|Temp)[^\s"\'*?<>|]+)', all_text)))
            permissions = list(set(re.findall(r'(?:chmod|chown|icacls|attrib|cacls)[^\r\n]{3,50}', all_text, re.IGNORECASE)))
            kernel_apis = list(set(re.findall(r'\b(?:Nt[A-Z]\w+|Zw[A-Z]\w+|sys_[\w]+|ioctl|DeviceIoControl)\b', all_text)))

            iocs = {
                "network_endpoints_with_ports": ip_ports,
                "domains_and_subdomains": filtered_domains,
                "urls": list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', all_text))),
                "network_timeouts_retries_seconds": timeouts,
                "executed_commands": commands[:15],
                "file_directory_access": file_paths[:20],
                "permission_modifications": permissions,
                "kernel_system_calls": kernel_apis,
                "emails": list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', all_text))),
                "registry_keys": list(set(re.findall(r'HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM\\|HKCU\\[^\s]+', all_text, re.IGNORECASE)))
            }

            return list(extracted_strings), iocs
        except Exception as e:
            return [], {"error": str(e)}
