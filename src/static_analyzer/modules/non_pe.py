import math
import re
import base64

class NonPEAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path

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

    def analyze_universal_entropy(self, chunk_size=4096):
        chunks_info = []
        suspicious_indicators = []
        high_entropy_count = 0
        total_chunks = 0
        
        try:
            with open(self.file_path, 'rb') as f:
                offset = 0
                while chunk := f.read(chunk_size):
                    total_chunks += 1
                    ent = self._calculate_entropy(chunk)
                    flags = []
                    if ent > 7.2:
                        high_entropy_count += 1
                        flags.append("High Entropy")

                    chunks_info.append({
                        "offset": hex(offset),
                        "size": len(chunk),
                        "entropy": round(ent, 2),
                        "flags": ", ".join(flags) if flags else "Normal"
                    })
                    offset += len(chunk)

            if high_entropy_count > 0:
                suspicious_indicators.append(
                    f"Detected {high_entropy_count} high-entropy chunks out of {total_chunks} "
                    f"(Threshold > 7.2), suggesting compression, encryption, or packed payloads."
                )
        except Exception as e:
            suspicious_indicators.append(f"Error calculating universal entropy: {e}")

        return chunks_info, suspicious_indicators

    def analyze_heuristics(self, file_content):
        heuristics_found = []
        try:
            text_content = file_content.decode('utf-8', errors='ignore') if file_content else ""

            if text_content:
                b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text_content)
                if len(b64_matches) > 3:
                    heuristics_found.append(f"Multiple large Base64-encoded blocks detected ({len(b64_matches)} instances), suggesting obfuscated payloads.")

                eval_patterns = re.findall(r'\b(eval|exec|system|passthru|shell_exec|base64_decode)\s*\(', text_content, re.IGNORECASE)
                if eval_patterns:
                    unique_evals = list(set(eval_patterns))
                    heuristics_found.append(f"Dangerous execution or evaluation sinks detected: {', '.join(unique_evals)}")

                if re.search(r'-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]+', text_content, re.IGNORECASE):
                    heuristics_found.append("Obfuscated PowerShell EncodedCommand switch detected.")

            if file_content.startswith(b'\x7FELF') and len(file_content) > 40:
                is_64bit = file_content[4] == 2
                shoff_offset = 40 if is_64bit else 32
                shoff = int.from_bytes(file_content[shoff_offset:shoff_offset+8 if is_64bit else 4], byteorder='little')
                if shoff == 0:
                    heuristics_found.append("ELF Header Anomaly: Section headers are stripped or missing (often seen in packed or obfuscated ELF binaries).")

        except Exception as e:
            heuristics_found.append(f"Error during non-PE heuristic evaluation: {e}")

        return heuristics_found

    def inspect_and_decode_base64(self, text_content):
        decoded_results = []
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        matches = set(b64_pattern.findall(text_content))
        
        for match in matches:
            if len(set(match)) < 5:
                continue
                
            try:
                padded_match = match + "=" * ((4 - len(match) % 4) % 4)
                decoded_bytes = base64.b64decode(padded_match)
                
                if len(decoded_bytes) < 16:
                    continue
                    
                payload_type = "Raw Binary / Shellcode"
                inner_text = ""
                inner_iocs = {}
                
                if all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded_bytes):
                    payload_type = "Decoded Script / Plain Text"
                    inner_text = decoded_bytes.decode('utf-8', errors='ignore')
                    inner_iocs = {
                        "ips": list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', inner_text))),
                        "urls": list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', inner_text)))
                    }
                elif decoded_bytes.startswith(b'MZ'):
                    payload_type = "Embedded Windows PE Binary (.exe/.dll)"
                elif decoded_bytes.startswith(b'PK\x03\x04'):
                    payload_type = "Embedded ZIP / Archive Container"
                elif decoded_bytes.startswith(b'\x7FELF'):
                    payload_type = "Embedded Linux ELF Binary"

                decoded_results.append({
                    "encoded_sample": match[:30] + "..." if len(match) > 30 else match,
                    "decoded_size": len(decoded_bytes),
                    "payload_type": payload_type,
                    "preview": inner_text[:120].strip() if inner_text else decoded_bytes[:16].hex(' '),
                    "iocs": inner_iocs
                })
            except Exception:
                continue

        return decoded_results
