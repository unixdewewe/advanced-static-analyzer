import struct
import logging

class ELFAnalyzer:
    """Performs deep static analysis of Linux ELF executables and shared objects."""
    def __init__(self, file_path, file_bytes):
        self.file_path = file_path
        self.content = file_bytes

    def analyze(self):
        elf_info = {
            "is_elf": self.content.startswith(b'\x7FELF'),
            "architecture": "Unknown",
            "endianness": "Unknown",
            "entry_point": "N/A",
            "sections_count": 0,
            "segments_count": 0,
            "linked_libraries": [],
            "warnings": []
        }

        if not elf_info["is_elf"]:
            return elf_info

        try:
            # ELF Header Parsing (Ident bytes 4 and 5 determine class and endianness)
            class_bit = self.content[4] # 1 = 32-bit, 2 = 64-bit
            data_encoding = self.content[5] # 1 = LSB (Little), 2 = MSB (Big)
            
            elf_info["architecture"] = "64-bit ELF" if class_bit == 2 else "32-bit ELF"
            elf_info["endianness"] = "Little Endian" if data_encoding == 1 else "Big Endian"
            endian_fmt = '<' if data_encoding == 1 else '>'

            if class_bit == 2:
                # 64-bit ELF Header offsets
                # e_entry: offset 24 (8 bytes), e_phoff: offset 32 (8 bytes), e_shoff: offset 40 (8 bytes)
                e_entry = struct.unpack(f'{endian_fmt}Q', self.content[24:32])[0]
                e_phoff = struct.unpack(f'{endian_fmt}Q', self.content[32:40])[0]
                e_shoff = struct.unpack(f'{endian_fmt}Q', self.content[40:48])[0]
                e_phnum = struct.unpack(f'{endian_fmt}H', self.content[56:58])[0]
                e_shnum = struct.unpack(f'{endian_fmt}H', self.content[60:62])[0]
            else:
                # 32-bit ELF Header offsets
                e_entry = struct.unpack(f'{endian_fmt}I', self.content[24:28])[0]
                e_phoff = struct.unpack(f'{endian_fmt}I', self.content[28:32])[0]
                e_shoff = struct.unpack(f'{endian_fmt}I', self.content[32:36])[0]
                e_phnum = struct.unpack(f'{endian_fmt}H', self.content[44:46])[0]
                e_shnum = struct.unpack(f'{endian_fmt}H', self.content[48:50])[0]

            elf_info["entry_point"] = hex(e_entry)
            elf_info["segments_count"] = e_phnum
            elf_info["sections_count"] = e_shnum

            if e_shoff == 0:
                elf_info["warnings"].append("ELF Header Anomaly: Section header offset is 0 (Stripped/Obfuscated binary).")

            # Extract dynamic libraries (NEEDED entries) by scanning for shared object strings
            # Look for common .so extensions or dynamic linkage tags in the binary blob
            import re
            libs = re.findall(b'([a-zA-Z0-9_.-]+\.so(?:\.\d+)*)', self.content)
            elf_info["linked_libraries"] = list(set([lib.decode('utf-8', errors='ignore') for lib in libs[:15]]))

        except Exception as e:
            logging.error(f"Error parsing ELF structure: {e}")
            elf_info["warnings"].append(f"ELF Parsing Error: {str(e)}")

        return elf_info
