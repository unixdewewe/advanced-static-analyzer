import zipfile

class ZipJarInspector:
    def __init__(self, file_path):
        self.file_path = file_path

    def inspect_contents(self):
        archive_info = []
        suspicious_indicators = []
        
        try:
            if not zipfile.is_zipfile(self.file_path):
                return [], ["Not a valid ZIP/archive structure."]

            with zipfile.ZipFile(self.file_path, 'r') as zf:
                namelist = zf.namelist()
                for filename in namelist:
                    info = zf.getinfo(filename)
                    flags = []
                    if filename.endswith(('.class', '.dex', '.exe', '.dll', '.sh', '.bat', '.ps1')):
                        flags.append("Executable / Code Artifact")
                    
                    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
                        flags.append("Suspicious Path Traversal Name")
                        suspicious_indicators.append(f"Archive entry contains suspicious path traversal: {filename}")

                    archive_info.append({
                        "filename": filename,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                        "flags": ", ".join(flags) if flags else "Normal"
                    })
            
            return archive_info, suspicious_indicators
        except Exception as e:
            return [], [f"Error parsing archive structure: {e}"]
