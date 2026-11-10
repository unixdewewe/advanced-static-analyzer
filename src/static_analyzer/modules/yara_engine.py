import os

class YaraMitreAttack:
    def __init__(self, file_path, rules_path):
        self.file_path = file_path
        self.rules_path = rules_path

    def scan(self):
        try:
            import yara
        except ImportError:
            return ["yara-python module not installed."], []

        matches = []
        mitre_hits = []
        try:
            if os.path.isfile(self.rules_path):
                rules = yara.compile(filepath=self.rules_path)
            elif os.path.isdir(self.rules_path):
                filepaths = {os.path.basename(os.path.splitext(f)[0]): os.path.join(self.rules_path, f) 
                             for f in os.listdir(self.rules_path) if f.endswith('.yar') or f.endswith('.yara')}
                if not filepaths:
                    return [f"No .yar rules found in directory: {self.rules_path}"], []
                rules = yara.compile(filepaths=filepaths)
            else:
                return [f"Invalid YARA rules path: {self.rules_path}"], []

            raw_matches = rules.match(self.file_path)
            for match in raw_matches:
                rule_name = match.rule
                meta_dict = match.meta
                
                matches.append({
                    "rule": rule_name,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": meta_dict
                })

                # Automatically extract MITRE data directly from the YARA rule's meta section
                if "mitre_id" in meta_dict:
                    mitre_hits.append({
                        "source": f"YARA: {rule_name}",
                        "id": meta_dict.get("mitre_id"),
                        "name": meta_dict.get("description", "Malicious Artifact"),
                        "tactic": meta_dict.get("tactic", "Unknown")
                    })
        except Exception as e:
            matches.append(f"YARA scan error: {str(e)}")
            
        return matches, mitre_hits
