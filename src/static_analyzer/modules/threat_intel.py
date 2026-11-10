import os
import json
import urllib.request
import urllib.parse
import urllib.error

class ThreatIntel:
    def __init__(self, sha256_hash, provider="virustotal", api_key=None):
        self.sha256 = sha256_hash
        self.provider = provider.lower()
        self.api_key = api_key

    def query(self):
        # Automatically resolve API keys from environment variables if not passed explicitly
        if not self.api_key:
            if self.provider == "virustotal":
                self.api_key = os.environ.get("VT_API_KEY")
            elif self.provider == "hybridanalysis":
                self.api_key = os.environ.get("HA_API_KEY")
            elif self.provider == "malwarebazaar":
                self.api_key = os.environ.get("MALWAREBAZAAR_API_KEY")

        try:
            if self.provider == "virustotal":
                url = f"https://www.virustotal.com/api/v3/files/{self.sha256}"
                headers = {"accept": "application/json"}
                if self.api_key:
                    headers["x-apikey"] = self.api_key
                
                req = urllib.request.Request(url, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        res_json = json.loads(response.read().decode("utf-8"))
                        stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values()) if stats else 0
                        return {
                            "provider": "VirusTotal",
                            "status": "Found in Database",
                            "detections": f"{malicious} / {total} engines flagged as malicious",
                            "malicious_count": malicious
                        }
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        return {"provider": "VirusTotal", "status": "Hash not found in database."}
                    elif e.code == 401:
                        return {"provider": "VirusTotal", "status": "Invalid or missing API key. Provide via --api-key or VT_API_KEY env."}
                    else:
                        return {"provider": "VirusTotal", "status": f"HTTP Error {e.code}"}

            elif self.provider == "malwarebazaar":
                url = "https://mb-api.abuse.ch/api/v1/"
                
                headers = {
                    "User-Agent": "StaticAnalyzer/2.0"
                }
                if self.api_key:
                    headers["Auth-Key"] = self.api_key

                data = urllib.parse.urlencode({"query": "get_info", "hash": self.sha256}).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers=headers)
                
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        res_json = json.loads(response.read().decode("utf-8"))
                        status = res_json.get("query_status")
                        
                        if status == "ok":
                            item = res_json["data"][0]
                            return {
                                "provider": "MalwareBazaar",
                                "status": "Found in Database",
                                "signature": item.get("signature", "Unknown"),
                                "file_name": item.get("file_name", "Unknown"),
                                "file_type": item.get("file_type", "Unknown"),
                                "first_seen": item.get("first_seen", "Unknown"),
                                "tags": item.get("tags", [])
                            }
                        elif status == "hash_not_found":
                            return {"provider": "MalwareBazaar", "status": "Hash not found in database."}
                        elif status == "illegal_hash":
                            return {"provider": "MalwareBazaar", "status": "Invalid hash format provided."}
                        elif status == "no_hash_provided":
                            return {"provider": "MalwareBazaar", "status": "No hash provided in query."}
                        else:
                            return {"provider": "MalwareBazaar", "status": f"Unexpected status: {status}"}
                            
                except urllib.error.HTTPError as e:
                    return {"provider": "MalwareBazaar", "status": f"HTTP Error {e.code}"}
                except Exception as e:
                    return {"provider": "MalwareBazaar", "status": f"API connection error: {str(e)}"}

            elif self.provider == "hybridanalysis":
                url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
                data = urllib.parse.urlencode({"hash": self.sha256}).encode("utf-8")
                headers = {"accept": "application/json", "user-agent": "StaticAnalyzer/2.0"}
                if self.api_key:
                    headers["api-key"] = self.api_key
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        res_json = json.loads(response.read().decode("utf-8"))
                        if res_json and isinstance(res_json, list):
                            item = res_json[0]
                            return {
                                "provider": "Hybrid Analysis",
                                "status": "Found in Database",
                                "verdict": item.get("verdict", "N/A"),
                                "threat_score": item.get("threat_score", "N/A")
                            }
                        else:
                            return {"provider": "Hybrid Analysis", "status": "Hash not found in database."}
                except urllib.error.HTTPError as e:
                    return {"provider": "Hybrid Analysis", "status": f"HTTP Error {e.code}"}

            else:
                return {"status": f"Unknown provider: {self.provider}"}

        except Exception as e:
            return {"status": f"Lookup Failed ({str(e)})"}