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
                self.api_key = os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("MB_API_KEY")

            # VirusTotal API v3 endpoint 
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
                    if e.code == 403:
                        return {"provider": "MalwareBazaar", "status": "HTTP 403 Forbidden: Invalid or unauthorized Auth-Key."}
                    return {"provider": "MalwareBazaar", "status": f"HTTP Error {e.code}"}
                except Exception as e:
                    return {"provider": "MalwareBazaar", "status": f"API connection error: {str(e)}"}
            
            # Hybrid Analysis API v2 endpoint for hash search
            elif self.provider == "hybridanalysis":
                params = urllib.parse.urlencode({"hash": self.sha256})
                url = f"https://www.hybrid-analysis.com/api/v2/search/hash?{params}"
                headers = {"accept": "application/json", "user-agent": "StaticAnalyzer/2.0"}
                if self.api_key:
                    headers["api-key"] = self.api_key
                req = urllib.request.Request(url, headers=headers, method="GET")
                
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        res_json = json.loads(response.read().decode("utf-8"))
                        reports = res_json.get("reports", [])
                        if reports and isinstance(reports, list):
                            item = reports[0]
                            return {
                                "provider": "Hybrid Analysis",
                                "status": "Found in Database",
                                "report_id": item.get("id", "N/A"),
                                "environment": item.get("environment_description", "N/A"),
                                "state": item.get("state", "N/A"),
                                "verdict": item.get("verdict", "N/A")
                            }
                        else:
                            return {"provider": "Hybrid Analysis", "status": "Hash not found in database."}
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        return {"provider": "Hybrid Analysis", "status": "Hash not found in database."}
                    elif e.code == 401:
                        return {"provider": "Hybrid Analysis", "status": "Invalid or missing API key."}
                    return {"provider": "Hybrid Analysis", "status": f"HTTP Error {e.code}"}

            else:
                return {"status": f"Unknown provider: {self.provider}"}

        except Exception as e:
            return {"status": f"Lookup Failed ({str(e)})"}
