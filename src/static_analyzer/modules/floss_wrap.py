import os
import subprocess

class FlareFloss:
    def __init__(self, file_path):
        self.file_path = file_path

    def run(self):
        floss_results = {"status": "skipped", "strings": []}
        file_size = os.path.getsize(self.file_path)
        
        if file_size > 0x1000000:
            floss_results["status"] = "skipped: file size exceeds FLOSS analysis threshold (> 16MB)."
            return floss_results

        try:
            result = subprocess.run(
                ["floss", "--quiet", self.file_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=60
            )
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                floss_results["status"] = "success"
                floss_results["strings"] = [line.strip() for line in lines if line.strip()][:50]
            else:
                floss_results["status"] = f"error: {result.stderr.strip()}"
        except FileNotFoundError:
            floss_results["status"] = "FLOSS tool not installed or not in system PATH."
        except subprocess.TimeoutExpired:
            floss_results["status"] = "error: FLOSS execution timed out after 60 seconds."
        except Exception as e:
            floss_results["status"] = f"error: {str(e)}"
            
        return floss_results
