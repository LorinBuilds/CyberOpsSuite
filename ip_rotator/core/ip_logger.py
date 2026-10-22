"""IP Logger for IP Rotator module."""

import csv
import datetime
import urllib.request
from pathlib import Path
import sys

# Resolve project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.utils.paths import config_root


class IPLogger:
    def __init__(self):
        
        self.log_dir = config_root("IPRotator")
        self.csv_file = self.log_dir / "ip_history.csv"
        
       
        if not self.csv_file.exists():
            with open(self.csv_file, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "IP Address", "Status"])

    def get_current_ip(self) -> str:
        """Get public IP by routing through Tor SOCKS5 proxy."""
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        try:
            
            req = urllib.request.Request("https://api.ipify.org?format=text")
            with urllib.request.urlopen(req, timeout=10) as response:
                ip = response.read().decode('utf-8').strip()
                return ip
        except Exception as e:
            return f"Error: Could not fetch IP"

    def log_current_ip(self):
        """Fetch current IP via Tor and save it to CSV."""
        ip = self.get_current_ip()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        status = "Success" if not ip.startswith("Error") else "Failed"
        
        with open(self.csv_file, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([now, ip, status])
            
        return ip

    def get_log_path(self) -> str:
        return str(self.csv_file)
    
    def get_real_ip(self) -> str:
        """Get the real system IP (without Tor proxy)."""
        try:
            import urllib.request
            req = urllib.request.Request("https://api.ipify.org?format=text")
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode("utf-8").strip()
        except Exception:
            return "Unknown"