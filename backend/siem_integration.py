import os
import requests
from datetime import datetime

SIEM_WEBHOOK_URL = os.environ.get('SIEM_WEBHOOK_URL', '')

def send_to_siem(url: str, attack_type: str, severity: str, source_ip: str):
    """
    Simulates sending detection logs to an external SIEM.
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "attack_type": attack_type,
        "severity": severity,
        "source_ip": source_ip
    }
    
    if SIEM_WEBHOOK_URL:
        try:
            requests.post(SIEM_WEBHOOK_URL, json=log_entry, timeout=2)
            print(f"[SIEM] Successfully forwarded log for {attack_type}")
        except Exception as e:
            print(f"[SIEM ERROR] Failed to send log: {e}")
    else:
        print(f"[SIEM SIMULATION] Log generated: {log_entry}")
