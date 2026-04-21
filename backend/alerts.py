import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
ALERT_RECIPIENT = os.environ.get('ALERT_RECIPIENT', '')

def send_alert(attack_type: str, severity: str, source_ip: str, url: str):
    """
    Sends an alert via SMTP if credentials are provided, otherwise falls back to console.
    """
    subject = f"IDS ALERT: {severity} Severity {attack_type} Detected"
    body = f"""
    URL Intrusion Detection System Alert
    ------------------------------------
    Severity: {severity}
    Attack Type: {attack_type}
    Source IP: {source_ip}
    URL: {url}
    
    Please investigate this traffic immediately.
    """
    
    if SMTP_USERNAME and SMTP_PASSWORD and ALERT_RECIPIENT:
        try:
            msg = MIMEMultipart()
            msg['From'] = SMTP_USERNAME
            msg['To'] = ALERT_RECIPIENT
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            text = msg.as_string()
            server.sendmail(SMTP_USERNAME, ALERT_RECIPIENT, text)
            server.quit()
            print(f"[ALERT] Sent email alert to {ALERT_RECIPIENT} for {attack_type}")
        except Exception as e:
            print(f"[ALERT ERROR] Failed to send email: {e}")
            print(f"[CONSOLE FALLBACK ALERT] {subject}\n{body}")
    else:
        # Fallback to console alert simulation
        print(f"\n{'='*50}")
        print(f"[CONSOLE ALERT SIMULATION]")
        print(f"{subject}")
        print(body)
        print(f"{'='*50}\n")
