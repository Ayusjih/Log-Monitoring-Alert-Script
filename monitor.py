import os
import re
import time
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# --- CONFIGURATION ---
LOG_FILE_PATH = "/var/log/auth.log"  # Update to your target log file
INCIDENT_LOG = "alerts.log"
CHECK_INTERVAL = 1.0  # Seconds to wait between reads

# Email Settings (Optional - Fill in to enable email alerts)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASS = "your_app_password"
ALERT_RECIPIENT = "admin@example.com"

# --- DETECTION PATTERNS ---
# Category: (Regex Pattern, Description)
PATTERNS = {
    "Security": [
        (r"Failed password", "Failed login attempt"),
        (r"invalid user", "Unauthorized access attempt"),
        (r"HTTP/1.1\" (401|403|500)", "Web Server Error/Access Denied"),
        (r"SELECT.*FROM.*WHERE", "Potential SQL Injection"),
        (r"root login", "Root login attempt detected")
    ],
    "System": [
        (r"Disk full", "Critical: Disk Space Warning"),
        (r"service crashed", "Process/Service failure"),
        (r"Permission denied", "Repeated permission errors")
    ]
}

# Setup Incident Logging
logging.basicConfig(
    filename=INCIDENT_LOG,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_email_alert(category, message):
    """Sends an email alert to the administrator."""
    if not EMAIL_USER or not EMAIL_PASS:
        return # Skip if credentials aren't provided

    msg = MIMEText(f"Suspicious Activity Detected:\n\nCategory: {category}\nDetails: {message}")
    msg['Subject'] = f"ALERT: {category} Incident Detected"
    msg['From'] = EMAIL_USER
    msg['To'] = ALERT_RECIPIENT

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"[-] Failed to send email alert: {e}")

def process_line(line):
    """Checks a single log line against regex patterns."""
    line = line.strip()
    if not line:
        return

    for category, rules in PATTERNS.items():
        for pattern, description in rules:
            if re.search(pattern, line, re.IGNORECASE):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_msg = f"[{category}] {description} | Line: {line}"
                
                # 1. Console Alert
                print(f"\033[91m!!! ALERT [{timestamp}] {alert_msg}\033[0m")
                
                # 2. Store in alerts.log
                logging.warning(alert_msg)
                
                # 3. Trigger Email
                send_email_alert(category, alert_msg)

def monitor_log():
    """Main loop to monitor the log file in real-time."""
    print(f"[*] Starting monitoring on: {LOG_FILE_PATH}")
    print(f"[*] Incidents will be logged to: {INCIDENT_LOG}")
    
    try:
        if not os.path.exists(LOG_FILE_PATH):
            print(f"[-] Error: File {LOG_FILE_PATH} does not exist.")
            return

        with open(LOG_FILE_PATH, "r") as f:
            # Seek to the end of the file (tail -f behavior)
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(CHECK_INTERVAL)
                    continue
                
                process_line(line)

    except PermissionError:
        print("[-] Error: Insufficient permissions to read the log file. Try running with sudo.")
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    monitor_log()