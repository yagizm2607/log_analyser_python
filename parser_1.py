import numpy as np
import pandas as pd
import re as re
from datetime import datetime
import sys

# System Logs Typical Structure
# timestamp -  host - service - process_id - message


## Log Parsing

events = []

TIMESTAMP_RE = r"[A-Z][a-z]{2,3} \d{1,2} \d{2}:\d{2}:\d{2}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"
PID_RE = r"\[(\d+)\]"

EVENT_PATTERNS = {
    "failed_login": r"Failed password",
    "successful_login": r"Accepted password",
    "invalid_user": r"invalid user",
    "session_start": r"Started session|session opened",
    "session_close": r"Closed session|session closed",
    "sudo_command": r"sudo.*COMMAND=",
    "system_event": r"system event executed",
}

def extract_user(message, event_type):
    
    user = None

    # Invalid user pattern (Highest priority)
    invalid_match = re.search(r"invalid user (\S+)", message)
    if invalid_match:
        user = invalid_match.group(1)
        return user
    
    # Session patterns
    session_match = re.search(r"session opened for user (\S+)", message)
    if session_match:
        return session_match.group(1)
    
    # SSH login patterns
    ssh_match = re.search(r"(?:for|user) (\S+?)(?:\s+from|\s+port|$)", message)
    if ssh_match:
        user = ssh_match.group(1)
        if user not in ["from", "port", "invalid", "failed", "accepted"]:
            return user
        
    # Sudo patterns
    sudo_match = re.search(r"sudo:\s+(\w+)\s+:", message)
    if sudo_match:
        return sudo_match.group(1)
    
    return None

def validate_event(event):
    
    if event["timestamp"] and event["host"]:

        try:
            current_year = datetime.now().year
            fake_date = f"{current_year} {event['timestamp']}"
            
        except:
            event["parse_warning"] = "Invalid timestamp format"


    return event

class LogStats:
    def __init__(self):
        self.total_lines = 0
        self.parsed_events = 0
        self.failed_parses = 0
        self.event_counts = {}

    def update(self, event):
        self.parsed_events += 1
        event_type = event.get("event_type", "unknown")
        self.event_counts[event_type] = self.event_counts.get(event_type, 0) + 1

def parse_auth_log(filename):
    events = []
    stats = LogStats()

    TIMESTAMP_RE = r"[A-Z][a-z]{2,3} \d{1,2} \d{2}:\d{2}:\d{2}"
    IP_RE = r"\d+\.\d+\.\d+\.\d+"
    # PID_RE = r"\[(\d+)\]"

    try:
        with open(filename, "r") as file:
            raw = file.read()
            stats.total_lines = raw.count("\n")
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        return []
    
    chunks = re.split(f"(?={TIMESTAMP_RE})", raw)

    for line_num, chunk in enumerate(chunks, 1):
        line = chunk.strip()
        if not line:
            continue

        # Extract timestamp

        ts_match = re.search(TIMESTAMP_RE, line)
        if not ts_match:
            stats.failed_parses += 1
            continue

        timestamp = ts_match.group()

        # Parse rest of the line

        after_ts = line.split(timestamp, 1)[1].strip()
        parts = after_ts.split()

        if len(parts) < 2:
            stats.failed_parses += 1
            continue

        host = parts[0]
        remainder = " ".join(parts[1:])

        # Parse service and pid

        service = None
        pid = None
        message = remainder

        svc_match = re.match(r"(\w+)(?:\[(\d+)\])?:\s(.*)", remainder)
        if svc_match:
            service = svc_match.group(1)
            pid = svc_match.group(2)
            message = svc_match.group(3)

        # Determine event type

        event_type = None
        for e_type, pattern in EVENT_PATTERNS.items():
            if re.search(pattern, message, re.IGNORECASE):
                event_type = e_type
                break

        # Extract IP and user

        ip_match = re.search(IP_RE, message)
        ip = ip_match.group() if ip_match else None

        user = extract_user(message, event_type)

        try:
            dt = datetime.strptime(f"{datetime.now().year} {timestamp}", 
                                              "%Y %b %d %H:%M:%S")
        except:
            dt = None

        event = {
            "timestamp": dt,
            "host": host,
            "service": service,
            "pid": pid,
            "event_type": event_type,
            "user": user,
            "ip": ip,
            "message": message[:200]
        }

        event = validate_event(event)
        events.append(event)
        stats.update(event)

    print(f"\n📊 Parse Statistics:")
    print(f"  Total lines: {stats.total_lines}")
    print(f"  Parsed events: {stats.parsed_events}")
    print(f"  Failed parses: {stats.failed_parses}")
    print(f"\n📈 Event Types:")
    for event_type, count in stats.event_counts.items():
        print(f"  {event_type}: {count}")
    
    return pd.DataFrame(events)

if __name__ == "__main__":
    print("Running log parser as main script...")
    
    if (len(sys.argv)) > 1:
        log_filename = sys.argv[1]
    else:
        log_filename = "auth.log"
        print(f"No filename provided, using default: {log_filename}")

    events = parse_auth_log(log_filename)



