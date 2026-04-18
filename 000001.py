import numpy as np
import pandas as pd
import re as re

# System Logs Typical Structure
# timestamp -  host - service - process_id - message


## Log Parsing

events = []

TIMESTAMP_RE = r"[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}"
IP_RE = r"\d+\.\d+\.\d+\.\d+"
PID_RE = r"\[(\d+)\]"

EVENT_PATTERNS = {
    "failed_login": r"Failed password",
    "successful_login": r"Accepted password",
    "invalid_user": r"invalid user",
    "session_start": r"Started session|session opened",
    "system_event_executed": r"system event executed",
}

with open("auth.log", "r") as file:
    raw = file.read()

chunks = re.split(f"(?={TIMESTAMP_RE})", raw)

for line in chunks:
        
        line = line.strip()
        if not line:
            continue

        # --------------------
        # Timestamp (anywhere)
        # --------------------

        ts_match = re.search(TIMESTAMP_RE, line)
        if not ts_match:
            continue

        timestamp = ts_match.group()
        
        # --------------------
        # Host (after timestamp)
        # --------------------

        after_ts = line.split(timestamp, 1)[1].strip()
        parts = after_ts.split()


        if len(parts) < 1:
            continue

        host = parts[0]

        if len(parts) < 2:
            continue
        
        # --------------------
        # Service + Message
        # --------------------

        remainder = " ".join(parts[1:])

        service = None
        pid = None
        message = remainder

        svc_match = re.match(r"(\w+)(\[(\d+)\])?:\s(.*)", remainder)
        if svc_match:
            service = svc_match.group(1)
            pid = svc_match.group(3)
            message = svc_match.group(4)

        # --------------------
        # Event Type (regex)
        # --------------------

        event_type = None

        for e_type, pattern in EVENT_PATTERNS.items():
            if re.search(pattern, message):
                event_type = e_type
                break

        # --------------------
        # IP Extraction
        # --------------------

        ip_match = re.search(IP_RE, message)
        if ip_match:
            ip = ip_match.group()
        else:
            ip = None

        # --------------------
        # USER Extraction
        # --------------------

        user = None

        invalid_match = re.search(r"invalid user (\w+)", message)
        if invalid_match:
            user = invalid_match.group(1)
        else:
            user_match = re.search(r"(?:for|of)\s(\w+)", message)
            if user_match:
                user = user_match.group(1)
            else:
                user_match_2 = re.search(r"/home/(\w+)/", message)
                if user_match_2:
                    user = user_match_2.group(1)

        # --------------------
        # Structure Output
        # --------------------

        events.append({
            "timestamp": timestamp,
            "host": host,
            "service": service,
            "pid": pid,
            "event_type": event_type,
            "user": user,
            "ip": ip,
            "message": message
        })

        
# Converting Data

df = pd.DataFrame(events)


failed_df = df[df["event_type"] == "failed_login"]
ip_counts = failed_df.groupby("ip").size()
suspicious_ips = ip_counts[ip_counts > 5]
print(suspicious_ips)
print(df.head(10))
        