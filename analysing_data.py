from parser_1 import parse_auth_log
import pandas as pd
import numpy as np
from datetime import datetime

def analyse_data(df):

    # Detect failed login attempts
    failed_attempts = df[df['event_type'] == "failed_login"]
    if not failed_attempts.empty:
        print(f"Total failed attempts: {len(failed_attempts)}")
        print("Top failed users:\n")
        print(failed_attempts['user'].value_counts().head(10))
        print("Top failed IPs for failed login attempts:\n")
        print(failed_attempts['ip'].value_counts().head(10))
    else:
        print("No failed login attempts found")

    
    # Time-related data
    if df['timestamp'].notna().any():
        
        
        df['date'] = df['timestamp'].dt.date
        print("Events per day:")
        print(df['date'].value_counts().sort_index())

        df['hour'] = df['timestamp'].dt.hour
        print("\nEvents per hour:")
        print(df['hour'].value_counts().sort_index())

    # Successful logins
    success = df[df['event_type'] == "successful_login"]
    if not success.empty:
        print(f"Total successful login attempts: {len(success)}")
        print("\nSuccessful logins by user:")
        print(success['user'].value_counts().head(10))

    


        
        
    

if __name__ == "__main__":

    import sys

    log_file = sys.argv[1] if len(sys.argv) > 1 else "auth.log"

    print(f"Parsing log file {log_file}")

    df = parse_auth_log(log_file)


    if df.empty:
        print("No events found or file error.")
        sys.exit(1)

    print("Data overview:")
    print(df.head())
    print(f"\nData Types:\n{df.dtypes}")

    analyse_data(df)


