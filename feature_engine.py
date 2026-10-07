import json
import time
import numpy as np

def extract_window_features(log_file="ssh_attempts.jsonl", window_size=10):
    """
    Reads the JSON log and computes behavioral features per IP 
    for events occurring within the last `window_size` seconds.
    """
    current_time = time.time()
    events_by_ip = {}
    
    try:
        with open(log_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if current_time - event["timestamp"] <= window_size:
                        ip = event["source_ip"]
                        if ip not in events_by_ip:
                            events_by_ip[ip] = []
                        events_by_ip[ip].append(event)
                except Exception:
                    pass
    except FileNotFoundError:
        return {}

    features_by_ip = {}
    for ip, events in events_by_ip.items():
        attempt_count = len(events)
        failures = sum(1 for e in events if e["status"] in ("FAILURE", "BLOCKED_DROPPED"))
        failure_rate = failures / attempt_count if attempt_count > 0 else 0
        
        unique_users = len(set(e["username"] for e in events))
        unique_user_ratio = unique_users / attempt_count if attempt_count > 0 else 0
        
        timestamps = sorted([e["timestamp"] for e in events])
        if len(timestamps) > 1:
            diffs = np.diff(timestamps)
            ia_mean = np.mean(diffs)
            ia_std = np.std(diffs)
        else:
            ia_mean = 10.0  # Default long gap for single isolated attempts
            ia_std = 0.0
            
        features_by_ip[ip] = {
            "attempt_count": attempt_count,
            "failure_rate": failure_rate,
            "unique_user_ratio": unique_user_ratio,
            "inter_arrival_mean": ia_mean,
            "inter_arrival_std": ia_std
        }
        
    return features_by_ip