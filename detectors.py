import joblib
import numpy as np
import pandas as pd

try:
    ml_model = joblib.load("rf_model.joblib")
except FileNotFoundError:
    ml_model = None

def baseline_detector(features):
    """Flags malicious if >= 5 failed attempts in the window."""
    attempt_count = features["attempt_count"]
    failure_rate = features["failure_rate"]
    failed_attempts = attempt_count * failure_rate
    return bool(failed_attempts >= 5)

def ml_detector(features):
    """
    Supervised ML detector.
    Requires at least 2 attempts in the window to prevent false-positive lockouts
    on single legitimate typos.
    """
    if ml_model is None or features["attempt_count"] < 2:
        return False
        
    x_df = pd.DataFrame([{
        "attempt_count": features["attempt_count"],
        "failure_rate": features["failure_rate"],
        "unique_user_ratio": features["unique_user_ratio"],
        "inter_arrival_mean": features["inter_arrival_mean"],
        "inter_arrival_std": features["inter_arrival_std"]
    }])
    
    prediction = ml_model.predict(x_df)[0]
    return bool(prediction == 1)