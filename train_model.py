import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

def generate_synthetic_data(n_samples=2000):
    """Generates a dataset of 10-second sliding window features."""
    data = []
    labels = []
    
    for _ in range(n_samples):
        # 40% Burst, 30% Stealth, 30% Legit
        attack_type = np.random.choice(["burst", "stealth", "legit"], p=[0.4, 0.3, 0.3])
        
        if attack_type == "burst":
            attempts = np.random.randint(20, 100)
            fail_rate = 1.0
            unique_ratio = np.random.uniform(0.1, 0.5)
            ia_mean = np.random.uniform(0.05, 0.3)
            ia_std = np.random.uniform(0.01, 0.05)
            label = 1
        elif attack_type == "stealth":
            attempts = np.random.randint(1, 4)
            fail_rate = 1.0
            unique_ratio = 1.0
            ia_mean = np.random.uniform(4.0, 7.0)
            ia_std = np.random.uniform(0.1, 0.5)
            label = 1
        else: # Legitimate User
            attempts = np.random.randint(1, 4)
            # Occasional typos mean a small chance of failure
            fail_rate = np.random.choice([0.0, 0.33, 0.5], p=[0.8, 0.15, 0.05])
            unique_ratio = 1.0
            ia_mean = np.random.uniform(5.0, 15.0)
            ia_std = np.random.uniform(1.0, 5.0)
            label = 0
            
        data.append([attempts, fail_rate, unique_ratio, ia_mean, ia_std])
        labels.append(label)
        
    columns = ["attempt_count", "failure_rate", "unique_user_ratio", "inter_arrival_mean", "inter_arrival_std"]
    return pd.DataFrame(data, columns=columns), np.array(labels)

if __name__ == "__main__":
    print("[*] Generating synthetic sliding-window dataset...")
    X, y = generate_synthetic_data(2000)
    
    print("[*] Training Random Forest Classifier...")
    # Tree-based model selected based on Hamza et al. (2025) performance benchmarks
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
    clf.fit(X, y)
    
    print("\n[*] Training Performance:")
    print(classification_report(y, clf.predict(X), target_names=["Benign (0)", "Attack (1)"]))
    
    joblib.dump(clf, "rf_model.joblib")
    print("[*] Model saved to disk as 'rf_model.joblib'")