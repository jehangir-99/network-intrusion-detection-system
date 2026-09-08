import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

def generate_synthetic_network_data(n_samples=2000):
    """
    Generates synthetic network flow features:
    [packet_length, dst_port, protocol_code, tcp_flags_code]
    
    Protocol Codes: 0 = ICMP, 1 = TCP, 2 = UDP
    TCP Flag Codes: 0 = None/ACK, 1 = SYN, 2 = SYN-ACK/Malicious Pattern
    """
    np.random.seed(42)
    half_samples = n_samples // 2

    # 1. Benign Traffic (Web browsing, DNS, normal packet sizes)
    benign_len = np.random.normal(loc=600, scale=150, size=half_samples)
    benign_ports = np.random.choice([80, 443, 53, 22, 8080], size=half_samples)
    benign_proto = np.random.choice([1, 2], size=half_samples, p=[0.8, 0.2])  # Mostly TCP/UDP
    benign_flags = np.random.choice([0, 1], size=half_samples, p=[0.9, 0.1])  # Mostly standard ACK/SYN

    benign_features = np.column_stack([benign_len, benign_ports, benign_proto, benign_flags])
    benign_labels = np.zeros(half_samples)

    # 2. Malicious Traffic (Port scans, DDoS bursts, reverse shell ports)
    malicious_len = np.random.normal(loc=64, scale=10, size=half_samples)  # Small flood packets
    malicious_ports = np.random.choice([4444, 31337, 5555, 6667, 80], size=half_samples)
    malicious_proto = np.random.choice([1, 0], size=half_samples, p=[0.85, 0.15])  # TCP scans / ICMP sweeps
    malicious_flags = np.random.choice([1, 2], size=half_samples, p=[0.7, 0.3])  # SYN floods / Malicious flags

    malicious_features = np.column_stack([malicious_len, malicious_ports, malicious_proto, malicious_flags])
    malicious_labels = np.ones(half_samples)

    # Combine into single dataset
    X = np.vstack([benign_features, malicious_features])
    y = np.concatenate([benign_labels, malicious_labels])

    return X, y

def train_and_save_model():
    print("[*] Generating dataset and building ML pipeline...")
    X, y = generate_synthetic_network_data()

    # Train Random Forest
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X, y)

    # Validate model
    preds = clf.predict(X)
    print("\n=== Model Training Performance ===")
    print(classification_report(y, preds, target_names=['Benign', 'Malicious']))

    # Ensure output directory exists and save artifact
    os.makedirs('models', exist_ok=True)
    model_filepath = os.path.join('models', 'random_forest.pkl')
    joblib.dump(clf, model_filepath)
    print(f"[+] Model saved successfully to {model_filepath}\n")

if __name__ == '__main__':
    train_and_save_model()