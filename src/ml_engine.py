import os
import numpy as np
import joblib

class MLInferenceEngine:
    def __init__(self, model_relative_path='../models/random_forest.pkl'):
        # Resolve absolute path relative to this script
        base_dir = os.path.dirname(__file__)
        self.model_path = os.path.abspath(os.path.join(base_dir, model_relative_path))
        self.model = self._load_model()

    def _load_model(self):
        """Loads the pre-trained Random Forest model."""
        if os.path.exists(self.model_path):
            try:
                model = joblib.load(self.model_path)
                print(f"[+] ML Engine loaded model successfully from {self.model_path}")
                return model
            except Exception as e:
                print(f"[-] Error loading ML model: {e}")
                return None
        else:
            print(f"[!] Warning: ML model file not found at {self.model_path}. Run 'python train.py' first.")
            return None

    def _preprocess_feature_dict(self, feat):
        """
        Converts the raw feature dictionary extracted from Scapy packets into 
        the 4-element numerical feature vector expected by the Random Forest model:
        [packet_length, dst_port, protocol_code, tcp_flags_code]
        """
        # Map Protocol String to Categorical Integer
        proto = feat.get('protocol', 'OTHER')
        if proto == 'TCP':
            proto_code = 1
        elif proto == 'UDP':
            proto_code = 2
        elif proto == 'ICMP':
            proto_code = 0
        else:
            proto_code = 3

        # Map TCP Flags
        tcp_flags = feat.get('tcp_flags', '')
        if tcp_flags == 'S':  # SYN Packet
            flag_code = 1
        elif tcp_flags in ['F', 'R', 'P']:  # Unusual / Scanning Flags
            flag_code = 2
        else:
            flag_code = 0

        # Feature Vector: [length, dst_port, protocol_code, flag_code]
        vector = [
            float(feat.get('length', 0)),
            float(feat.get('dst_port', 0)),
            float(proto_code),
            float(flag_code)
        ]

        return np.array([vector])

    def predict(self, feature_dict):
        """
        Runs ML inference on packet feature dictionary.
        Returns an alert payload dictionary if classified as malicious (1), or None if benign (0).
        """
        if not self.model or not feature_dict:
            return None

        try:
            vector = self._preprocess_feature_dict(feature_dict)
            prediction = self.model.predict(vector)[0]
            
            # Predict Probabilities (Confidence Score)
            probabilities = self.model.predict_proba(vector)[0]
            confidence = probabilities[int(prediction)]

            if prediction == 1 and confidence >= 0.65:
                return {
                    'alert_name': f'ML Anomaly: Malicious Traffic Pattern Detected (Confidence: {confidence:.2%})',
                    'severity': 'HIGH' if confidence > 0.85 else 'MEDIUM'
                }
        except Exception as e:
            print(f"[-] ML Inference Exception: {e}")

        return None