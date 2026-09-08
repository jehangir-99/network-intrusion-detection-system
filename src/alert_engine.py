from src.rules import SignatureIDS
from src.ml_engine import MLInferenceEngine
from src.database import log_alert

class AlertEngine:
    def __init__(self):
        self.rule_ids = SignatureIDS()
        self.ml_ids = MLInferenceEngine()

    def process_packet_features(self, feat):
        if not feat:
            return

        # 1. Rule-Based Signatures
        rule_alerts = self.rule_ids.inspect(feat)
        for alert in rule_alerts:
            log_alert(
                feat['src_ip'], feat['dst_ip'], feat['src_port'], feat['dst_port'],
                feat['protocol'], 'RULE-BASED', alert['alert_name'], alert['severity']
            )

        # 2. ML Anomaly Detection
        ml_alert = self.ml_ids.predict(feat)
        if ml_alert:
            log_alert(
                feat['src_ip'], feat['dst_ip'], feat['src_port'], feat['dst_port'],
                feat['protocol'], 'ML-DETECTION', ml_alert['alert_name'], ml_alert['severity']
            )