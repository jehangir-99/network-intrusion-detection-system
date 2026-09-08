class SignatureIDS:
    def __init__(self):
        self.suspicious_ports = {4444, 5555, 6667, 31337} # Common reverse shell ports

    def inspect(self, feature_dict):
        alerts = []
        if not feature_dict:
            return alerts

        # Check for suspicious target ports
        if feature_dict['dst_port'] in self.suspicious_ports:
            alerts.append({
                'alert_name': f"Suspicious Target Port Detected ({feature_dict['dst_port']})",
                'severity': 'HIGH'
            })

        # Check for SYN Scan Signature
        if feature_dict['protocol'] == 'TCP' and feature_dict['tcp_flags'] == 'S':
            alerts.append({
                'alert_name': 'TCP SYN Scan Activity',
                'severity': 'MEDIUM'
            })

        # Check ICMP Ping Sweeps
        if feature_dict['protocol'] == 'ICMP':
            alerts.append({
                'alert_name': 'ICMP Echo Activity (Potential Sweep)',
                'severity': 'LOW'
            })

        return alerts