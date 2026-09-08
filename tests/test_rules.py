import pytest
from src.rules import SignatureIDS

@pytest.fixture
def rule_engine():
    return SignatureIDS()

def test_suspicious_port_detection(rule_engine):
    mock_feature = {
        'src_ip': '10.0.0.10',
        'dst_ip': '192.168.1.1',
        'src_port': 54321,
        'dst_port': 31337,  # Suspicious port
        'protocol': 'TCP',
        'tcp_flags': 'S'
    }
    
    alerts = rule_engine.inspect(mock_feature)
    assert len(alerts) > 0
    assert any("Suspicious Target Port" in alert['alert_name'] for alert in alerts)
    assert any(alert['severity'] == "HIGH" for alert in alerts)

def test_syn_scan_detection(rule_engine):
    mock_feature = {
        'src_ip': '10.0.0.10',
        'dst_ip': '192.168.1.1',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP',
        'tcp_flags': 'S'  # SYN Flag
    }

    alerts = rule_engine.inspect(mock_feature)
    assert len(alerts) == 1
    assert alerts[0]['alert_name'] == 'TCP SYN Scan Activity'
    assert alerts[0]['severity'] == 'MEDIUM'

def test_benign_traffic_no_alerts(rule_engine):
    mock_feature = {
        'src_ip': '192.168.1.100',
        'dst_ip': '1.1.1.1',
        'src_port': 50000,
        'dst_port': 443,
        'protocol': 'TCP',
        'tcp_flags': 'A'  # Standard ACK packet
    }

    alerts = rule_engine.inspect(mock_feature)
    assert len(alerts) == 0