import pytest
from scapy.layers.inet import IP, TCP, ICMP
from src.features import extract_packet_features

def test_tcp_packet_feature_extraction():
    # Construct a raw Scapy TCP SYN Packet
    packet = IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S")
    features = extract_packet_features(packet)

    assert features is not None
    assert features['src_ip'] == "192.168.1.50"
    assert features['dst_ip'] == "192.168.1.1"
    assert features['src_port'] == 12345
    assert features['dst_port'] == 80
    assert features['protocol'] == "TCP"
    assert features['tcp_flags'] == "S"

def test_icmp_packet_feature_extraction():
    # Construct a raw ICMP Ping Packet
    packet = IP(src="10.0.0.5", dst="10.0.0.1")/ICMP()
    features = extract_packet_features(packet)

    assert features is not None
    assert features['src_ip'] == "10.0.0.5"
    assert features['protocol'] == "ICMP"
    assert features['dst_port'] == 0

def test_non_ip_packet_handling():
    # Non-IP dummy packet
    class DummyPacket:
        def haslayer(self, layer):
            return False

    features = extract_packet_features(DummyPacket())
    assert features is None