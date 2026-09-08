from scapy.layers.inet import IP, TCP, UDP, ICMP

def extract_packet_features(packet):
    if not packet.haslayer(IP):
        return None

    features = {
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'src_port': 0,
        'dst_port': 0,
        'protocol': 'OTHER',
        'length': len(packet),
        'tcp_flags': None,
        'window_size': 0
    }

    if packet.haslayer(TCP):
        features['protocol'] = 'TCP'
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['tcp_flags'] = str(packet[TCP].flags)
        features['window_size'] = packet[TCP].window
    elif packet.haslayer(UDP):
        features['protocol'] = 'UDP'
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        features['protocol'] = 'ICMP'

    return features