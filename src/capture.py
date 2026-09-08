from scapy.all import sniff
from src.features import extract_packet_features

def start_capture(interface=None, packet_count=0, callback=None):
    def handle_packet(packet):
        feat = extract_packet_features(packet)
        if feat and callback:
            callback(feat)

    print("[+] Starting Npcap packet sniffing engine...")
    
    # Scapy auto-detects Npcap on Windows for native raw packet capture
    sniff(iface=interface, prn=handle_packet, store=0, count=packet_count)