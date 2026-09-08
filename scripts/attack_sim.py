import time
import random
from scapy.all import IP, TCP, ICMP, send

TARGET_IP = "127.0.0.1"

def simulate_syn_scan():
    """Simulates a TCP SYN Port Scan across common ports."""
    print("[!] Launching Simulated TCP SYN Port Scan...")
    target_ports = [21, 22, 80, 443, 3306, 8080]
    for port in target_ports:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.2)
    print("[+] SYN Scan batch sent.")

def simulate_suspicious_port_access():
    """Triggers signature rule alert for reverse shell / trojan ports."""
    print("[!] Launching Connection to Suspicious Backdoor Port (31337)...")
    pkt = IP(dst=TARGET_IP)/TCP(dport=31337, flags="S")
    send(pkt, verbose=False)
    print("[+] Suspicious port packet sent.")

def simulate_icmp_sweep():
    """Simulates an ICMP Echo Sweep (Ping Scan)."""
    print("[!] Launching ICMP Ping Sweep Simulation...")
    for _ in range(5):
        pkt = IP(dst=TARGET_IP)/ICMP()
        send(pkt, verbose=False)
        time.sleep(0.1)
    print("[+] ICMP Sweep batch sent.")

def simulate_ml_anomaly_burst():
    """Generates an anomalous packet size/flag combination to trigger the ML Engine."""
    print("[!] Launching ML Anomaly Traffic Burst...")
    for _ in range(10):
        # Abnormal length + malicious flags combination
        pkt = IP(dst=TARGET_IP)/TCP(dport=4444, flags="F")
        send(pkt, verbose=False)
        time.sleep(0.1)
    print("[+] ML Anomaly burst sent.")

def run_simulation_loop():
    print("=" * 60)
    print("🛡️  NIDS ATTACK SIMULATOR STARTED")
    print("    Target Destination: 127.0.0.1")
    print("    Press Ctrl+C to stop simulation loop.")
    print("=" * 60)

    attack_functions = [
        simulate_syn_scan,
        simulate_suspicious_port_access,
        simulate_icmp_sweep,
        simulate_ml_anomaly_burst
    ]

    try:
        while True:
            # Pick a random attack type and trigger it
            attack = random.choice(attack_functions)
            attack()
            print("[*] Waiting 5 seconds before next attack wave...\n")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[-] Attack Simulation stopped.")

if __name__ == "__main__":
    run_simulation_loop()