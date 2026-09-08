import sys
from src.database import init_db
from src.alert_engine import AlertEngine
from src.capture import start_capture

def main():
    print("[*] Initializing Network Security IDS...")
    init_db()
    engine = AlertEngine()

    print("[*] Monitoring traffic... (Press Ctrl+C to stop)")
    try:
        start_capture(callback=engine.process_packet_features)
    except KeyboardInterrupt:
        print("\n[-] IDS Pipeline stopped.")
        sys.exit(0)

if __name__ == '__main__':
    main()