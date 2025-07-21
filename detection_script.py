import os
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import logging

# Constants for SYN flood detection
THR = 100                          # Threshold for SYN packets per IP in a given timeframe
MON_TIME = 10                       # Timeframe in seconds for monitoring
LOG_FILE = "syn_flood.log"          # Log file for SYN flood events

# Global dictionary to store packet counts
pkt_cnt = defaultdict(int)

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def detect(packet):                  # Function to process packets and detect potential SYN flood
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # Check if it's a SYN packet
        ip = packet[IP].src
        pkt_cnt[ip] += 1  # Increment packet count for the source IP

def reset():                          # Function to reset packet counts after each monitoring interval
    global pkt_cnt
    pkt_cnt = defaultdict(int)

def monitor(iface):                  # Main function to monitor traffic on the specified interface
    print(f"Monitoring: {iface}")
    try:
        while True:
            # Sniff packets for MON_TIME seconds
            sniff(iface=iface, filter="tcp", prn=detect, timeout=MON_TIME)

            # Check for suspicious IPs
            for ip, cnt in pkt_cnt.items():
                if cnt > THR:
                    print(f"Potential SYN flood from {ip} (SYN count: {cnt})")
                    logging.warning(f"Potential SYN flood from {ip} (SYN count: {cnt})")

            # Reset counts for the next monitoring interval
            reset()

    except KeyboardInterrupt:
        print("Monitoring stopped.")
    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"Error: {e}")

def monitor_threaded(iface):         # Function to run monitoring in a separate thread
    t = threading.Thread(target=monitor, args=(iface,))
    t.daemon = True  # Daemon thread exits when the main program exits
    t.start()

if __name__ == "__main__":
    # Prompt user for the network interface to monitor
    iface = input("Enter the interface to monitor (e.g., wlp2s0): ")
    if not iface:
        print("No interface provided. Exiting.")
        exit(1)
    
    monitor_threaded(iface)  # Start monitoring in a separate thread
    while True:
        time.sleep(1)  # Keep the main program alive to allow traffic monitoring in the background

