import os
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import logging

# Global variables
pkt_cnt = defaultdict(int)
blocked_ips = {}  # Dictionary to store blocked IPs and their unblock time

# Set up logging
LOG_FILE = "syn_flood.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def block_ip(ip, block_time):  # Function to block an IP address using iptables
    if ip not in blocked_ips:
        print(f"Blocking IP: {ip} for {block_time} seconds")
        logging.warning(f"Blocking IP: {ip} for {block_time} seconds")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips[ip] = time.time() + block_time  # Store the unblock time

def unblock_ip():  # Function to unblock IPs after their block time has passed
    current_time = time.time()
    for ip, unblock_time in list(blocked_ips.items()):
        if current_time >= unblock_time:
            print(f"Unblocking IP: {ip}")
            logging.info(f"Unblocking IP: {ip}")
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")  # Remove the iptables rule
            del blocked_ips[ip]

def detect(packet):  # Function to process packets and detect potential SYN flood
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # Check for SYN packet
        ip = packet[IP].src
        pkt_cnt[ip] += 1

def reset():  # Function to reset packet counts after each monitoring interval
    global pkt_cnt
    pkt_cnt = defaultdict(int)

def monitor(iface, THR, MON_TIME, BLOCK_TIME):  # Main function to monitor traffic and detect attacks
    print(f"Monitoring: {iface} | Threshold: {THR} SYN packets | Interval: {MON_TIME}s | Block Time: {BLOCK_TIME}s")
    try:
        while True:
            # Sniff packets for MON_TIME seconds
            sniff(iface=iface, filter="tcp", prn=detect, timeout=MON_TIME)

            # Check for suspicious IPs and block them
            for ip, cnt in pkt_cnt.items():
                if cnt > THR:
                    print(f"Potential SYN flood from {ip} (SYN count: {cnt})")
                    logging.warning(f"Potential SYN flood from {ip} (SYN count: {cnt})")
                    block_ip(ip, BLOCK_TIME)

            # Reset counts for the next monitoring interval
            reset()

            # Unblock IPs whose block time has expired
            unblock_ip()

    except KeyboardInterrupt:
        print("Monitoring stopped.")
    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"Error: {e}")

def monitor_threaded(iface, THR, MON_TIME, BLOCK_TIME):  # Function to run monitoring in a separate thread
    t = threading.Thread(target=monitor, args=(iface, THR, MON_TIME, BLOCK_TIME))
    t.daemon = True  # Daemon thread exits when the main program exits
    t.start()

if __name__ == "__main__":
    # Prompt user for configuration
    iface = input("Enter the interface to monitor (e.g., wlp2s0): ").strip()
    if not iface:
        print("No interface provided. Exiting.")
        exit(1)

    try:
        THR = int(input("Enter the SYN packet threshold to detect (e.g., 100): ").strip())
        MON_TIME = int(input("Enter the monitoring interval in seconds (e.g., 10): ").strip())
        BLOCK_TIME = int(input("Enter the time to block an IP in seconds (e.g., 60): ").strip())
    except ValueError:
        print("Invalid input. Threshold, interval, and block time must be integers.")
        exit(1)

    print("Starting SYN flood detection and automatic IP blocking...")
    monitor_threaded(iface, THR, MON_TIME, BLOCK_TIME)  # Start monitoring in a separate thread
    
    # Keep the main program alive
    while True:
        unblock_ip()  # Ensure blocked IPs are unblocked on time
        time.sleep(1)

