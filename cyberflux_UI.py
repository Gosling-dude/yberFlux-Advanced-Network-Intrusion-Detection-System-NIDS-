import scapy.all as scapy      # The tool that's like Wireshark
from scapy.all import conf     # Force L3 socket on Windows
conf.use_pcap = True
conf.L2socket = conf.L3socket

import time
import os
from datetime import datetime

failed_logins = {}  # To record failed logins
blocked_ips = set()  # Record blocked IPs (to prevent duplicate entries)
arp_table = {}  # To store expected MAC addresses for IPs

# Log detected threats to a file and print to the console
def log_threat(message, attack_type):
    log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message} | Attack Type: {attack_type}"
    with open("logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")
    print(log_entry)

# Block an IP using the system firewall
def block_ip(ip):
    if ip not in blocked_ips:
        # On Windows, iptables commands will silently fail; sniffing still works
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        log_threat(f"Blocked IP: {ip}", "IP Blocked")

# Unblock an IP
def unblock_ip(ip):
    if ip in blocked_ips:
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        blocked_ips.remove(ip)
        print(f"Unblocked IP: {ip}")
    else:
        print(f"IP {ip} is not blocked.")

# Clear old login attempts older than 5 minutes
def clean_expired_logins():
    current_time = datetime.now()
    for ip in list(failed_logins):
        if (current_time - failed_logins[ip]['last_attempt']).total_seconds() > 300:
            del failed_logins[ip]

# Reset iptables and clear old blocked IPs
def reset_firewall():
    print("Resetting firewall rules...")
    os.system("sudo iptables -F")  # Flush all iptables rules
    blocked_ips.clear()
    print("Firewall rules cleared.")

# Detect potential threats: SSH brute-force, Nmap scans, ARP poisoning
def detect_threat(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
        tcp_flags = packet[scapy.TCP].flags

        # Ignore packets from blocked IPs 
        if src_ip in blocked_ips:
            return
        
        # Nmap scans
        if tcp_flags == "S":  # SYN scan
            log_threat(f"SYN scan detected from {src_ip} to port {dst_port}", "Nmap SYN Scan")
        elif tcp_flags == "FPU":  # XMAS scan
            log_threat(f"XMAS scan detected from {src_ip}", "Nmap XMAS Scan")
        elif tcp_flags == "":  # Null scan
            log_threat(f"Null scan detected from {src_ip}", "Nmap Null Scan")

        # SSH brute-force
        if dst_port == 22:
            clean_expired_logins()
            if src_ip not in failed_logins:
                failed_logins[src_ip] = {'count': 0, 'last_attempt': datetime.now()}
            failed_logins[src_ip]['count'] += 1
            failed_logins[src_ip]['last_attempt'] = datetime.now()
            log_threat(f"{src_ip} -> {dst_ip}, Port: {dst_port}", "Potential SSH Brute Force")

    # ARP poisoning detection
    if packet.haslayer(scapy.ARP):
        arp_src_ip = packet[scapy.ARP].psrc
        arp_src_mac = packet[scapy.ARP].hwsrc

        if arp_src_ip in arp_table:
            if arp_table[arp_src_ip] != arp_src_mac:
                log_threat(f"ARP Poisoning detected: {arp_src_ip} is claiming to be {arp_src_mac}", "ARP Poisoning")
        else:
            arp_table[arp_src_ip] = arp_src_mac

# Start sniffing on a specified network interface
def start_sniffing(interface):
    global failed_logins
    reset_firewall()
    failed_logins = {}
    print("Starting packet sniffing on interface: " + interface)
    scapy.sniff(iface=interface, store=False, prn=detect_threat)

# Display blocked IPs
def show_blocked_ips():
    if blocked_ips:
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(ip)
    else:
        print("No IPs are currently blocked.")

# Show logs from file
def view_logs():
    try:
        with open("logs.txt", "r") as log_file:
            for log in log_file:
                print(log.strip())
    except FileNotFoundError:
        print("No logs found.")

def show_menu():
    while True:

        print("--------------------------------------------------------------")
        print("""
         ___ ____  ____            ___ ___ _____
        |_ _|  _ \/ ___|          |_ _/ _ \_   _|
         | || | | \___ \   _____   | | | | || |
         | || |_| |___) | |_____|  | | |_| || |
        |___|____/|____/          |___\___/ |_|
               NIDS (by Sumit Chauhan)
        """)
        print("--------------------------------------------------------------")
        print("Network Intrusion Detection System Menu:")
        print("1. Start Packet Sniffing")
        print("2. Block an IP Manually")
        print("3. Remove IP from Blocklist")
        print("4. Show Blocked IPs")
        print("5. View Logs")
        print("6. Exit")
        print("--------------------------------------------------------------")

        choice = input("Please select an option (1-6): ")

        if choice == "1":
            interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
            start_sniffing(interface)
        elif choice == "2":
            ip_to_block = input("Enter the IP address to block: ")
            block_ip(ip_to_block)
        elif choice == "3":
            ip_to_unblock = input("Enter the IP address to unblock: ")
            unblock_ip(ip_to_unblock)
        elif choice == "4":
            show_blocked_ips()
        elif choice == "5":
            view_logs()
        elif choice == "6":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    show_menu()
