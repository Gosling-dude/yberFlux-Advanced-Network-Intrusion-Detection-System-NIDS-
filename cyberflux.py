import subprocess
import time
import os
from datetime import datetime

# --- Configuration & State ---
LOG_FILE = "logs.txt"
SIMULATION_FILE = "simulated_traffic.txt"
DETECTOR_EXECUTABLE = "detector.exe"
GCLOUD_PROJECT = "gen-lang-client-0121715357"
GCLOUD_REGION = "us-central1"

# In-memory list to simulate the blocklist
blocked_ips = set()

# --- Core Functions ---

def log_event(message):
    """Appends a message to the log file with a timestamp."""
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def block_ip(ip_address):
    """Simulates blocking an IP address."""
    if ip_address in blocked_ips:
        print(f"  -> IP {ip_address} is already blocked.")
        return
    print(f"  -> [SIMULATED] Blocking IP address: {ip_address} using Windows Firewall rule...")
    # In a real Windows scenario, you might run:
    # os.system(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in interface=any action=block remoteip={ip_address}')
    blocked_ips.add(ip_address)
    log_event(f"Blocked IP: {ip_address}")

def unblock_ip(ip_address):
    """Simulates unblocking an IP address."""
    if ip_address not in blocked_ips:
        print(f"  -> IP {ip_address} is not in the blocklist.")
        return
    print(f"  -> [SIMULATED] Unblocking IP address: {ip_address}...")
    # In a real Windows scenario, you might run:
    # os.system(f'netsh advfirewall firewall delete rule name="Block {ip_address}"')
    blocked_ips.remove(ip_address)
    log_event(f"Unblocked IP: {ip_address}")

def start_simulation():
    """Reads the simulation file and passes each line to the C++ detector."""
    print("\n--- Starting Network Traffic Simulation ---")
    print("Reading from 'simulated_traffic.txt' and analyzing with 'detector.exe'\n")
    
    if not os.path.exists(SIMULATION_FILE):
        print(f"[ERROR] Simulation file not found: {SIMULATION_FILE}")
        return
    if not os.path.exists(DETECTOR_EXECUTABLE):
        print(f"[ERROR] C++ detector not found: {DETECTOR_EXECUTABLE}. Please compile detector.cpp first.")
        return

    # This process will be kept alive to maintain state (like known ARP mappings)
    detector_process = subprocess.Popen(
        [f".\\{DETECTOR_EXECUTABLE}"], # Use .\\ for explicit relative path
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # Create a new process group to ensure it's a separate process
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP 
    )

    with open(SIMULATION_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            print(f"[INFO] Processing: {line}")

            # Send the line to the C++ detector's stdin
            detector_process.stdin.write(line + '\n')
            detector_process.stdin.flush()
            
            # Check for immediate output (alerts)
            # This part is tricky with standard pipes. For this demo, we'll check after the loop.
            # A more robust solution might use sockets or temporary files.

            time.sleep(0.5) # Pause to make it feel like real-time

    # Close stdin to signal the end of input and get all final output
    detector_process.stdin.close()
    
    # Read all alerts from the detector's stdout
    stdout, stderr = detector_process.communicate()

    if stderr:
        print(f"\n[DETECTOR ERROR] {stderr.strip()}")

    if stdout:
        print("\n--- Simulation Complete. Alerts Detected: ---")
        alerts = stdout.strip().split('\n')
        for alert in alerts:
            print(f"\033[91m[ALERT] {alert}\033[0m") # Print alert in red
            log_event(alert)
            # Automatically block the offending IP
            parts = alert.split(' | ')
            if len(parts) > 2:
                ip_to_block = parts[2]
                print(f"  -> Taking action: Auto-blocking IP {ip_to_block}")
                block_ip(ip_to_block)
    else:
        print("\n--- Simulation Complete. No alerts detected. ---")

# --- UI Functions ---

def display_menu():
    """Prints the main menu."""
    print("\n--- CyberFlux NIDS ---")
    print("1. Start Simulation")
    print("2. Block an IP Manually")
    print("3. Unblock an IP")
    print("4. Show Blocked IPs")
    print("5. View Logs")
    print("6. Exit")
    return input("Choose an option: ")

def main():
    """Main program loop."""
    while True:
        choice = display_menu()
        if choice == '1':
            start_simulation()
        elif choice == '2':
            ip = input("Enter IP to block: ")
            block_ip(ip)
        elif choice == '3':
            ip = input("Enter IP to unblock: ")
            unblock_ip(ip)
        elif choice == '4':
            print("\n--- Currently Blocked IPs ---")
            if blocked_ips:
                for ip in blocked_ips:
                    print(ip)
            else:
                print("No IPs are currently blocked.")
        elif choice == '5':
            print("\n--- Attack Log ---")
            try:
                with open(LOG_FILE, "r") as f:
                    print(f.read().strip())
            except FileNotFoundError:
                print("Log file not found.")
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()