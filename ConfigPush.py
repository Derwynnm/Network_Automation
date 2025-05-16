import pandas as pd
from netmiko import ConnectHandler
from credentials import username, password, secret
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Load device IPs from Excel
df = pd.read_excel(r'C:\Users\dmckella\Desktop\WriteMem.xlsx')  # Update file name if needed

# Lock for thread-safe printing
print_lock = threading.Lock()

# Set the maximum number of concurrent threads
MAX_THREADS = 100  # Change this number based on your testing

def configure_device(ip):
    if not ip or ip.lower() == 'nan':
        return  # skip empty or bad rows

    with print_lock:
        print(f"\n Connecting to {ip}...")

    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret  
    }

    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # --- Command Set ---
        commands = [
            'do wr'
        ]

        output = connection.send_config_set(commands)
        with print_lock:
            print(f" {ip} configured successfully.\n{output}")

        connection.disconnect()

    except Exception as e:
        with print_lock:
            print(f" Could not connect to {ip}: {e}")

# Collect valid IPs
ips = [str(row.get('IP Address')).strip() for _, row in df.iterrows() if str(row.get('IP Address')).strip().lower() != 'nan']

# Use ThreadPoolExecutor to manage threads
with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    futures = {executor.submit(configure_device, ip): ip for ip in ips}

    for future in as_completed(futures):
        pass  # Results are already printed inside configure_device

print("\nAll tasks completed.")
