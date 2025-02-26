import pandas as pd
from netmiko import ConnectHandler
from time import sleep

# Function to configure port description on Cisco Switch
def configure_port_description(switch_ip, ports, description, username, password):
    # Setup the SSH connection details
    device = {
        'device_type': 'cisco_ios',   # Cisco device type
        'host': switch_ip,
        'username': username,
        'password': password,
        'secret':  'secret', # Enable password
        'conn_timeout': 60,  # Connection timeout in seconds
        'global_delay_factor': 2,  # Delay between commands (higher = slower)
        'verbose': False,    # Optional: Turn off debugging output
    }

    try:
        # Connect to the device
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()  # Enter enable mode

            # Loop over each port and send configuration command
            for port in ports:
                port = port.strip()  # Strip extra spaces from the port name
                config_commands = [f'interface {port}', f'description {description}']
                output = net_connect.send_config_set(config_commands)
                print(f"Configured {port} on {switch_ip} with description: {description}")
                print(output)

                # Wait for the prompt after configuring each port
                net_connect.find_prompt()
                sleep(1)  # Optional: Add a small sleep to give time for the device to process

    except Exception as e:
        print(f"Failed to connect or configure {switch_ip}: {e}")

# Read the Excel file
def read_excel(file_path):
    # Assuming the Excel file has columns: 'IP Address', 'Port', 'Description'
    df = pd.read_excel(file_path)
    return df

# Main execution
def main():
    # User credentials for SSH
    username = 'username'
    password = 'password'

    # Path to the Excel file with switch details
    file_path = r'\file\path\here.xlsx'

    # Read the data from Excel
    switch_data = read_excel(file_path)

    # Iterate over each row and configure the port description
    for index, row in switch_data.iterrows():
        ip_address = row['IP Address']
        ports = [p.strip() for p in row['Port'].split(',')]  # Ensure ports are clean
        description = row['Description']

        # Configure the port descriptions on the switch
        configure_port_description(ip_address, ports, description, username, password)

        # Sleep between requests to avoid rate-limiting issues (optional)
        sleep(1)

if __name__ == "__main__":
    main()
