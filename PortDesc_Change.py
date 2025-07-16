from netmiko import ConnectHandler
import re

# Define the device (Cisco switch)
device = {
    'device_type': 'cisco_ios',
    'host': '10.199.9.50',  # Replace with your switch's IP
    'username': 'pebcak99',  # Replace with your SSH username
    'password': '*ri$d%1',  # Replace with your SSH password
    'secret': 'habu99',  # Replace with your enable password
}

try:
    # Connect to the device
    net_connect = ConnectHandler(**device)
    net_connect.enable()  # Enter enable mode

    # Show the interface descriptions
    output = net_connect.send_command('show int desc')

    # Print the output to check its structure
    print("Output of 'show int desc':")
    print(output)

    # Find all interfaces with descriptions that contain 'X Rm'
    interfaces = re.findall(r'(\S+)\s+\S+\s+\S+\s+ADM Rm (\S+)', output)

    if interfaces:
        # Loop through each interface and change the description
        '''for interface, room_number in interfaces:

            if room_number.startswith('H'):
                room_number = room_number[1:]'''
           
        for match in interfaces:
            if len(match) == 3:
                interface, room_number, extra_description = match
        # Construct the new description
                new_description = f"ADM_Room {room_number}{extra_description.strip()}"

            else:
                interface, room_number = match

                new_description = f"ADM_Room {room_number}"

            # Send the command to change the description
            
            config_commands = [
                f"interface {interface}",
                f"description {new_description}"
            ]
            result = net_connect.send_config_set(config_commands)
            print(f"Updated {interface}: description to {new_description}")
            print("Result of config set:")
            print(result)

    else:
        print("No interfaces with 'XX Rm' found.")


except Exception as e:
    print(f"An error occurred: {e}")

finally:
    # Close the connection
    if 'net_connect' in locals():
        net_connect.disconnect()
        print("Connection closed.")