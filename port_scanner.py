import re # for REGEX
import socket
from datetime import datetime

# Clean and validate target
def clean_and_validate(target):
    # remove http:// or https:// if present
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]
    
    # remove trailing slash if present
    target = target.rstrip('/')

    # validate IP address format (IPv4)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        # check each octet is between 0-255
        parts = target.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return target # valid IPv4 address
        
    # validate domain name format
    domain_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
    if re.match(domain_pattern, target):
        return target
    
    return None # invalid input

# Resolve hostname to IP
def hostname_to_ip(target):
    domain_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
    if re.match(domain_pattern, target):
        return socket.gethostbyname(target)
    else:
        return target
    
def port_range(ports="20-1024"):
    port_list = []
    ports = ports.split(',')
    for item in ports:
        item = item.strip()
        if '-' in item:
            start, finish = item.split('-')
            try:
                start = int(start.strip())
                finish = int(finish.strip())
            except ValueError:
                raise ValueError("Ports cannot contain letters or invalid numbers.")
            if not (1<= start <= 65535 and 1 <= finish <= 65535):
                raise ValueError("Port numbers must be between 1 and 65535.")
            port_list.extend(range(start, finish + 1))
        else:
            try:
                port = int(item)
            except ValueError:
                raise ValueError("Ports cannot contain letters or invalid numbers.")
            if not (1 <= port <= 65535):
                raise ValueError("Port numbers must be between 1 and 65535.")
            port_list.append(port)
    return port_list

def main():
    # Get target input
    user_input = input('Target IP/Domain: ')
    target = clean_and_validate(user_input)
    if not target:
        print('Invalid IP/Domain')
        return
    
    # Resolve hostname to IP
    try:
        target = hostname_to_ip(target)
    except socket.gaierror:
        print('Hostname could not be resolved')
        return
    except Exception as e:
        print(f'Something went wrong: {e}')
        return

    # Define port range
    user_input = input("Enter ports to scan. Range can be defined with \"-\", for multiple selections separate with \",\": ")
    try:
        ports = port_range(user_input)
    except ValueError as ve:
        print(f"Error parsing ports: {ve}")

    # Attempt connections

    # Check connection status

    # Get service name

    # Display results

# Handle errors

# Bring in argparse once project is running but stick with input() until then

if __name__ == '__main__':
    main()

