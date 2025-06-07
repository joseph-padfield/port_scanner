import re # for REGEX
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed # for threading

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
        ip = socket.gethostbyname(target)
        print(f"Target IP: {ip}")
        return ip
    else:
        return target
    
def port_range(ports):
    if len(ports) == 0:
        ports = "20-1024"
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

def scan_port(target, port): # added this in order to incorporate threading
    # Create a TCP socket for each port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a socket timeout to limit how long you wait for a response before moving on
    sock.settimeout(0.5)
    # Check connection status
    result = sock.connect_ex((target, port))
    # close socket
    sock.close()
    # Get service name
    try:
        service = "Unknown"
        status = False
        if result == 0:
            status = True
            service = socket.getservbyport(port)
    except OSError:
        service = "Unknown"
    return (port, status, service)

def scan_ports_concurrently(target, ports):
    open_ports = []
    # create a ThreadPoolExecutor to manage a pool of worker threads
    with ThreadPoolExecutor(max_workers=100) as executor: # set maximum of 100 threads will run concurrently
        # first argument is executable, followed by arguments
        futures = {executor.submit(scan_port, target, port): port for port in ports} # creates dictionary 
        # iterate over the futures as they complete (not necessarily in submission order)
        for future in as_completed(futures):
            port, status, service = future.result() # result() is method of ThreadPoolExecutor, return from scan_port() function
            if status: # if port is open
                open_ports.append((port, service)) # add to list of open ports
                print(f"Port {port} Open ({service})")
    return open_ports



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
        return

    # Attempt connections
    try:
        print(f"Scanning {len(ports)} ports on target {target}...")
        start_time = datetime.now()
        print(f"Start: {start_time}")
        # for port in ports:
        #     # Create a TCP socket for each port
        #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     # Set a socket timeout to limit how long you wait for a response before moving on
        #     sock.settimeout(0.5)

        #     # Check connection status
        #     result = sock.connect_ex((target, port)) # Returns 0 if connection is successful, non-0 means closed or filtered ports
        #     # Use connect_ex() rather than connect() as it returns error code rather than raising exceptions

        #     # close socket
        #     sock.close()

        #     if result == 0:
        #     # Get service name
        #         try:
        #             service = socket.getservbyport(port)
        #         except OSError:
        #             service = "Unknown"
        #         # Display results
        #         print(f"Port {port} Open ({service})")
        open_ports = scan_ports_concurrently(target, ports)
        end_time = datetime.now()
        print(f"End: {end_time}")
        print(f"Scan completed in {end_time - start_time}\n{len(open_ports)} open ports found.")
    except KeyboardInterrupt:
        print("Scan interrupted by user.")

# Streaming

# Banner grabbing

# OS detection

# Version detecting

# Bring in argparse once project is running but stick with input() until then

if __name__ == '__main__':
    main()

