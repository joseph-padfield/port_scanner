import re # for REGEX
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed # for threading
from colorama import init, Fore, Style

# initialising colorama for coloured text and resets colours automatically after each print
# usage in code will look like: "print(Fore.GREEN + 'Port 80 Open (HTTP)')"
init(autoreset=True)

# clean and validate target
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

# resolve hostname to IP
def hostname_to_ip(target):
    domain_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
    if re.match(domain_pattern, target):
        ip = socket.gethostbyname(target)
        print(f"Target IP: {ip}")
        return ip
    else:
        return target
    
# extract ports
def port_range(ports):
    if not ports.strip():
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
                raise ValueError(Fore.RED + "Ports cannot contain letters or invalid numbers.")
            if not (1<= start <= 65535 and 1 <= finish <= 65535):
                raise ValueError(Fore.RED + "Port numbers must be between 1 and 65535.")
            port_list.extend(range(start, finish + 1))
        else:
            try:
                port = int(item)
            except ValueError:
                raise ValueError(Fore.RED + "Ports cannot contain letters or invalid numbers.")
            if not (1 <= port <= 65535):
                raise ValueError(Fore.RED + "Port numbers must be between 1 and 65535.")
            port_list.append(port)
    return port_list

# scan port function
def scan_port(target, port):
    # create a TCP socket for port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set a socket timeout to limit how long you wait for a response before moving on
    sock.settimeout(0.5)
    try:
        # check connection status
        result = sock.connect_ex((target, port))
        banner = b""
        service = "Unknown"
        status = False
        if result == 0:
            status = True
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown"
            # grab banner, with short timeout
            try:
                sock.settimeout(1)
                banner = sock.recv(1024) # returns a bytes object
            except socket.timeout:
                banner = b"" # byte literal - represents an empty sequence of bytes
        # close socket
        sock.close()
        banner_str = banner.decode('utf-8', errors='ignore').strip() if banner else "" # decode banner
        return (port, status, service, banner_str)
    except Exception as e:
        sock.close()
        return (port, False, "Unknown", "")

def scan_ports_concurrently(target, ports): # implementing streaming
    open_ports = []
    # create a ThreadPoolExecutor to manage a pool of worker threads
    with ThreadPoolExecutor(max_workers=100) as executor: # set maximum of 100 threads will run concurrently
        # first argument is executable, followed by arguments
        futures = {executor.submit(scan_port, target, port): port for port in ports} # creates dictionary 
        # iterate over the futures as they complete (not necessarily in submission order)
        for future in as_completed(futures):
            port, status, service, banner = future.result() # result() is method of ThreadPoolExecutor, return from scan_port() function
            if status: # if port is open
                open_ports.append((port, service, banner )) # add to list of open ports
                print(Fore.GREEN + f"Port {port} Open ({service})    {banner}")
    return open_ports

# banner grab (version detection)
def grab_banner(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((target, port))
        banner = sock.recv(1024)  # read up to 1024 bytes
        sock.close()
        return banner.decode('utf-8', errors='ignore').strip()
    except Exception as e:
        return "No banner"

# OS detection


def main():
    # Get target input
    user_input = input('\nEnter target IP address or domain name: ').strip()
    target = clean_and_validate(user_input)
    if not target:
        print(Fore.RED + 'Invalid IP/Domain')
        return
    # Resolve hostname to IP
    try:
        target = hostname_to_ip(target)
    except socket.gaierror:
        print(Fore.RED + 'Hostname could not be resolved')
        return
    except Exception as e:
        print(Fore.RED + f'Something went wrong: {e}')
        return
    # Define port range
    user_input = input("Enter ports to scan (e.g. 22,80-90). Press Enter to scan default ports 20-1024: ")
    try:
        ports = port_range(user_input)
    except ValueError as ve:
        print(Fore.RED + f"Error parsing ports: {ve}")
        return
    # Attempt connections
    try:
        print(f"\nScanning {len(ports)} ports on target {target}...")
        start_time = datetime.now()
        print(f"\nStart: {start_time}\n")
        open_ports = scan_ports_concurrently(target, ports)
        end_time = datetime.now()
        print(f"\nEnd: {end_time}\n")
        print(f"\nScan completed in {end_time - start_time}\n" + Fore.GREEN + f"{len(open_ports)} open ports found.")
    except KeyboardInterrupt:
        print(Fore.RED + "Scan interrupted by user.")

# Bring in argparse once project is running but stick with input() until then

if __name__ == '__main__':
    main()
