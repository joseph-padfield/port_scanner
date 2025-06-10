import re # for REGEX
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed # for threading
from colorama import init, Fore, Style
import argparse # for running entirely in the CLI
import ipaddress

# initialising colorama for coloured text and resets colours automatically after each print
# usage in code will look like: "print(Fore.GREEN + 'Port 80 Open (HTTP)')"
init(autoreset=True)

def parse_args():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments with attributes 'target' and 'ports'.
    """
    parser = argparse.ArgumentParser(description='Python Port Scanner')
    parser.add_argument('--target', help='Target IP Address or Domain Name, e.g. scanme.nmap.org\n')
    parser.add_argument('--ports', help='Ports to scan, e.g. 22, 80-90. Defaults to 20-1024.')
    return parser.parse_args()

def is_valid_ip(ip):
    """
    Check if the provided string is a valid IPv4 or IPv6 address.
    
    Args:
        ip (str): IP address string.
    
    Returns:
        bool: True if valid IP, otherwise False.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# clean and validate target
def clean_and_validate(target):
    """
    Clean input target by stripping URL scheme and trailing slash, 
    then validate as either IP address or domain name.
    
    Args:
        target (str): Target input string.
    
    Returns:
        str or None: Cleaned target string if valid, None otherwise.
    """
    # remove http:// or https:// if present
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]
    # remove trailing slash if present
    target = target.rstrip('/')
    # validate IP address format (IPv4)
    if is_valid_ip(target):
        return target
    # validate domain name format
    domain_pattern = r'^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$'
    if re.match(domain_pattern, target):
        return target
    return None # invalid input

# resolve hostname to IP
def hostname_to_ip(target):
    """
    Resolve domain name to IP address if target is a domain.

    Args:
        target (str): Validated target string (IP or domain).

    Returns:
        str: IP address if domain resolved successfully; else original target.
    """
    domain_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
    if re.match(domain_pattern, target):
        ip = socket.gethostbyname(target)
        print(f"Target IP: {ip}")
        return ip
    else:
        return target
    
# extract ports
def port_range(ports):
    """
    Parse port range input string into list of integer ports.

    Args:
        ports (str): Ports string, e.g. "22,80-90".

    Returns:
        list[int]: List of port numbers.

    Raises:
        ValueError: If ports contain invalid numbers or are out of range.
    """
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

# scan port function
def scan_port(target, port):
    """
    Scan a single TCP port on the target to determine if open and grab banner.

    Args:
        target (str): IP address to scan.
        port (int): Port number to scan.

    Returns:
        tuple: (port (int), status (bool), service (str), banner (str))
            status is True if port is open, False otherwise.
            banner is empty string if no banner retrieved.
    """
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
        return (port, False, "Unknown", "")
    finally:
        sock.close()

def scan_ports_concurrently(target, ports): # implementing streaming
    """
    Scan multiple ports concurrently on the target using threads.

    Args:
        target (str): IP address to scan.
        ports (list[int]): List of port numbers to scan.

    Returns:
        list[tuple]: List of tuples (port, service, banner) for open ports.
    """
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
    """
    Attempt to grab a banner from an open port by connecting and reading bytes.

    Args:
        target (str): IP address to connect.
        port (int): Port number.

    Returns:
        str: Decoded banner string or 'No banner' if unavailable.
    """
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((target, port))
        banner = sock.recv(1024)  # read up to 1024 bytes
        sock.close()
        return banner.decode('utf-8', errors='ignore').strip()
    except Exception as e:
        return "No banner"

def main():
    """
    Main entry point: parse arguments, validate input, and perform port scanning.

    Handles user input either from CLI arguments or interactive prompts.
    Prints scan progress and results with color-coded output.
    """
    args = parse_args()
    # Get target input
    if args.target:
        target_input = args.target.strip()
    else:
        target_input = input('\nEnter target IP address or domain name: ').strip()
    # if no target_input, show helper message
    if not target_input:
        print(Fore.YELLOW + "No target specified. Please provide an IP address or domain name.")
        print("Example usage:")
        print("  python scanner.py --target example.com --ports 22,80-90")
        return
    target = clean_and_validate(target_input)
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
    if not args.ports:
        ports_input = input("Enter ports to scan (e.g. 22,80-90). Press Enter to scan default ports 20-1024: ")
    else:
        ports_input = args.ports
    if not ports_input:
        print(Fore.YELLOW + "No ports specified, defaulting to ports 20-1024.")
    try:
        ports = port_range(ports_input)
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
        print(f"\nEnd: {end_time}")
        print(f"\nScan completed in {end_time - start_time}\n" + Fore.GREEN + f"{len(open_ports)} open ports found.")
    except KeyboardInterrupt:
        print(Fore.RED + "Scan interrupted by user.")

if __name__ == '__main__':
    main()
