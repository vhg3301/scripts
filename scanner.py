# A simple Port Scanner 
# Author: Vitor Gabriel
# Features: TCP/UDP scanning, service identification, firewall detection and multithreading 

from concurrent.futures import ThreadPoolExecutor
import socket

# Dictionary of important ports and their services
important_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
}

# Get user input
target = input("Type your target: ")
initial_port = int(input("Type the initial port: "))
final_port = int(input("Type the final port: "))

def scan_tcp(port_for_scan):
    
    scan1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # <-- create a connection!
    scan1.settimeout(2) # <-- set a timeout to prevent getting stuck forever
    
    # Error handling: try to connect and catch specific errors
    try:
        scan1.connect((target, port_for_scan))
        service = important_ports.get(port_for_scan, "unknown service")
        return True, f"[+] Port TCP {port_for_scan} ({service}) is open!"
    
    # Handle different types of connection errors
    except ConnectionRefusedError:
        service = important_ports.get(port_for_scan, "unknown service")
        return False, f"[-] Port TCP {port_for_scan} ({service}) is closed!"
    except socket.gaierror:
        return False, f"[x] ERROR - DNS doesn't respond!"
    except socket.timeout:
        service = important_ports.get(port_for_scan, "unknown service")  # Removed "!" here
        return False, f"[~] Port TCP {port_for_scan} ({service}) is filtered (firewall!)" # <-- firewall detection
    except Exception as e:
        return False, f"[x] ERROR - unknown error"
    finally:
        scan1.close()

# UDP scan (needs improvement - currently very basic)
def scan_udp(port_for_scan2):
    scan2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    scan2.settimeout(2)
    try:
        scan2.sendto(b"hi", (target, port_for_scan2))
        dados, addr = scan2.recvfrom(1024)
        return True, f"[+] Port UDP {port_for_scan2} is open!"
    except:
        return False, f"[-] Port UDP {port_for_scan2} is closed!"
    finally:
        scan2.close()

# Multithreading to make scanning faster

def scan_range(initial_port, final_port):

    # Main scanning logic
    ports = list(range(initial_port, final_port + 1)) # <-- define port range
    with ThreadPoolExecutor(max_workers=50) as executor:
        tcp_results = list(executor.map(scan_tcp, ports))
        udp_results = executor.map(scan_udp, ports)

    # Show open TCP ports
    for status, msg in tcp_results:
        if status:
            print(msg)

    # Show firewall detection messages at the end
    for status, msg in tcp_results:
        if not status and "filtered" in msg.lower() and "unknown" not in msg:
            port = msg.split(" ")[3]
            service = msg.split("(")[1].split(")")[0]
            print(f"[~] {service} port ({port}) - firewall detected!") 
 
    # Show open UDP ports
    for resultado in udp_results:
        status, msg = resultado
        if status:
            print(msg)
 
scan_range(initial_port, final_port)
