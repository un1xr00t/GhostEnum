import argparse
import random
import time
from scapy.all import IP, ICMP, TCP, UDP, sr, sr1

def discover_hosts(network):
    """
    Discover live hosts in the given network using ICMP.
    """
    print(f"Scanning for live hosts in {network}...")
    packets = IP(dst=network)/ICMP()
    responses, _ = sr(packets, timeout=2, verbose=0)
    live_hosts = [resp[IP].src for resp in responses]
    print(f"Live hosts detected: {live_hosts}")
    return live_hosts

def tcp_syn_scan(target, ports):
    """
    Perform a TCP SYN scan on the given target and ports.
    """
    print(f"Starting TCP SYN scan on {target}...")
    open_ports = []
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 'SA':
            open_ports.append(port)
            print(f"[+] Port {port} is open")
        else:
            print(f"[-] Port {port} is closed or filtered")
        time.sleep(random.uniform(0.5, 1.5))  # Random delay for stealth
    return open_ports

def udp_scan(target, ports):
    """
    Perform a UDP scan on the given target and ports.
    """
    print(f"Starting UDP scan on {target}...")
    open_ports = []
    for port in ports:
        pkt = IP(dst=target)/UDP(dport=port)
        response = sr1(pkt, timeout=2, verbose=0)
        if response is None:  # No response might mean open/filtered
            open_ports.append(port)
            print(f"[?] Port {port} is open or filtered")
        elif response.haslayer(ICMP) and response[ICMP].type == 3:
            print(f"[-] Port {port} is closed")
        time.sleep(random.uniform(0.5, 1.5))  # Random delay for stealth
    return open_ports

def save_results(file_name, results):
    """
    Save scan results to a file.
    """
    with open(file_name, 'w') as file:
        for host, ports in results.items():
            file.write(f"Host: {host}\n")
            file.write("Open TCP Ports: " + ", ".join(map(str, ports.get('TCP', []))) + "\n")
            file.write("Open UDP Ports: " + ", ".join(map(str, ports.get('UDP', []))) + "\n\n")
    print(f"Results saved to {file_name}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Enumeration and Port Scanning Toolkit")
    parser.add_argument('-n', '--network', help="Target network (e.g., 192.168.1.0/24)", required=True)
    parser.add_argument('-p', '--ports', help="Port range to scan (e.g., 1-1024)", default="1-1024")
    parser.add_argument('-o', '--output', help="Output file name", default="scan_results.txt")
    args = parser.parse_args()

    # Parse ports range
    start_port, end_port = map(int, args.ports.split('-'))
    ports = list(range(start_port, end_port + 1))

    results = {}

    # Discover live hosts
    live_hosts = discover_hosts(args.network)

    # Scan each live host for open ports
    for host in live_hosts:
        print(f"\nScanning {host}...")
        open_tcp_ports = tcp_syn_scan(host, ports)
        open_udp_ports = udp_scan(host, ports)
        results[host] = {'TCP': open_tcp_ports, 'UDP': open_udp_ports}

    # Save results to a file
    save_results(args.output, results)

if __name__ == "__main__":
    main()

