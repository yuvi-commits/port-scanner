"""
Port Scanner
------------
A multithreaded TCP port scanner for scanning hosts you own or are
authorized to test. Supports custom port ranges, adjustable thread count,
timeout control, and service name identification.

Usage:
    python port_scanner.py <host> [-p PORT_RANGE] [-t THREADS] [--timeout SECONDS]

Examples:
    python port_scanner.py 192.168.1.1
    python port_scanner.py scanme.nmap.org -p 1-1024 -t 100
    python port_scanner.py 127.0.0.1 -p 20,22,80,443
"""

import argparse
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue

print_lock = threading.Lock()


def parse_ports(port_arg: str):
    """
    Parses a port argument into a sorted list of unique ports.
    Supports ranges ("1-1024") and comma-separated lists ("22,80,443"),
    including combinations ("22,80,1000-1010").
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            ports.add(port)
    return sorted(ports)


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{host}'")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float):
    """
    Attempts a TCP connection to a single port.
    Returns (port, is_open, service_name) if open, otherwise None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return (port, True, service)
    except socket.error:
        pass
    finally:
        sock.close()
    return None


def run_scan(ip: str, ports: list, threads: int, timeout: float):
    open_ports = []
    total = len(ports)
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                open_ports.append(result)
                with print_lock:
                    port, _, service = result
                    print(f"[+] Port {port:<6} OPEN   ({service})")

            # Simple progress indicator on the same line
            with print_lock:
                sys.stdout.write(f"\rScanned {completed}/{total} ports...")
                sys.stdout.flush()

    print()  # newline after progress indicator
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(
        description="A multithreaded TCP port scanner for authorized security testing.",
        epilog="Only scan systems you own or have explicit permission to test.",
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port(s) to scan, e.g. '1-1024', '22,80,443', or '22,80,1000-1010' (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds per port (default: 1.0)"
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    ip = resolve_host(args.host)

    print("=" * 50)
    print(f" Scanning target : {args.host} ({ip})")
    print(f" Port range      : {args.ports} ({len(ports)} ports)")
    print(f" Threads         : {args.threads}")
    print(f" Started at      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    start_time = datetime.now()
    open_ports = run_scan(ip, ports, args.threads, args.timeout)
    elapsed = (datetime.now() - start_time).total_seconds()

    print("=" * 50)
    if open_ports:
        print(f"Scan complete: {len(open_ports)} open port(s) found in {elapsed:.2f}s")
    else:
        print(f"Scan complete: no open ports found in {elapsed:.2f}s")
    print("=" * 50)


if __name__ == "__main__":
    main()
