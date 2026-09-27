# 🔍 Port Scanner

A fast, multithreaded TCP port scanner written in Python. Built for learning
network fundamentals and practicing security-tooling development — scans a
target host across a specified port range and reports which ports are open,
along with the associated service name where available.

> ⚠️ **Ethical use only.** Only scan hosts you own or have explicit written
> permission to test. Scanning systems without authorization may be illegal
> in your jurisdiction. `scanme.nmap.org` is provided by the Nmap project
> specifically for practicing scans.

## Features

- **Multithreaded scanning** — scans hundreds of ports concurrently instead of one at a time
- **Flexible port selection** — single ports, ranges, or a mix (`22,80,1000-1010`)
- **Service identification** — maps common open ports to their service name (e.g. 22 → ssh)
- **Configurable timeout and thread count** — tune for speed vs. reliability
- **Hostname or IP support** — automatically resolves domain names

## Requirements

- Python 3.7+
- No external dependencies — uses only the standard library (`socket`, `argparse`, `concurrent.futures`)

## Usage

```bash
python port_scanner.py <host> [-p PORT_RANGE] [-t THREADS] [--timeout SECONDS]
```

### Examples

Scan the default range (ports 1–1024) on a local machine:
```bash
python port_scanner.py 127.0.0.1
```

Scan a specific range with more threads for speed:
```bash
python port_scanner.py scanme.nmap.org -p 1-1024 -t 200
```

Scan a specific list of ports:
```bash
python port_scanner.py 127.0.0.1 -p 22,80,443
```

Scan a mix of individual ports and ranges:
```bash
python port_scanner.py 127.0.0.1 -p 21,22,80,1000-1010
```

## Sample output

```
==================================================
 Scanning target : 127.0.0.1 (127.0.0.1)
 Port range      : 22,80,443 (3 ports)
 Threads         : 100
 Started at      : 2026-09-27 14:02:11
==================================================
[+] Port 22     OPEN   (ssh)
[+] Port 80     OPEN   (http)
Scanned 3/3 ports...
==================================================
Scan complete: 2 open port(s) found in 0.14s
==================================================
```

## How it works

1. The target hostname is resolved to an IP address using `socket.gethostbyname`.
2. The requested port range/list is parsed into a sorted list of unique ports.
3. A `ThreadPoolExecutor` dispatches a connection attempt (`connect_ex`) for
   each port concurrently, dramatically reducing total scan time compared to
   a sequential loop.
4. Ports that accept a connection are reported as open, with a best-effort
   service name lookup via `socket.getservbyport`.

## What I learned building this

- Socket programming and the TCP three-way handshake at a practical level
- Using `concurrent.futures.ThreadPoolExecutor` to parallelize I/O-bound work
- Thread-safe printing with locks to avoid garbled console output
- Designing a clean CLI with `argparse`, including custom input validation

## Possible improvements

- [ ] Add UDP scanning support
- [ ] Add banner grabbing for open ports (read service version info)
- [ ] Export results to JSON/CSV
- [ ] Add a `--stealth` mode using raw SYN scanning (requires elevated privileges)

## Disclaimer

This tool is intended for educational purposes and authorized security
testing only. The author is not responsible for misuse of this software.
