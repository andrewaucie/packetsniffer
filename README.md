# C++ Professional Packet Sniffer (TUI Edition)

## Overview
This project is a multithreaded, ncurses-driven packet sniffer that ingests live traffic or offline `.pcap` files, performs full Layer 2–7 decoding, and reassembles TCP streams in real time. It is designed as a professional-grade reference for modern C++ (C++11) networking, demonstrating producer/consumer pipelines, stateful parsing, and an operator-friendly terminal UI.

## Highlights
- **Interactive dashboard** – ncurses layout with live protocol counts, libpcap statistics, bandwidth metrics, top talkers, TLS host tracking, and a scrollable packet log. Resize your terminal freely; the panes adapt automatically.
- **Threaded capture pipeline** – dedicated producer thread feeds a worker pool (`-t <threads>` or auto-detected) so parsing keeps up with busy links without dropping packets.
- **Deep protocol coverage** – Ethernet (incl. 802.1Q), IPv4/IPv6, ARP, TCP, UDP, ICMP/ICMPv6, DNS decoding, TLS SNI extraction, and HTTP request/response extraction.
- **Stateful TCP reassembly** – rebuilds byte streams bidirectionally, handles out-of-order segments, and prints each conversation once FIN/RST is observed.
- **Conversation timeline** – per-flow view of handshake latency, first-response time, duration, byte balance (client vs. server), and color-coded connection state.
- **Packet log controls** – pause/resume capture, scroll through history, and apply display filters to search by IP, port, protocol, or payload info.
- **Flexible sources & filters** – capture from an interface (`-i`) or offline file (`-r`), apply standard BPF expressions (`-f "tcp port 80"`), and optionally stop after N packets (`-c`).
- **Operational safeguards** – graceful shutdown on `q`/`Ctrl+C`, defensive ncurses initialization (TERM validation, sudo preservation), and real-time visibility into drops and queue depth.

## Build & Install

### Prerequisites
- `libpcap` development headers
- `ncurses` development headers
- A C++11-capable compiler (tested with `g++`)

macOS (with Xcode CLT) already ships `libpcap` and `ncurses`.  
Ubuntu / Debian:

```
sudo apt update
sudo apt install build-essential libpcap-dev libncurses5-dev
```

Fedora / RHEL:

```
sudo dnf install gcc-c++ libpcap-devel ncurses-devel
```

### Build

```
cd /Users/andrewaucie/Desktop/D58
make
```

The Makefile links `libpcap`, `pthread`, and `ncurses`. Run `make clean` to remove artifacts.

## Running the Sniffer

```
sudo ./sniffer [options]
```

| Option | Description |
| --- | --- |
| `-i <interface>` | Live capture from the given device (e.g., `en0`, `eth0`). |
| `-r <file>` | Read packets from a saved capture. Implies offline mode (no sudo needed). |
| `-c <count>` | Stop after N packets. Default `-1` means run until stopped. |
| `-f <filter>` | Berkeley Packet Filter expression (`tcp`, `udp port 53`, etc.). |
| `-t <threads>` | Number of worker threads. Defaults to hardware concurrency minus one. |
| `-h` | Show usage help and exit. |

Press `q` inside the UI to stop gracefully. `Ctrl+C` is also handled, ensuring ncurses restores the terminal state.

### Example Workflows

- **Watch everything on an interface**
  ```
  sudo ./sniffer -i en0
  ```

- **Inspect HTTPS traffic (TLS SNI extraction)**
  ```
  sudo ./sniffer -i en0 -f "tcp port 443"
  ```
  Watch TLS handshakes and SNI hostnames appear in the live packet log.

- **Focus on DNS diagnostics**
  ```
  sudo ./sniffer -i en0 -f "udp port 53"
  ping google.com
  ```
  Observe question/answer flows and top talkers for DNS servers.

- **Analyze a captured file offline**
  ```
  sudo tcpdump -i en0 -c 50 -w test.pcap
  ./sniffer -r test.pcap
  ```

## UI Reference

The dashboard consists of six auto-resizing panes. Resize the terminal to allocate more space to sections you care about—the layout recomputes dynamically.

### Protocol Stats (top-left)
- Running counts per protocol with percentages (IPv4, IPv6, TCP, UDP, ICMP, ARP, TLS, HTTP, DNS, etc.)
- Color-coded: TCP (blue), UDP (yellow), ICMP/ARP/IPv6 (magenta), TLS (green)
- TCP Flags breakdown showing SYN, ACK, FIN, RST, PSH counts

### Capture Stats (top-center)
- Worker thread count and real-time processing rate (packets/sec)
- libpcap totals: received, processed, dropped (red highlight if drops occur)
- Queue backlog for back-pressure visibility
- Total bytes transferred
- **TLS Hosts** – recently seen HTTPS hostnames with TLS version, connection count, and bytes transferred

### Live Bandwidth (top-right)
- Current bandwidth (exponentially smoothed), peak, and session average
- Total bytes and capture duration
- TCP session count and unique IP count
- DNS query/response counters
- **Top Ports** – most active ports with well-known service names (HTTP, HTTPS, SSH, DNS, etc.)

### Top Talkers (bottom-left)
- Ranked IP address leaderboard sorted by bytes
- Visual bar chart showing relative traffic volume
- Supports both IPv4 and IPv6 addresses

### Conversation Timeline (bottom-right, upper)
- Per-flow metrics: handshake latency, first-response time, total duration
- Bidirectional byte counts (up/down)
- Connection state with color coding: Handshake (cyan), Established/Streaming (green), Closed (red)

### Packet Log (bottom-right, lower)
Interactive packet view with columns: ID, L3, L4, Size, Time, Source, Destination, Info

| Key | Action |
| --- | --- |
| `SPACE` | Pause/resume live capture |
| `/` | Enter filter mode (searches IP, port, protocol, info) |
| `ESC` | Clear filter and scroll position |
| `↑`/`w` | Scroll toward newer packets |
| `↓`/`s` | Scroll toward older packets (auto-pauses) |
| `PgUp`/`PgDn` | Scroll by page |
| `a`/`Home` | Jump to newest packet |
| `d`/`End` | Jump to oldest packet |
| `q` | Quit gracefully |

Features a visual scrollbar and scroll position indicator. Protocols are color-coded to match the stats pane.

## Architecture Overview
- `src/main.cpp` – main entry point, CLI parsing, and thread orchestration.
- `src/core.cpp` / `include/core.hpp` – packet capture pipeline (producer/consumer), protocol decoding (L2-L7), timeline tracking, and shared application state.
- `src/ui.cpp` / `include/ui.hpp` – ncurses lifecycle, window management, and all rendering functions.
- `src/reassembly.cpp` / `include/reassembly.hpp` – TCP state tracking via `ConnectionTuple` and `ConnectionData`, buffering segments until FIN/RST, then flushing the reconstructed stream.

The pipeline follows a classical producer/consumer pattern:
1. **Producer** (`pcap_capture_thread`) grabs frames and enqueues decoded metadata plus raw payload.
2. **Workers** pull from the queue, run protocol-specific parsers, and update stats/top talkers.
3. **UI thread** renders the shared state at ~10 Hz while watching for `q`.

## Troubleshooting & Tips
- Run with `sudo -E` (or export `TERM`) to ensure the ncurses dashboard initializes when elevating privileges.
- On macOS, grant Full Disk Access to your terminal/iTerm/VS Code if `libpcap` appears to drop all packets.
- If the queue grows and drops spike, increase worker threads (`-t`) or narrow the BPF filter.
- Use `error_log.txt` for troubleshooting unexpected runtime failures; the program appends detailed messages before exiting.

