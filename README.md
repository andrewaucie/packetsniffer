# C++ Professional Packet Sniffer (TUI Edition)

## Overview
This project is a multithreaded, ncurses-driven packet sniffer that ingests live traffic or offline `.pcap` files, performs full Layer 2–7 decoding, and reassembles TCP streams in real time. It is designed as a professional-grade reference for modern C++ (C++11) networking, demonstrating producer/consumer pipelines, stateful parsing, and an operator-friendly terminal UI.

## Highlights
- **Interactive dashboard** – ncurses layout with live protocol counts, libpcap statistics, bandwidth graph, top talkers, and a rolling packet log. Resize your terminal freely; the panes adapt automatically.
- **Threaded capture pipeline** – dedicated producer thread feeds a worker pool (`-t <threads>` or auto-detected) so parsing keeps up with busy links without dropping packets.
- **Deep protocol coverage** – Ethernet (incl. 802.1Q), IPv4/IPv6, ARP, TCP, UDP, ICMP/ICMPv6, DNS decoding, and HTTP request/response extraction.
- **Stateful TCP reassembly** – rebuilds byte streams bidirectionally, handles out-of-order segments, and prints each conversation once FIN/RST is observed.
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

- **Inspect cleartext HTTP with TCP reassembly**
  ```
  sudo ./sniffer -i en0 -f "tcp port 80"
  curl http://example.com
  ```
  Reassembled request/response bodies appear in the live packet log when sessions close.

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
- **Protocol Stats** – running counts per L2/L3/L4/L7 classification (`Ethernet`, `IPv6`, `TCP`, `HTTP`, etc.).
- **Capture Stats** – libpcap totals (received, processed, dropped) and current queue size for back-pressure visibility.
- **Live Bandwidth** – smoothed bytes-per-second meter with human-readable units.
- **Top Talkers** – rolling leaderboard of IPs producing the most traffic, independent of protocol.
- **Packet Log** – tail of detailed packet summaries and reassembly output; updated continuously.

Resize the terminal to allocate more space to the sections you care about. The layout recomputes each pass of the UI loop.

## Architecture Overview
- `sniffer.cpp` – main entry point, CLI parsing, ncurses lifecycle, producer thread (`pcap_loop`), and worker pool orchestration.
- `parsers.cpp` / `parsers.h` – protocol decoding routines used by the workers; updates statistics and composes `PacketSummary` records.
- `reassembly.cpp` / `reassembly.h` – TCP state tracking via `ConnectionTuple` and `ConnectionData`, buffering segments until FIN/RST, then flushing the reconstructed stream.

The pipeline follows a classical producer/consumer pattern:
1. **Producer** (`pcap_capture_thread`) grabs frames and enqueues decoded metadata plus raw payload.
2. **Workers** pull from the queue, run protocol-specific parsers, and update stats/top talkers.
3. **UI thread** renders the shared state at ~10 Hz while watching for `q`.

## Troubleshooting & Tips
- Run with `sudo -E` (or export `TERM`) to ensure the ncurses dashboard initializes when elevating privileges.
- On macOS, grant Full Disk Access to your terminal/iTerm/VS Code if `libpcap` appears to drop all packets.
- If the queue grows and drops spike, increase worker threads (`-t`) or narrow the BPF filter.
- Use `error_log.txt` for troubleshooting unexpected runtime failures; the program appends detailed messages before exiting.

Happy packet hunting!

