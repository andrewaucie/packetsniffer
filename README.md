C++ Professional Packet SnifferThis is a high-performance, stateful C++ packet sniffer that runs on the command line. It is capable of capturing live network traffic (or reading from a .pcap file), parsing protocols from Layer 2 to Layer 7, and performing stateful TCP stream reassembly.This tool is a practical demonstration of core C++ concepts (OOP, STL, memory management) and deep networking principles (protocol de-encapsulation, TCP state management).FeaturesMulti-Protocol Parsing:L2: Ethernet (with VLAN 802.1Q support)L3: IPv4, IPv6, and ARPL4: TCP, UDP, ICMP, and ICMPv6L7: Detects and parses DNS and HTTPStateful TCP Reassembly:Tracks individual TCP connections (for both IPv4 and IPv6).Buffers out-of-order packets.Reassembles and prints the full data stream (e.g., an entire HTTP request) when a connection closes (FIN/RST).Flexible Capture Options:Captures from a live network interface (-i).Reads packets from a saved .pcap file (-r).Powerful Filtering:Uses the standard BPF (Berkeley Packet Filter) syntax to filter captures (e.g., "tcp port 80" or "host 8.8.8.8").Advanced Protocol Handling:Correctly walks the IPv6 Extension Header chain to find the true L4 protocol.Parses ARP requests and replies to show local network lookups.Project StructureThe project is split into a professional, multi-file C++ structure for readability and maintainability.sniffer.cpp: (Main Executable)Contains only the main() function.Responsible for parsing command-line arguments and setting up the pcap capture session.sniffer.h: (Master Header)Includes all common C/C++ libraries and networking headers.Defines the custom structs (my_arphdr, simple_dnshdr).parsers.cpp / parsers.h: (The Core Logic)packet_handler(): The main pcap callback function.Contains all helper functions for parsing each protocol layer (e.g., handle_ipv4_packet, handle_udp_packet).This is the "stateless" part of the sniffer.reassembly.cpp / reassembly.h: (The "Depth" Feature)ConnectionTuple: A struct to uniquely identify a TCP connection (works for both IPv4/IPv6).ConnectionData: A class to store the buffered packet data.tcp_sessions: The global std::map that manages all active connections.Implements the "stateful" logic for stream reassembly.Getting StartedPrerequisitesYou must have the libpcap development library installed.On macOS: It is included with the Xcode Command Line Tools.On Linux (Ubuntu/Debian):sudo apt-get update
sudo apt-get install libpcap-dev
On Linux (Fedora/RHEL):sudo dnf install libpcap-devel
CompilationPlace all 6 files (sniffer.h, sniffer.cpp, parsers.h, parsers.cpp, reassembly.h, reassembly.cpp) in the same directory.Compile the project by linking all implementation files and the pcap library:g++ sniffer.cpp parsers.cpp reassembly.cpp -o sniffer -lpcap
If your compiler warns about C++17 features, you can specify an older standard (the code is C++11 compatible):g++ -std=c++11 sniffer.cpp parsers.cpp reassembly.cpp -o sniffer -lpcap
UsageThe program is run with command-line flags.Professional Sniffer Tool (Stateful, Multi-Protocol)
Usage: ./sniffer [options]
  -i <interface>   Live capture from <interface> (e.g., en0)
  -r <file>        Read packets from <file> (e.g., capture.pcap)
  -c <count>       Stop after <count> packets (default: 100)
  -f <filter>      Set BPF filter (e.g., "tcp port 80")
  -h               Show this help menu
Note: You must use sudo for any live capture (the -i flag) to grant the program permission to access the network card.ExamplesExample 1: See All Local Network TrafficThis is a great test to see everything, including ARP, ICMP, and IPv6 traffic.# Replace 'en0' with your device (e.g., wlan0 on Linux)
sudo ./sniffer -i en0
You will see a mix of traffic, including ARP requests from your computer asking for your router's MAC address:--- Packet #5 (42 bytes) ---
L2 - Dst MAC: ff:ff:ff:ff:ff:ff  Src MAC: 82:18:b1:03:ac:a8
L3 - Protocol: ARP
    L3 - ARP Operation: Request
        Who has 192.168.0.1? Tell 82:18:b1:03:ac:a8 (192.168.0.146)
Example 2: Reassemble an HTTP RequestThis demonstrates the TCP stream reassembly feature.In Terminal 1:# Listen *only* for unencrypted web traffic
sudo ./sniffer -i en0 -f "tcp port 80"
In Terminal 2:# Make an unencrypted web request
curl [http://http.debian.net/](http://http.debian.net/)
Terminal 1 Output:Your sniffer will print the individual packets (SYN, SYN-ACK, ACK, PSH...) and then, when the connection closes, it will print the two reassembled streams:--- REASSEMBLED STREAM (192.168.0.146:49592 -> 151.101.126.132:80) ---
GET / HTTP/1.1
Host: http.debian.net
User-Agent: curl/8.7.1
Accept: */*

--- REASSEMBLED STREAM (151.101.126.132:80 -> 192.168.0.146:49592) ---
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 1876
...
<!DOCTYPE HTML PUBLIC ...>
... (rest of HTML page) ...
--- END OF CONVERSATION ---
Example 3: Monitor DNS LookupsThis shows the L7 parser for DNS (which runs over UDP).In Terminal 1:# Listen *only* for DNS traffic
sudo ./sniffer -i en0 -f "udp port 53"
In Terminal 2:# Ping a website to trigger a DNS lookup
ping google.com
Terminal 1 Output:You will see the DNS "Question" packet from your computer and the "Answer" packet from the DNS server.--- Packet #1 (78 bytes) ---
L3 - Protocol: IPv4
    L3 - From IP: 192.168.0.146 -> To IP: 8.8.8.8
    L4 - UDP: 192.168.0.146:58804 -> 8.8.8.8:53
        L7 - DNS:
            ID: 0x4a1b  Questions: 1  Answers: 0

--- Packet #2 (122 bytes) ---
L3 - Protocol: IPv4
    L3 - From IP: 8.8.8.8 -> To IP: 192.168.0.146
    L4 - UDP: 8.8.8.8:53 -> 192.168.0.146:58804
        L7 - DNS:
            ID: 0x4a1b  Questions: 1  Answers: 1
Example 4: Analyze a Saved FileThis is perfect for debugging. You can capture traffic with a tool like Wireshark or tcpdump and analyze it with your sniffer. No sudo is required.# First, create a small capture file
sudo tcpdump -i en0 -c 20 -w test.pcap

# Now, analyze that file with your tool
./sniffer -r test.pcap
A Note for macOS UsersmacOS has strong security features. Even with sudo, pcap may be blocked from capturing all traffic. If your sniffer sees no packets, you must grant "Full Disk Access" to your terminal application.Go to System Settings > Privacy & Security > Full Disk Access.Click +, authenticate, and add your terminal application (e.g., Terminal.app or iTerm.app).If you are running the sniffer from VS Code's integrated terminal, you must add Visual Studio Code.app.Quit and restart your terminal application for the changes to take effect.