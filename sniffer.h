/*
 * sniffer.h
 *
 * This is the master header file for the project.
 * It includes all common C/C++ libraries, networking headers,
 * and threading headers. It also defines all custom data
 * structures and global, thread-safe components.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

// --- Standard C++ Headers ---
#include <iostream>     // For std::cout, std::cerr
#include <iomanip>      // For std::setw, std::setfill, std::hex
#include <map>          // For std::map (session tracking)
#include <vector>       // For std::vector (packet data buffering)
#include <string>       // For std::string (protocol-agnostic IPs)
#include <sstream>      // For std::stringstream (thread-safe output buffering)
#include <cctype>       // For isprint()
#include <csignal>      // For signal handling (SIGINT)

// --- Multithreading Headers ---
#include <thread>               // For std::thread
#include <mutex>                // For std::mutex, std::lock_guard, std::unique_lock
#include <condition_variable>   // For std::condition_variable
#include <queue>                // For std::queue
#include <atomic>               // For std::atomic<bool>

// --- C Networking Headers ---
#include <pcap.h>       // The main libpcap library
#include <arpa/inet.h>  // For ntohs, ntohl, inet_ntop
#include <netinet/if_ether.h> // For struct ether_header, ETHERTYPE_...
#include <netinet/ip.h>       // For struct ip, IPPROTO_...
#include <netinet/ip6.h>      // For struct ip6_hdr
#include <netinet/tcp.h>      // For struct tcphdr, TH_SYN, etc.
#include <netinet/udp.h>      // For struct udphdr
#include <netinet/ip_icmp.h>  // For ICMP
#include <netinet/icmp6.h>  // For ICMPv6
#include <net/if_arp.h>       // For system's arphdr

// --- C Standard Library Headers ---
#include <stdlib.h>     // For atoi, exit
#include <string.h>     // For strcmp

// --- Custom Header Definitions ---

/**
 * @struct my_arphdr
 * @brief Custom ARP header definition to avoid conflicts with
 * different system header implementations (e.g., macOS vs. Linux).
 */
struct my_arphdr {
    uint16_t htype;    // Hardware Type
    uint16_t ptype;    // Protocol Type
    uint8_t  hlen;     // Hardware Address Length
    uint8_t  plen;     // Protocol Address Length
    uint16_t oper;     // Operation Code (1=request, 2=reply)
    u_char   sha[6];   // Sender Hardware Address (MAC)
    u_char   spa[4];   // Sender Protocol Address (IP)
    u_char   tha[6];   // Target Hardware Address (MAC)
    u_char   tpa[4];   // Target Protocol Address (IP)
};

/**
 * @struct simple_dnshdr
 * @brief A simplified DNS header for parsing basic info.
 */
struct simple_dnshdr {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
};


// --- Producer-Consumer Queue Components ---

/**
 * @struct QueuedPacket
 * @brief A container to hold a packet's data and metadata
 * as it passes from the producer to the consumers.
 * Using std::vector ensures we have our own copy of the
 * packet data, as the libpcap buffer is ephemeral.
 */
struct QueuedPacket {
    pcap_pkthdr header;               // Packet metadata (timestamp, len)
    std::vector<u_char> data;         // Packet data buffer
};

// Global thread-safe queue for packets
extern std::queue<QueuedPacket> packet_queue;
extern std::mutex queue_mutex;
extern std::condition_variable queue_cond;

// Global flag to signal threads to shut down
extern std::atomic<bool> shutting_down;

// Global mutex to protect std::cout from being scrambled by threads
extern std::mutex print_mutex;

// Global pcap handle, needed for the signal handler to break the loop
extern pcap_t* g_handle;

#endif // SNIFFER_H