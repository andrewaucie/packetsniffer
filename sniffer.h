/*
 * sniffer.h
 *
 * This is the master header file for the TUI project.
 * It includes all common C/C++ libraries, networking headers,
 * and threading headers. It also defines all custom data
 * structures and 'extern' declarations for global components.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

// --- Standard C++ Headers ---
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cctype>
#include <csignal>
#include <deque> // For the results queue

// --- TUI Header ---
#include <ncurses.h> // The TUI library

// --- Multithreading Headers ---
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

// --- C Networking Headers ---
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>

// --- C Standard Library Headers ---
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For usleep() in the UI thread

// --- Custom Header Definitions ---

// Custom ARP header (renamed to avoid conflicts)
struct my_arphdr {
    uint16_t htype, ptype;
    uint8_t  hlen, plen;
    uint16_t oper;
    u_char   sha[6], spa[4], tha[6], tpa[4];
};

// Simplified DNS header
struct simple_dnshdr {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
};

// --- Producer-Consumer Queue Components ---

/**
 * @struct QueuedPacket
 * @brief Holds a full copy of the packet data to be
 * passed from the producer to a consumer.
 */
struct QueuedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;
};

// 'extern' tells the compiler "this global exists, but is defined elsewhere"
extern std::queue<QueuedPacket> packet_queue;
extern std::mutex queue_mutex;
extern std::condition_variable queue_cond;

// --- TUI Model Data Structures ---

/**
 * @struct PacketSummary
 * @brief A lightweight struct holding the *results* of parsing one packet.
 * This is what consumers push to the UI thread.
 */
struct PacketSummary {
    int id;
    unsigned int len;
    std::string l3_protocol;
    std::string l4_protocol;
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;
    std::string info;
};

// --- Thread-Safe Global "Model" ---

// Global flag to signal all threads to shut down
extern std::atomic<bool> shutting_down;

// Global pcap handle, needed for the signal handler to break the loop
extern pcap_t* g_handle;

// (FIX) Global string to hold any pcap capture errors
extern std::string g_pcap_error;

// --- Statistics Model ---
extern std::mutex stats_mutex;
extern std::map<std::string, long> stats_map;
extern struct pcap_stat g_pcap_stats;

// --- Results Model ---
extern std::mutex results_mutex;
extern std::deque<PacketSummary> results_queue;
extern const size_t MAX_RESULTS;

#endif // SNIFFER_H