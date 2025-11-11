/*
 * core.hpp
 *
 * Core packet capture, processing, and timeline tracking.
 * Provides the producer/consumer pipeline and shared application state.
 */

#ifndef CORE_HPP
#define CORE_HPP

// --- Standard C++ Headers ---
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cctype>
#include <csignal>
#include <deque>

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
#include <unistd.h>
#include <sys/time.h>

// --- Custom Header Definitions ---

/**
 * @struct my_arphdr
 * @brief Custom ARP header structure (renamed to avoid conflicts with system headers)
 */
struct my_arphdr {
    uint16_t htype, ptype;    ///< Hardware and protocol types
    uint8_t  hlen, plen;      ///< Hardware and protocol address lengths
    uint16_t oper;            ///< Operation (1=request, 2=reply)
    u_char   sha[6], spa[4];  ///< Sender hardware and protocol addresses
    u_char   tha[6], tpa[4];  ///< Target hardware and protocol addresses
};

/**
 * @struct simple_dnshdr
 * @brief Simplified DNS header structure for basic parsing
 */
struct simple_dnshdr {
    uint16_t id;       ///< Query ID
    uint16_t flags;    ///< DNS flags
    uint16_t qdcount;  ///< Question count
    uint16_t ancount;  ///< Answer count
    uint16_t nscount;  ///< Name server count
    uint16_t arcount;  ///< Additional records count
};

// --- Data Structures ---

/**
 * @struct QueuedPacket
 * @brief Holds a full copy of the packet data to be
 * passed from the producer to a consumer.
 */
struct QueuedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;
};

/**
 * @struct PacketSummary
 * @brief A lightweight struct holding the *results* of parsing one packet.
 * This is what consumers push to the UI thread.
 */
struct PacketSummary {
    int id;
    unsigned int len;
    struct timeval timestamp;
    std::string l3_protocol;
    std::string l4_protocol;
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;
    std::string info;
    int ttl;
};

/**
 * @struct ConversationTimelineEntry
 * @brief Tracks timing milestones and byte counts for a TCP conversation.
 */
struct ConversationTimelineEntry {
    std::string flow_label;
    std::string client_ip;
    std::string server_ip;
    uint16_t client_port;
    uint16_t server_port;

    struct timeval start_ts;
    struct timeval last_ts;

    bool syn_seen;
    bool synack_seen;
    bool ack_seen;
    struct timeval syn_ts;
    struct timeval synack_ts;
    struct timeval ack_ts;

    bool first_payload_c2s_seen;
    bool first_payload_s2c_seen;
    struct timeval first_payload_c2s_ts;
    struct timeval first_payload_s2c_ts;

    bool closed;
    struct timeval close_ts;

    size_t bytes_c2s;
    size_t bytes_s2c;

    std::string forward_key;
    std::string reverse_key;
};

// --- Global Application State ---

/** @brief Global flag to signal all threads to shut down */
extern std::atomic<bool> shutting_down;

/** @brief Global pcap handle, needed for the signal handler to break the loop */
extern pcap_t* g_handle;

/** @brief Global string to hold any pcap capture errors */
extern std::string g_pcap_error;

// --- Producer-Consumer Queue ---
extern std::queue<QueuedPacket> packet_queue;
extern std::mutex queue_mutex;
extern std::condition_variable queue_cond;

// --- Statistics Model ---
extern std::mutex stats_mutex;
/** @brief Protocol statistics (e.g., "TCP": 123) */
extern std::map<std::string, long> stats_map;
/** @brief Per-IP byte counters for top talkers */
extern std::map<std::string, long> ip_stats_map;
/** @brief pcap library statistics (packets received, dropped, etc.) */
extern struct pcap_stat g_pcap_stats;
/** @brief Total packets processed by consumer threads */
extern std::atomic<unsigned long> packets_processed;
/** @brief Total bytes observed across all packets */
extern std::atomic<unsigned long long> total_bytes;
/** @brief Count of active TCP sessions being tracked */
extern std::atomic<long> tcp_session_count;

// --- Results Model ---
extern std::mutex results_mutex;
/** @brief Recent packet summaries for display in the main window */
extern std::deque<PacketSummary> results_queue;
/** @brief Maximum number of packet summaries to retain */
extern const size_t MAX_RESULTS;

// --- Conversation Timeline Model ---
extern std::mutex timeline_mutex;
/** @brief Map of active TCP conversations with timing information */
extern std::map<std::string, ConversationTimelineEntry> conversation_timeline;
/** @brief Maximum number of conversations to track simultaneously */
extern const size_t MAX_TIMELINE_TRACKED;

// --- Function Declarations ---

/**
 * @brief Signal handler for Ctrl+C (SIGINT) and window resize (SIGWINCH).
 */
void signal_handler(int signum);

/**
 * @brief The PRODUCER callback. Called by pcap_loop.
 */
void producer_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief The CONSUMER loop. Run by all worker threads.
 */
void consumer_thread_loop();

/**
 * @brief The PRODUCER thread function.
 */
void pcap_capture_thread(pcap_t *handle, int packet_count);

/**
 * @brief Prints the command-line help menu (to standard error).
 */
void print_usage(char *progname);

#endif // CORE_HPP

