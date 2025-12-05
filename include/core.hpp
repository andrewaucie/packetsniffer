/*
 * core.hpp - Shared state and packet processing declarations
 */

#ifndef CORE_HPP
#define CORE_HPP

#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cctype>
#include <csignal>
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <chrono>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

struct my_arphdr {
    uint16_t htype, ptype;
    uint8_t  hlen, plen;
    uint16_t oper;
    u_char   sha[6], spa[4];
    u_char   tha[6], tpa[4];
};

struct simple_dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct TlsHostInfo {
    std::string hostname;
    std::string tls_version;
    int connection_count;
    unsigned long long bytes_transferred;
    std::chrono::steady_clock::time_point last_seen;
};

struct QueuedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;
};

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

extern std::atomic<bool> shutting_down;
extern pcap_t* g_handle;
extern std::string g_pcap_error;

extern std::queue<QueuedPacket> packet_queue;
extern std::mutex queue_mutex;
extern std::condition_variable queue_cond;

extern std::mutex stats_mutex;
extern std::map<std::string, long> stats_map;
extern std::map<std::string, long> ip_stats_map;
extern std::map<uint16_t, long> port_stats_map;
extern std::map<std::string, long> tcp_flags_count;
extern std::map<std::string, TlsHostInfo> tls_hosts_map;
extern const size_t MAX_TLS_HOSTS;
extern struct pcap_stat g_pcap_stats;
extern std::atomic<unsigned long> packets_processed;
extern std::atomic<unsigned long long> total_bytes;
extern std::atomic<unsigned long long> peak_bytes_per_sec;
extern std::atomic<long> tcp_session_count;
extern std::atomic<long> dns_queries;
extern std::atomic<long> dns_responses;
extern int g_num_worker_threads;

extern std::chrono::steady_clock::time_point capture_start_time;

extern std::mutex results_mutex;
extern std::deque<PacketSummary> results_queue;
extern const size_t MAX_RESULTS;

extern std::mutex timeline_mutex;
extern std::map<std::string, ConversationTimelineEntry> conversation_timeline;
extern const size_t MAX_TIMELINE_TRACKED;

void signal_handler(int signum);
void producer_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet);
void consumer_thread_loop();
void pcap_capture_thread(pcap_t *handle, int packet_count);
void print_usage(char *progname);

#endif
