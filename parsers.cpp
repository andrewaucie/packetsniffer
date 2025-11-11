/*
 * parsers.cpp
 *
 * Defines the main producer/consumer logic and all
 * the L2-L7 helper functions for parsing.
 *
 * This file implements the core of the multithreaded
 * architecture.
 */

#include "parsers.h"
#include "sniffer.h"
#include "reassembly.h" // For TCP reassembly
#include <chrono>

// Thread-safe atomic packet counter
// This is 'static' so it is local *only* to this file.
static std::atomic<int> packet_id(1);

// Anonymous namespace for static helper functions
// This restricts their scope to this file, which is good practice.
namespace {

// --- Helper Parser Functions (static) ---

/**
 * @brief Helper to format a MAC address to a string.
 */
static std::string mac_to_string(const u_char *addr) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(addr[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}

/**
 * @brief L7 Parser for DNS. Populates the info string.
 */
static void parse_dns(const u_char *payload, unsigned int len, PacketSummary& summary) {
    if (len < static_cast<unsigned int>(sizeof(simple_dnshdr))) return;
    const struct simple_dnshdr *dns_header = (const struct simple_dnshdr *)payload;
    
    std::stringstream ss;
    ss << "ID: 0x" << std::hex << ntohs(dns_header->id) << std::dec
       << " Q: " << ntohs(dns_header->qdcount)
       << " A: " << ntohs(dns_header->ancount);
    summary.info = ss.str();
}

/**
 * @brief L4 Parser for TCP packets. Populates the summary.
 */
static void handle_tcp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary) {
    if (l4_len < static_cast<unsigned int>(sizeof(tcphdr))) return; 
    const struct tcphdr *tcp_header = (const struct tcphdr *)(l4_payload);
    
    summary.src_port = std::to_string(ntohs(tcp_header->th_sport));
    summary.dst_port = std::to_string(ntohs(tcp_header->th_dport));

    // Get flags
    std::string flags = "";
    if (tcp_header->th_flags & TH_SYN) flags += "SYN ";
    if (tcp_header->th_flags & TH_ACK) flags += "ACK ";
    if (tcp_header->th_flags & TH_FIN) flags += "FIN ";
    if (tcp_header->th_flags & TH_RST) flags += "RST ";
    if (tcp_header->th_flags & TH_PUSH) flags += "PSH ";

    // --- Reassembly Logic ---
    unsigned int tcp_header_size = tcp_header->th_off * 4;
    if (tcp_header_size < 20 || tcp_header_size > l4_len) return; 
    
    unsigned int payload_offset = tcp_header_size;
    unsigned int payload_len = l4_len - payload_offset;

    ConnectionTuple tuple;
    tuple.ip_src = summary.src_ip;
    tuple.ip_dst = summary.dst_ip;
    tuple.sport = tcp_header->th_sport;
    tuple.dport = tcp_header->th_dport;
    uint32_t seq_num = ntohl(tcp_header->th_seq);

    if (payload_len > 0) {
        // We have data, add the reassembly summary to the flags
        flags += handle_tcp_reassembly(l4_payload + payload_offset, payload_len, seq_num, tuple);
    }
    summary.info = flags; // Set the final info string

    if (tcp_header->th_flags & (TH_FIN | TH_RST)) {
        // Stream is closing. Get the summary and push *it*
        // to the results queue as a separate event.
        PacketSummary stream_summary = handle_stream_close(tuple);
        stream_summary.id = packet_id++; // Use the atomic counter
        
        std::lock_guard<std::mutex> lock(results_mutex);
        results_queue.push_back(std::move(stream_summary));
        if (results_queue.size() > MAX_RESULTS) {
            results_queue.pop_front();
        }
    }
}

/**
 * @brief L4 Parser for UDP packets. Populates the summary.
 */
static void handle_udp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary) {
    if (l4_len < static_cast<unsigned int>(sizeof(udphdr))) return; 
    const struct udphdr *udp_header = (const struct udphdr *)(l4_payload);
    
    summary.src_port = std::to_string(ntohs(udp_header->uh_sport));
    summary.dst_port = std::to_string(ntohs(udp_header->uh_dport));

    // L7 DNS Hook
    if (summary.src_port == "53" || summary.dst_port == "53") {
        unsigned int payload_offset = sizeof(udphdr);
        unsigned int payload_len = l4_len - payload_offset;
        parse_dns(l4_payload + payload_offset, payload_len, summary);
    }
}

/**
 * @brief L3 Parser for ARP packets. Populates the summary.
 */
static void handle_arp_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(my_arphdr))) return; 
    const struct my_arphdr *arp_header = (const struct my_arphdr *)l3_payload;

    uint16_t op = ntohs(arp_header->oper);
    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    summary.src_ip = spa_str;
    summary.dst_ip = tpa_str;
    
    if (op == 1) { // Request
        summary.info = "Request: Who has " + std::string(tpa_str) + "? Tell " + std::string(spa_str);
    } else if (op == 2) { // Reply
        summary.info = "Reply: " + std::string(spa_str) + " is at " + mac_to_string(arp_header->sha);
    }
}

/**
 * @brief L3 Parser for IPv4 packets. Populates the summary.
 */
static void handle_ipv4_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(ip))) return; 
    const struct ip *ip_header = (const struct ip *)(l3_payload);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    summary.src_ip = src_ip_str;
    summary.dst_ip = dst_ip_str;

    unsigned int ip_header_size = ip_header->ip_hl * 4;
    if (ip_header_size < 20) return; // Basic validation

    unsigned int l4_offset = ip_header_size;
    if (l4_offset > l3_len) return; // Check for malformed packet
    unsigned int l4_len = l3_len - l4_offset;
    const u_char *l4_payload = l3_payload + l4_offset;
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            summary.l4_protocol = "TCP";
            handle_tcp_packet(l4_payload, l4_len, summary);
            break;
        case IPPROTO_UDP:
            summary.l4_protocol = "UDP";
            handle_udp_packet(l4_payload, l4_len, summary);
            break;
        case IPPROTO_ICMP:
            summary.l4_protocol = "ICMP";
            summary.info = "ICMP Packet";
            break;
        default:
            summary.l4_protocol = "Other";
            break;
    }
}

/**
 * @brief L3 Parser for IPv6 packets. Populates the summary.
 */
static void handle_ipv6_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(ip6_hdr))) return; 
    const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)(l3_payload);

    char src_ip6[INET6_ADDRSTRLEN];
    char dst_ip6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);
    summary.src_ip = src_ip6;
    summary.dst_ip = dst_ip6;

    int next_header_type = ip6_header->ip6_nxt;
    unsigned int l4_offset = sizeof(struct ip6_hdr);

    while (next_header_type == IPPROTO_HOPOPTS || next_header_type == IPPROTO_ROUTING ||
           next_header_type == IPPROTO_FRAGMENT || next_header_type == IPPROTO_DSTOPTS ||
           next_header_type == IPPROTO_AH || next_header_type == IPPROTO_ESP) {
        
        if (l3_len < l4_offset + 2) break; 
        next_header_type = (int)l3_payload[l4_offset];
        int header_len = (int)l3_payload[l4_offset + 1];
        l4_offset += (header_len * 8) + 8;
        if (l4_offset > l3_len) break; 
    }
    
    unsigned int l4_len = l3_len - l4_offset;
    const u_char *l4_payload = l3_payload + l4_offset;

    switch (next_header_type) {
        case IPPROTO_TCP:
            summary.l4_protocol = "TCP";
            handle_tcp_packet(l4_payload, l4_len, summary);
            break;
        case IPPROTO_UDP:
            summary.l4_protocol = "UDP";
            handle_udp_packet(l4_payload, l4_len, summary);
            break;
        case IPPROTO_ICMPV6:
            summary.l4_protocol = "ICMPv6";
            summary.info = "ICMPv6 Packet";
            break;
        default:
            summary.l4_protocol = "Other";
            break;
    }
}

/**
 * @brief Main packet processing function, called by a consumer.
 * This is the root of the parsing logic.
 * @param header pcap metadata
 * @param packet Raw packet data
 * @return A PacketSummary struct containing the parsed results.
 */
static PacketSummary process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    PacketSummary summary;
    summary.id = packet_id++; // Atomically increment and assign
    summary.len = header->caplen;

    const struct ether_header *eth_header = (const struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    unsigned int l3_offset = sizeof(struct ether_header); 

    if (ether_type == ETHERTYPE_VLAN) {
        ether_type = ntohs(*(uint16_t *)(packet + l3_offset + 2));
        l3_offset += 4;
    }
    
    if (l3_offset > header->caplen) {
        summary.info = "Malformed L2 Header";
        return summary;
    }
    unsigned int l3_len = header->caplen - l3_offset; 
    const u_char *l3_payload = packet + l3_offset;

    switch (ether_type) {
        case ETHERTYPE_IP:
            summary.l3_protocol = "IPv4";
            handle_ipv4_packet(l3_payload, l3_len, summary);
            break;
        case ETHERTYPE_IPV6:
            summary.l3_protocol = "IPv6";
            handle_ipv6_packet(l3_payload, l3_len, summary);
            break;
        case ETHERTYPE_ARP:
            summary.l3_protocol = "ARP";
            handle_arp_packet(l3_payload, l3_len, summary);
            break;
        default:
            summary.l3_protocol = "Other";
            break;
    }
    return summary;
}

// Close the anonymous namespace
}


// --- Producer/Consumer Functions (Public) ---

/**
 * @brief The PRODUCER callback. Called by pcap_loop.
 */
void producer_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user_data; // Mark as unused to silence -Wunused-parameter

    QueuedPacket qp;
    qp.header = *header;
    qp.data.assign(packet, packet + header->caplen);
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        packet_queue.push(std::move(qp));
    }
    queue_cond.notify_one();
}

/**
 * @brief The CONSUMER loop. Run by all worker threads.
 */
void consumer_thread_loop() {
    
    // {
    //     // Use stringstream for thread-safe startup message
    //     std::stringstream ss;
    //     ss << "[Worker thread " << std::this_thread::get_id() << " started]" << std::endl;
    //     // Lock only when printing
    //     std::lock_guard<std::mutex> lock(stats_mutex); // Use stats_mutex, it's shared
    //     std::cout << ss.str();
    // }
    
    while (true) {
        QueuedPacket packet_to_process;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cond.wait(lock, []{
                return !packet_queue.empty() || shutting_down;
            });
            if (shutting_down && packet_queue.empty()) {
                break;
            }
            packet_to_process = std::move(packet_queue.front());
            packet_queue.pop();
        }

        // --- 1. Process Packet ---
        PacketSummary summary = process_packet(&packet_to_process.header, packet_to_process.data.data());

        // --- 2. Update Model ---
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats_map[summary.l3_protocol]++;
            if (!summary.l4_protocol.empty()) {
                stats_map[summary.l4_protocol]++;
            }
        }
        
        {
            std::lock_guard<std::mutex> lock(results_mutex);
            results_queue.push_back(std::move(summary));
            if (results_queue.size() > MAX_RESULTS) {
                results_queue.pop_front();
            }
        }
    }

    // {
    //     // Use stringstream for thread-safe shutdown message
    //     std::stringstream ss;
    //     ss << "[Worker thread " << std::this_thread::get_id() << " shutting down]" << std::endl;
    //     std::lock_guard<std::mutex> lock(stats_mutex);
    //     std::cout << ss.str();
    // }
}

/**
 * @brief The PRODUCER thread function.
 */
void pcap_capture_thread(pcap_t *handle, int packet_count) {
    // (FIX) Check pcap_loop's return value for errors.
    int ret = pcap_loop(handle, packet_count, producer_callback, NULL);
    
    if (ret == -1) {
        // A pcap error occurred. Store it so main can print it.
        g_pcap_error = pcap_geterr(handle);
    }
    // ret == 0 means it finished (hit packet_count)
    // ret == -2 means it was broken by pcap_breakloop (user pressed 'q' or Ctrl+C)
    // All of these are valid reasons to shut down.

    // After the loop finishes (for any reason),
    // signal the shutdown.
    shutting_down = true;
    queue_cond.notify_all(); // Wake up all workers
}