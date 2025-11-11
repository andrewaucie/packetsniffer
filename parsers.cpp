/*
 * parsers.cpp
 *
 * Defines the main producer/consumer logic and all
 * the L2-L7 helper functions for parsing.
 *
 * This file implements the core of the multithreaded
 * architecture and the "shippable" performance fix.
 */

#include "parsers.h"
#include "sniffer.h"
#include "reassembly.h" // For TCP reassembly
#include <chrono>

// --- Global Variable Definitions ---
// (These are *defined* here and *declared* in sniffer.h)
std::queue<QueuedPacket> packet_queue;
std::mutex queue_mutex;
std::condition_variable queue_cond;
std::atomic<bool> shutting_down(false);
std::mutex print_mutex;

// Thread-safe atomic packet counter
static std::atomic<int> packet_count(1);

// --- Helper Parser Functions (static) ---
// These functions are 'static', meaning they are only visible
// within this file (parsers.cpp). They are the helper
// functions for process_packet().

/**
 * @brief Helper to write a MAC address to a stringstream.
 */
static void print_mac_address(const u_char *addr, std::stringstream& ss) {
    // Save current stream state
    std::ios_base::fmtflags flags = ss.flags();
    char fill = ss.fill();
    
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(addr[i]);
        if (i < 5) ss << ":";
    }
    ss << std::dec;
    
    // Restore stream state
    ss.flags(flags);
    ss.fill(fill);
}

/**
 * @brief L7 Parser for DNS.
 */
static void parse_dns(const u_char *payload, int len, std::stringstream& ss) {
    if (len < sizeof(simple_dnshdr)) return;
    const struct simple_dnshdr *dns_header = (const struct simple_dnshdr *)payload;
    ss << "        L7 - DNS:" << std::endl;
    
    // Save stream state
    std::ios_base::fmtflags flags = ss.flags();
    ss << "            ID: 0x" << std::hex << ntohs(dns_header->id) << std::dec
       << "  Questions: " << ntohs(dns_header->qdcount)
       << "  Answers: " << ntohs(dns_header->ancount) << std::endl;
    // Restore stream state
    ss.flags(flags);
}

/**
 * @brief L4 Parser for TCP packets.
 */
static void handle_tcp_packet(const u_char *l4_payload, int l4_len, std::string src_ip_str, std::string dst_ip_str, std::stringstream& ss) {
    if (l4_len < sizeof(tcphdr)) return;

    const struct tcphdr *tcp_header = (const struct tcphdr *)(l4_payload);
    uint tcp_header_size = tcp_header->th_off * 4;
    if (tcp_header_size < 20 || tcp_header_size > l4_len) {
        ss << "    L4 - Invalid TCP header length" << std::endl;
        return;
    }

    int payload_offset = tcp_header_size;
    int payload_len = l4_len - payload_offset;

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    ss << "    L4 - TCP: " << src_ip_str << ":" << src_port << " -> " 
       << dst_ip_str << ":" << dst_port << std::endl;

    ConnectionTuple tuple;
    tuple.ip_src = src_ip_str;
    tuple.ip_dst = dst_ip_str;
    tuple.sport = tcp_header->th_sport; // Use network order for map key
    tuple.dport = tcp_header->th_dport;

    uint32_t seq_num = ntohl(tcp_header->th_seq);
    ss << "        Seq: " << seq_num;

    // Call reassembly logic if there is data
    if (payload_len > 0) {
        ss << "  Payload Len: " << payload_len;
        handle_tcp_reassembly(l4_payload + payload_offset, payload_len, seq_num, tuple);
    }

    // Print flags
    ss << "  Flags: ";
    if (tcp_header->th_flags & TH_SYN) ss << "SYN ";
    if (tcp_header->th_flags & TH_ACK) ss << "ACK ";
    if (tcp_header->th_flags & TH_FIN) ss << "FIN ";
    if (tcp_header->th_flags & TH_RST) ss << "RST ";
    if (tcp_header->th_flags & TH_PUSH) ss << "PSH ";
    ss << std::endl;

    // If FIN or RST, connection is closing. Reassemble!
    if (tcp_header->th_flags & (TH_FIN | TH_RST)) {
        handle_stream_close(tuple, ss);
    }
}

/**
 * @brief L4 Parser for UDP packets.
 */
static void handle_udp_packet(const u_char *l4_payload, int l4_len, std::string src_ip_str, std::string dst_ip_str, std::stringstream& ss) {
    if (l4_len < sizeof(udphdr)) return;
    
    const struct udphdr *udp_header = (const struct udphdr *)(l4_payload);
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    
    ss << "    L4 - UDP: " << src_ip_str << ":" << src_port << " -> " 
       << dst_ip_str << ":" << dst_port << std::endl;

    // L7 DNS Hook
    if (src_port == 53 || dst_port == 53) {
        int payload_offset = sizeof(udphdr);
        int payload_len = l4_len - payload_offset;
        parse_dns(l4_payload + payload_offset, payload_len, ss);
    }
}

/**
 * @brief L3 Parser for ARP packets.
 */
static void handle_arp_packet(const u_char *l3_payload, int l3_len, std::stringstream& ss) {
    if (l3_len < sizeof(my_arphdr)) return;
    const struct my_arphdr *arp_header = (const struct my_arphdr *)l3_payload;

    uint16_t op = ntohs(arp_header->oper);
    ss << "    L3 - ARP Operation: " << (op == 1 ? "Request" : (op == 2 ? "Reply" : "Unknown")) << std::endl;

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->tpa, tpa_str, INET_ADDRSTRLEN);
    
    if (op == 1) { // Request
        ss << "        Who has " << tpa_str << "? Tell ";
        print_mac_address(arp_header->sha, ss);
        ss << " (" << spa_str << ")" << std::endl;
    } else if (op == 2) { // Reply
        ss << "        " << spa_str << " is at ";
        print_mac_address(arp_header->sha, ss);
        ss << std::endl;
    }
}

/**
 * @brief L3 Parser for IPv4 packets.
 */
static void handle_ipv4_packet(const u_char *l3_payload, int l3_len, std::stringstream& ss) {
    ss << "L3 - Protocol: IPv4" << std::endl;
    if (l3_len < sizeof(ip)) return;
    const struct ip *ip_header = (const struct ip *)(l3_payload);

    // Convert IPs to string
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    
    ss << "    L3 - From IP: " << src_ip_str << " -> To IP: " << dst_ip_str << std::endl;

    uint ip_header_size = ip_header->ip_hl * 4;
    if (ip_header_size < 20) { ss << "    L3 - Invalid IP header length" << std::endl; return; }

    int l4_offset = ip_header_size;
    int l4_len = l3_len - l4_offset;
    const u_char *l4_payload = l3_payload + l4_offset;
    
    // De-multiplex to L4
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            handle_tcp_packet(l4_payload, l4_len, src_ip_str, dst_ip_str, ss);
            break;
        case IPPROTO_UDP:
            handle_udp_packet(l4_payload, l4_len, src_ip_str, dst_ip_str, ss);
            break;
        case IPPROTO_ICMP:
            ss << "    L4 - Protocol: ICMP" << std::endl;
            break;
        default:
            ss << "    L4 - Protocol: Unknown (" << (int)ip_header->ip_p << ")" << std::endl;
            break;
    }
}

/**
 * @brief L3 Parser for IPv6 packets.
 * Includes logic for walking the Extension Header chain.
 */
static void handle_ipv6_packet(const u_char *l3_payload, int l3_len, std::stringstream& ss) {
    ss << "L3 - Protocol: IPv6" << std::endl;
    if (l3_len < sizeof(ip6_hdr)) return;
    const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)(l3_payload);

    // Convert IPs to string
    char src_ip6[INET6_ADDRSTRLEN];
    char dst_ip6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);

    ss << "    L3 - From IP: " << src_ip6 << " -> To IP: " << dst_ip6 << std::endl;

    // Walk the Extension Header chain
    int next_header_type = ip6_header->ip6_nxt;
    int l4_offset = sizeof(struct ip6_hdr); // 40 bytes

    while (next_header_type == IPPROTO_HOPOPTS || next_header_type == IPPROTO_ROUTING ||
           next_header_type == IPPROTO_FRAGMENT || next_header_type == IPPROTO_DSTOPTS ||
           next_header_type == IPPROTO_AH || next_header_type == IPPROTO_ESP) {
        
        ss << "    L3 - IPv6 Extension Header: " << next_header_type << std::endl;
        if (l3_len < l4_offset + 2) break; // Not enough space for another header

        next_header_type = (int)l3_payload[l4_offset];
        int header_len = (int)l3_payload[l4_offset + 1];
        // Length is in 8-byte units, *not including* the first 8 bytes.
        l4_offset += (header_len * 8) + 8;
        
        if (l4_offset > l3_len) break; // Malformed packet
    }
    
    int l4_len = l3_len - l4_offset;
    const u_char *l4_payload = l3_payload + l4_offset;

    // De-multiplex to L4
    switch (next_header_type) {
        case IPPROTO_TCP:
            handle_tcp_packet(l4_payload, l4_len, src_ip6, dst_ip6, ss);
            break;
        case IPPROTO_UDP:
            handle_udp_packet(l4_payload, l4_len, src_ip6, dst_ip6, ss);
            break;
        case IPPROTO_ICMPV6:
            ss << "    L4 - Protocol: ICMPv6" << std::endl;
            break;
        default:
            ss << "    L4 - Protocol: Unknown (" << next_header_type << ")" << std::endl;
            break;
    }
}

/**
 * @brief This is the main processing function.
 * It's called by a consumer thread. It de-encapsulates
 * the packet layer by layer and writes all output to
 * the provided stringstream.
 *
 * @param header The pcap metadata for the packet.
 * @param packet A pointer to the raw packet data.
 * @param ss The stringstream to write all output to.
 */
static void process_packet(const struct pcap_pkthdr *header, const u_char *packet, std::stringstream& ss) {
    
    // (FIX 2) REMOVED the '\n' from here
    ss << " --- Packet #" << packet_count++ << " (" << header->caplen << " bytes) ---" << std::endl;

    // --- L2 (Ethernet) ---
    const struct ether_header *eth_header = (const struct ether_header *)packet;
    ss << "L2 - Dst MAC: "; print_mac_address(eth_header->ether_dhost, ss);
    ss << "  Src MAC: "; print_mac_address(eth_header->ether_shost, ss);
    ss << std::endl;

    uint16_t ether_type = ntohs(eth_header->ether_type);
    int l3_offset = sizeof(struct ether_header);

    // --- VLAN (802.1Q) ---
    if (ether_type == ETHERTYPE_VLAN) {
        ss << "L2 - VLAN Tag detected" << std::endl;
        // The *real* EtherType is 4 bytes deeper
        ether_type = ntohs(*(uint16_t *)(packet + l3_offset + 2));
        l3_offset += 4;
    }
    
    int l3_len = header->caplen - l3_offset;
    const u_char *l3_payload = packet + l3_offset;

    // --- L3 (IP / IPv6 / ARP) ---
    switch (ether_type) {
        case ETHERTYPE_IP:
            handle_ipv4_packet(l3_payload, l3_len, ss);
            break;
        case ETHERTYPE_IPV6:
            handle_ipv6_packet(l3_payload, l3_len, ss);
            break;
        case ETHERTYPE_ARP:
            ss << "L3 - Protocol: ARP" << std::endl;
            handle_arp_packet(l3_payload, l3_len, ss);
            break;
        default:
            // Save/restore hex formatting state
            std::ios_base::fmtflags flags = ss.flags();
            ss << "L3 - Protocol: Unknown (EtherType: 0x" << std::hex << ether_type << std::dec << ")" << std::endl;
            ss.flags(flags);
            break;
    }
}


// --- Producer/Consumer Functions (Public) ---

/**
 * @brief The PRODUCER. Called by pcap_loop.
 * This function is lightweight: it copies the packet data
 * into a std::vector (for ownership) and pushes it
 * onto the thread-safe queue.
 */
void producer_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    
    QueuedPacket qp;
    // Copy the header metadata
    qp.header = *header;
    // Copy the raw packet data
    qp.data.assign(packet, packet + header->caplen);

    // Push the packet onto the global queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        packet_queue.push(std::move(qp)); // Use move semantics
    }
    
    // Notify one waiting consumer thread
    queue_cond.notify_one();
}

/**
 * @brief The CONSUMER. The main loop for all worker threads.
 * This loop waits for a packet to appear in the queue,
 * processes it, and then writes the output to the console.
 */
void consumer_thread_loop() {
    // Get the thread ID *once* at the start
    const std::thread::id this_id = std::this_thread::get_id();

    {
        // Thread-safe print to announce startup
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "[Worker thread " << this_id << " started]" << std::endl;
    }
    
    while (true) {
        QueuedPacket packet_to_process;

        // --- Critical Section: Wait for and pop a packet ---
        {
            // unique_lock is required by condition_variable
            std::unique_lock<std::mutex> lock(queue_mutex);
            
            // Wait on the condition variable.
            // This atomically unlocks the mutex and puts the thread to sleep.
            queue_cond.wait(lock, []{
                // This predicate protects against spurious wakeups.
                // We wake up if the queue is not empty OR if we are shutting down.
                return !packet_queue.empty() || shutting_down;
            });

            // If we woke up because of the shutdown signal AND the
            // queue is empty, we are done.
            if (shutting_down && packet_queue.empty()) {
                break; // Exit the while(true) loop
            }

            // Otherwise, we have a packet to process.
            packet_to_process = std::move(packet_queue.front());
            packet_queue.pop();
        
        } // unique_lock is released here

        // --- Non-Critical Section: Process the packet ---
        // We do all the heavy parsing *outside* the queue lock,
        // so other threads are free to queue/dequeue.

        // Simulate a complex, 1-millisecond processing time for *every* packet.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        std::stringstream ss; // Create a local stringstream for this thread
        
        // (FIX 1) Add the newline and thread ID *before*
        // calling the processing function.
        ss << "\n[Thread: " << this_id << "]";
        
        process_packet(&packet_to_process.header, packet_to_process.data.data(), ss);

        // --- Critical Section: Print to Console ---
        // Now, lock the print mutex for the *minimum* time
        // to dump the fully-formed string to cout.
        std::string output = ss.str();
        if (!output.empty()) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << output;
        }
    }
    
    {
        // Thread-safe print to announce shutdown
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "[Worker thread " << this_id << " shutting down]" << std::endl;
    }
}