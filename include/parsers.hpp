/*
 * parsers.hpp
 *
 * Declares the main producer/consumer functions
 * for the multithreaded architecture.
 */

#ifndef PARSERS_HPP
#define PARSERS_HPP

#include "app.hpp" // For pcap_t

/**
 * @brief The PRODUCER callback.
 * This is the *only* function called by pcap_loop.
 * Its only job is to copy the packet and put it in the queue.
 */
void producer_callback(
    u_char *user_data,
    const struct pcap_pkthdr *header,
    const u_char *packet
);

/**
 * @brief The CONSUMER loop.
 * This is the function that all worker threads will run.
 * It waits for packets, pops them, processes them,
 * and pushes the results to the UI model.
 */
void consumer_thread_loop();

/**
 * @brief The PRODUCER thread function.
 * This function's sole job is to initialize and run
 * the pcap_loop, which will call producer_callback.
 */
void pcap_capture_thread(pcap_t *handle, int packet_count);


// (FIX) Anonymous namespace for static *declarations*
// This ensures these functions are only visible within
// the translation unit that includes this header (parsers.cpp).
namespace {
    // (FIX) Changed length types from 'int' to 'unsigned int'
    // to fix sign-compare warnings at their root.
    
    static std::string mac_to_string(const u_char *addr);
    
    static void parse_dns(const u_char *payload, unsigned int len, PacketSummary& summary);
    
    static void handle_tcp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary);
    static void handle_udp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary);
    
    static void handle_arp_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary);
    static void handle_ipv4_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary);
    static void handle_ipv6_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary);
    
    static PacketSummary process_packet(const struct pcap_pkthdr *header, const u_char *packet);
}

#endif // PARSERS_HPP