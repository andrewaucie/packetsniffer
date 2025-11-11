/*
 * reassembly.cpp
 *
 * Defines the implementation for TCP stream reassembly.
 * This file contains all stateful logic and is fully thread-safe.
 *
 * In this TUI version, functions do not print. They return
 * data to the worker threads, which then update the global model.
 */

#include "reassembly.h"

// --- Global Variable Definitions ---
// These are defined in sniffer.cpp and declared 'extern' in reassembly.h
std::map<ConnectionTuple, ConnectionData> tcp_sessions;
std::mutex session_mutex;


// --- Struct/Class Definitions ---

bool ConnectionTuple::operator<(const ConnectionTuple& other) const {
    if (ip_src != other.ip_src) return ip_src < other.ip_src;
    if (ip_dst != other.ip_dst) return ip_dst < other.ip_dst;
    if (sport != other.sport) return sport < other.sport;
    return dport < other.dport;
}


// --- Function Definitions ---

/**
 * @brief Thread-safe function to insert a packet's payload
 * into the correct session buffer.
 */
std::string handle_tcp_reassembly(const u_char *payload, unsigned int payload_len, uint32_t seq_num, ConnectionTuple tuple) {
    if (payload_len == 0) return "";

    // Lock the session map to prevent data races
    std::lock_guard<std::mutex> lock(session_mutex);

    bool is_new_direction = (tcp_sessions.find(tuple) == tcp_sessions.end());
    if (is_new_direction) {
        ConnectionTuple reverse_tuple = tuple;
        std::swap(reverse_tuple.ip_src, reverse_tuple.ip_dst);
        std::swap(reverse_tuple.sport, reverse_tuple.dport);

        if (tcp_sessions.find(reverse_tuple) == tcp_sessions.end()) {
            tcp_session_count.fetch_add(1, std::memory_order_relaxed);
        }
    }

    tcp_sessions[tuple].data_buffer[seq_num] = std::vector<u_char>(payload, payload + payload_len);

    return "Payload: " + std::to_string(payload_len) + "B";
}

/**
 * @brief (No longer used by TUI, but good to keep)
 * Iterates over the ordered map of data chunks and
 * writes the payload as ASCII to the stringstream.
 */
void get_reassembled_stream(ConnectionData& session, std::stringstream& ss) {
    if (session.data_buffer.empty()) return;

    // Use C++11 compatible loop
    for (std::map<uint32_t, std::vector<u_char>>::const_iterator it = session.data_buffer.begin();
         it != session.data_buffer.end(); ++it) {
        
        const std::vector<u_char>& data = it->second;
        for (u_char c : data) {
            ss << (isprint(c) || c == '\n' || c == '\r' ? (char)c : '.');
        }
    }
}

/**
 * @brief Thread-safe function to find, print, and
 * clean up both sides of a closing TCP connection.
 * Returns a PacketSummary for the UI.
 */
PacketSummary handle_stream_close(ConnectionTuple tuple) {
    
    // Lock the session map before reading/deleting
    std::lock_guard<std::mutex> lock(session_mutex);

    ConnectionTuple tuple_reverse = tuple;
    std::swap(tuple_reverse.ip_src, tuple_reverse.ip_dst);
    std::swap(tuple_reverse.sport, tuple_reverse.dport);
    
    std::stringstream info_ss;
    info_ss << "TCP Stream Closed (";
    
    size_t chunks_a = 0, chunks_b = 0; // Use size_t

    bool had_connection = false;

    // Clean up the A -> B stream
    if (tcp_sessions.count(tuple)) {
        had_connection = true;
        chunks_a = tcp_sessions[tuple].data_buffer.size();
        tcp_sessions.erase(tuple);
    }
    
    // Clean up the B -> A stream
    if (tcp_sessions.count(tuple_reverse)) {
        had_connection = true;
        chunks_b = tcp_sessions[tuple_reverse].data_buffer.size();
        tcp_sessions.erase(tuple_reverse);
    }
    
    info_ss << chunks_a << " / " << chunks_b << " chunks)";

    // Update global stats (lock acquired inside)
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats_map["TCP Streams"]++;
    }

    if (had_connection) {
        long expected = tcp_session_count.load(std::memory_order_relaxed);
        while (expected > 0 &&
               !tcp_session_count.compare_exchange_weak(
                   expected,
                   expected - 1,
                   std::memory_order_relaxed,
                   std::memory_order_relaxed)) {
            // Loop until successful or count observed as zero
        }
    }

    // Create a PacketSummary for the UI
    PacketSummary summary;
    summary.l3_protocol = (tuple.ip_src.find(':') != std::string::npos) ? "IPv6" : "IPv4";
    summary.l4_protocol = "TCP";
    summary.src_ip = tuple.ip_src;
    summary.dst_ip = tuple.ip_dst;
    summary.src_port = std::to_string(ntohs(tuple.sport));
    summary.dst_port = std::to_string(ntohs(tuple.dport));
    summary.info = info_ss.str();
    summary.ttl = 0; // TTL not available for stream close events
    summary.len = 0; // Length not applicable for stream close
    gettimeofday(&summary.timestamp, NULL); // Use current time for stream close

    return summary;
}