/*
 * reassembly.cpp
 *
 * Defines the implementation for TCP stream reassembly.
 * This file contains all stateful logic and is fully thread-safe.
 */

#include "reassembly.h"

// --- Global Variable Definitions ---
std::map<ConnectionTuple, ConnectionData> tcp_sessions;
std::mutex session_mutex;


// --- Struct/Class Definitions ---

/**
 * @brief Defines the comparison logic for ConnectionTuple,
 * allowing it to be a key in std::map.
 */
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
void handle_tcp_reassembly(const u_char *payload, int payload_len, uint32_t seq_num, ConnectionTuple tuple) {
    if (payload_len <= 0) return;

    // Lock the session map to prevent data races
    std::lock_guard<std::mutex> lock(session_mutex);

    // This one line is the magic.
    // 1. [tuple] finds or creates the session.
    // 2. .data_buffer[seq_num] finds or creates the buffer for this sequence number.
    // 3. We assign the payload data to it.
    tcp_sessions[tuple].data_buffer[seq_num] = std::vector<u_char>(payload, payload + payload_len);
}

/**
 * @brief Iterates over the ordered map of data chunks and
 * writes the payload as ASCII to the stringstream.
 */
void print_reassembled_stream(ConnectionData& session, std::stringstream& ss) {
    if (session.data_buffer.empty()) return;

    // Use C++11 compatible loop
    for (std::map<uint32_t, std::vector<u_char>>::const_iterator it = session.data_buffer.begin();
         it != session.data_buffer.end(); ++it) {
        
        const std::vector<u_char>& data = it->second;
        for (u_char c : data) {
            // Print printable characters, or '.' for non-printable
            ss << (isprint(c) || c == '\n' || c == '\r' ? (char)c : '.');
        }
    }
    ss << std::endl;
}

/**
 * @brief Thread-safe function to find, print, and
 * clean up both sides of a closing TCP connection.
 */
void handle_stream_close(ConnectionTuple tuple, std::stringstream& ss) {
    ss << "        CONNECTION END (FIN/RST) DETECTED." << std::endl;
    
    // Lock the session map before reading/deleting
    std::lock_guard<std::mutex> lock(session_mutex);

    // Create the reverse tuple to find the other side
    ConnectionTuple tuple_reverse = tuple;
    std::swap(tuple_reverse.ip_src, tuple_reverse.ip_dst);
    std::swap(tuple_reverse.sport, tuple_reverse.dport);

    // Print and erase the A -> B stream
    if (tcp_sessions.count(tuple)) {
        ss << "\n--- REASSEMBLED STREAM (" << tuple.ip_src << ":" << ntohs(tuple.sport)
           << " -> " << tuple.ip_dst << ":" << ntohs(tuple.dport) << ") ---" << std::endl;
        print_reassembled_stream(tcp_sessions[tuple], ss);
        tcp_sessions.erase(tuple);
    }
    
    // Print and erase the B -> A stream
    if (tcp_sessions.count(tuple_reverse)) {
        ss << "\n--- REASSEMBLED STREAM (" << tuple_reverse.ip_src << ":" << ntohs(tuple_reverse.sport)
           << " -> " << tuple_reverse.ip_dst << ":" << ntohs(tuple_reverse.dport) << ") ---" << std::endl;
        print_reassembled_stream(tcp_sessions[tuple_reverse], ss);
        tcp_sessions.erase(tuple_reverse);
    }
    ss << "--- END OF CONVERSATION ---" << std::endl;
}