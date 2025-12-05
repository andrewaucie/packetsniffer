/*
 * reassembly.cpp - TCP stream reassembly
 */

#include "reassembly.hpp"

std::map<ConnectionTuple, ConnectionData> tcp_sessions;
std::mutex session_mutex;

// Lexicographic comparison for use as map key.
bool ConnectionTuple::operator<(const ConnectionTuple& other) const {
    if (ip_src != other.ip_src) return ip_src < other.ip_src;
    if (ip_dst != other.ip_dst) return ip_dst < other.ip_dst;
    if (sport != other.sport) return sport < other.sport;
    return dport < other.dport;
}

// Store payload chunk by sequence number, track new sessions.
std::string handle_tcp_reassembly(const u_char *payload, unsigned int payload_len, uint32_t seq_num, ConnectionTuple tuple) {
    if (payload_len == 0) return "";

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

// Clean up session on FIN/RST, return summary with chunk counts.
PacketSummary handle_stream_close(ConnectionTuple tuple) {
    std::lock_guard<std::mutex> lock(session_mutex);

    ConnectionTuple tuple_reverse = tuple;
    std::swap(tuple_reverse.ip_src, tuple_reverse.ip_dst);
    std::swap(tuple_reverse.sport, tuple_reverse.dport);
    
    std::stringstream info_ss;
    info_ss << "TCP Stream Closed (";
    
    size_t chunks_a = 0, chunks_b = 0;
    bool had_connection = false;

    if (tcp_sessions.count(tuple)) {
        had_connection = true;
        chunks_a = tcp_sessions[tuple].data_buffer.size();
        tcp_sessions.erase(tuple);
    }
    
    if (tcp_sessions.count(tuple_reverse)) {
        had_connection = true;
        chunks_b = tcp_sessions[tuple_reverse].data_buffer.size();
        tcp_sessions.erase(tuple_reverse);
    }
    
    info_ss << chunks_a << " / " << chunks_b << " chunks)";

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
        }
    }

    PacketSummary summary;
    summary.l3_protocol = (tuple.ip_src.find(':') != std::string::npos) ? "IPv6" : "IPv4";
    summary.l4_protocol = "TCP";
    summary.src_ip = tuple.ip_src;
    summary.dst_ip = tuple.ip_dst;
    summary.src_port = std::to_string(ntohs(tuple.sport));
    summary.dst_port = std::to_string(ntohs(tuple.dport));
    summary.info = info_ss.str();
    summary.ttl = 0;
    summary.len = 0;
    gettimeofday(&summary.timestamp, NULL);

    return summary;
}
