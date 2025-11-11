/*
 * reassembly.hpp
 *
 * Declares the classes, structs, and functions
 * used for stateful TCP stream reassembly.
 *
 * This system is thread-safe and protocol-agnostic (IPv4/IPv6).
 */

#ifndef REASSEMBLY_HPP
#define REASSEMBLY_HPP

#include "app.hpp" // Includes all our types and headers

/**
 * @struct ConnectionTuple
 * @brief Uniquely identifies ANY TCP connection (IPv4 or IPv6).
 */
struct ConnectionTuple {
    std::string ip_src;
    std::string ip_dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol = IPPROTO_TCP;

    bool operator<(const ConnectionTuple& other) const;
};

/**
 * @class ConnectionData
 * @brief Stores reassembly data for a *single direction* of a TCP stream.
 */
class ConnectionData {
public:
    std::map<uint32_t, std::vector<u_char>> data_buffer;
};

// --- Global Session Manager ---
extern std::map<ConnectionTuple, ConnectionData> tcp_sessions;
extern std::mutex session_mutex;

// --- Function Declarations ---

/**
 * @brief Thread-safe function to insert a packet's payload
 * into the correct session buffer.
 * @return A string summary of the reassembly (e.g., "Payload: 128B").
 */
std::string handle_tcp_reassembly(
    const u_char *payload,
    unsigned int payload_len, // Changed to unsigned int
    uint32_t seq_num,
    ConnectionTuple tuple
);

/**
 * @brief Called on a FIN or RST. This function cleans up the
 * session and returns a PacketSummary for the UI.
 * @param tuple The connection tuple that triggered the close.
 * @return A PacketSummary struct describing the closed stream.
 */
PacketSummary handle_stream_close(ConnectionTuple tuple);


#endif // REASSEMBLY_HPP