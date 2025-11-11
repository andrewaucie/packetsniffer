/*
 * reassembly.h
 *
 * Declares the classes, structs, and functions
 * used for stateful TCP stream reassembly.
 *
 * This system is thread-safe and protocol-agnostic (IPv4/IPv6).
 */

#ifndef REASSEMBLY_H
#define REASSEMBLY_H

#include "sniffer.h" // Includes all our types and headers

/**
 * @struct ConnectionTuple
 * @brief Uniquely identifies ANY TCP connection (IPv4 or IPv6).
 * We use std::string to store IPs to be protocol-agnostic.
 * Ports are stored in network-byte-order for mapping.
 */
struct ConnectionTuple {
    std::string ip_src;
    std::string ip_dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol = IPPROTO_TCP;

    /**
     * @brief Comparison operator to allow this struct
     * to be used as a key in std::map.
     */
    bool operator<(const ConnectionTuple& other) const;
};

/**
 * @class ConnectionData
 * @brief Stores reassembly data for a *single direction* of a TCP stream.
 */
class ConnectionData {
public:
    /**
     * @brief A map of [sequence_number] -> [payload_data].
     * Using std::map automatically handles out-of-order packets
     * and de-duplicates packets with the same sequence number.
     */
    std::map<uint32_t, std::vector<u_char>> data_buffer;
};

// --- Global Session Manager ---

// This map holds all active, tracked TCP sessions.
extern std::map<ConnectionTuple, ConnectionData> tcp_sessions;

// A dedicated mutex to protect the tcp_sessions map from concurrent access.
extern std::mutex session_mutex;


// --- Function Declarations ---

/**
 * @brief Given a TCP payload, this function locks the session map
 * and inserts the payload data into the correct buffer.
 * @param payload Pointer to the start of the L7 payload.
 * @param payload_len Length of the payload.
 * @param seq_num The packet's TCP sequence number.
 * @param tuple The connection tuple (IPs/ports) for this packet.
 */
void handle_tcp_reassembly(
    const u_char *payload,
    int payload_len,
    uint32_t seq_num,
    ConnectionTuple tuple
);

/**
 * @brief Dumps the reassembled ASCII data for a finished stream
 * into the provided stringstream.
 * @param session The ConnectionData object to print.
 * @param ss The stringstream to write output to.
 */
void print_reassembled_stream(ConnectionData& session, std::stringstream& ss);

/**
 * @brief Called on a FIN or RST. This function locks the session map,
 * finds both directions of the closing stream, prints them
 * to the stringstream, and erases them from the map.
 * @param tuple The connection tuple that triggered the close.
 * @param ss The stringstream to write output to.
 */
void handle_stream_close(ConnectionTuple tuple, std::stringstream& ss);


#endif // REASSEMBLY_H