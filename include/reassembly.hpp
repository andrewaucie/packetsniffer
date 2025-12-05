/*
 * reassembly.hpp - TCP stream reassembly
 * 
 * Tracks payload chunks by sequence number to handle out-of-order delivery.
 */

#ifndef REASSEMBLY_HPP
#define REASSEMBLY_HPP

#include "core.hpp"

struct ConnectionTuple {
    std::string ip_src;
    std::string ip_dst;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol = IPPROTO_TCP;

    bool operator<(const ConnectionTuple& other) const;
};

class ConnectionData {
public:
    std::map<uint32_t, std::vector<u_char>> data_buffer;
};

extern std::map<ConnectionTuple, ConnectionData> tcp_sessions;
extern std::mutex session_mutex;

std::string handle_tcp_reassembly(
    const u_char *payload,
    unsigned int payload_len,
    uint32_t seq_num,
    ConnectionTuple tuple
);

PacketSummary handle_stream_close(ConnectionTuple tuple);

#endif
