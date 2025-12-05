/*
 * core.cpp - Packet capture and processing
 * 
 * Producer/consumer model: pcap_loop feeds packets into queue,
 * worker threads parse them and update shared state.
 */

#include "core.hpp"
#include "reassembly.hpp"
#include "ui.hpp"
#include <algorithm>

pcap_t *g_handle = NULL;
std::atomic<bool> shutting_down(false);
std::string g_pcap_error = "";

std::queue<QueuedPacket> packet_queue;
std::mutex queue_mutex;
std::condition_variable queue_cond;

std::mutex stats_mutex;
std::map<std::string, long> stats_map;
std::map<std::string, long> ip_stats_map;
std::map<uint16_t, long> port_stats_map;
std::map<std::string, long> tcp_flags_count;
std::map<std::string, TlsHostInfo> tls_hosts_map;
const size_t MAX_TLS_HOSTS = 20;
struct pcap_stat g_pcap_stats;
std::atomic<unsigned long> packets_processed(0);
std::atomic<unsigned long long> total_bytes(0);
std::atomic<unsigned long long> peak_bytes_per_sec(0);
std::atomic<long> tcp_session_count(0);
std::atomic<long> dns_queries(0);
std::atomic<long> dns_responses(0);
int g_num_worker_threads = 1;

std::chrono::steady_clock::time_point capture_start_time;

std::mutex results_mutex;
std::deque<PacketSummary> results_queue;
const size_t MAX_RESULTS = 100;

std::mutex timeline_mutex;
std::map<std::string, ConversationTimelineEntry> conversation_timeline;
const size_t MAX_TIMELINE_TRACKED = 64;

static std::atomic<int> packet_id(1);
static std::map<std::string, std::string> timeline_direction_lookup;

namespace {

// Convert 6-byte MAC address to "aa:bb:cc:dd:ee:ff" string.
std::string mac_to_string(const u_char *addr) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(addr[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}

// Build directional key: "ip:port->ip:port"
std::string make_direction_key(const std::string& src_ip, uint16_t src_port,
                                const std::string& dst_ip, uint16_t dst_port) {
    std::ostringstream oss;
    oss << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
    return oss.str();
}

// Build bidirectional flow label: "ip:port <-> ip:port"
std::string make_flow_label(const std::string& client_ip, uint16_t client_port,
                             const std::string& server_ip, uint16_t server_port) {
    std::ostringstream oss;
    oss << client_ip << ":" << client_port << " <-> "
        << server_ip << ":" << server_port;
    return oss.str();
}

// Map both A->B and B->A to same canonical key for bidirectional lookup.
void register_direction_keys_locked(ConversationTimelineEntry& entry,
                                     const std::string& canonical_key,
                                     const std::string& client_ip,
                                     uint16_t client_port,
                                     const std::string& server_ip,
                                     uint16_t server_port) {
    std::string forward = make_direction_key(client_ip, client_port, server_ip, server_port);
    std::string reverse = make_direction_key(server_ip, server_port, client_ip, client_port);

    if (entry.forward_key != forward) {
        if (!entry.forward_key.empty()) {
            timeline_direction_lookup.erase(entry.forward_key);
        }
        entry.forward_key = forward;
    }
    if (entry.reverse_key != reverse) {
        if (!entry.reverse_key.empty()) {
            timeline_direction_lookup.erase(entry.reverse_key);
        }
        entry.reverse_key = reverse;
    }

    timeline_direction_lookup[entry.forward_key] = canonical_key;
    timeline_direction_lookup[entry.reverse_key] = canonical_key;
}

// Evict oldest/closed entries when timeline exceeds MAX_TIMELINE_TRACKED.
void prune_timeline_locked() {
    while (conversation_timeline.size() > MAX_TIMELINE_TRACKED) {
        std::map<std::string, ConversationTimelineEntry>::iterator victim = conversation_timeline.end();
        for (std::map<std::string, ConversationTimelineEntry>::iterator it = conversation_timeline.begin();
             it != conversation_timeline.end(); ++it) {
            if (victim == conversation_timeline.end()) {
                victim = it;
                continue;
            }

            bool victim_closed = victim->second.closed;
            bool candidate_closed = it->second.closed;

            if (!victim_closed && candidate_closed) {
                victim = it;
                continue;
            }

            if (victim_closed == candidate_closed) {
                if (timercmp(&it->second.last_ts, &victim->second.last_ts, <)) {
                    victim = it;
                }
            }
        }

        if (victim == conversation_timeline.end()) {
            break;
        }

        if (!victim->second.forward_key.empty()) {
            timeline_direction_lookup.erase(victim->second.forward_key);
        }
        if (!victim->second.reverse_key.empty()) {
            timeline_direction_lookup.erase(victim->second.reverse_key);
        }

        conversation_timeline.erase(victim);
    }
}

// Track TCP handshake timing, payload direction, and connection state.
void update_conversation_timeline(const PacketSummary& summary,
                                   const struct tcphdr* tcp_header,
                                   unsigned int payload_len) {
    if (summary.src_ip.empty() || summary.dst_ip.empty()) {
        return;
    }

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    const bool syn_flag = (tcp_header->th_flags & TH_SYN) != 0;
    const bool ack_flag = (tcp_header->th_flags & TH_ACK) != 0;
    const bool fin_flag = (tcp_header->th_flags & TH_FIN) != 0;
    const bool rst_flag = (tcp_header->th_flags & TH_RST) != 0;

    struct timeval ts = summary.timestamp;

    std::string dir_key = make_direction_key(summary.src_ip, src_port, summary.dst_ip, dst_port);

    std::lock_guard<std::mutex> lock(timeline_mutex);

    std::string canonical_key;
    std::map<std::string, std::string>::iterator lookup = timeline_direction_lookup.find(dir_key);
    if (lookup != timeline_direction_lookup.end()) {
        canonical_key = lookup->second;
        if (conversation_timeline.find(canonical_key) == conversation_timeline.end()) {
            timeline_direction_lookup.erase(lookup);
            canonical_key.clear();
        }
    }

    bool created = false;
    if (canonical_key.empty()) {
        canonical_key = dir_key;
        ConversationTimelineEntry entry = {};
        entry.client_ip = summary.src_ip;
        entry.client_port = src_port;
        entry.server_ip = summary.dst_ip;
        entry.server_port = dst_port;
        entry.flow_label = make_flow_label(entry.client_ip, entry.client_port,
                                           entry.server_ip, entry.server_port);
        entry.start_ts = ts;
        entry.last_ts = ts;
        conversation_timeline[canonical_key] = entry;
        ConversationTimelineEntry& entry_ref = conversation_timeline[canonical_key];
        register_direction_keys_locked(entry_ref, canonical_key,
                                       entry_ref.client_ip, entry_ref.client_port,
                                       entry_ref.server_ip, entry_ref.server_port);
        created = true;
    }

    ConversationTimelineEntry& entry = conversation_timeline[canonical_key];
    entry.last_ts = ts;

    const bool syn_only = syn_flag && !ack_flag;
    const bool synack = syn_flag && ack_flag;
    const bool pure_ack = ack_flag && !syn_flag && !fin_flag && !rst_flag && payload_len == 0;

    auto update_roles = [&](const std::string& client_ip, uint16_t client_port,
                            const std::string& server_ip, uint16_t server_port) {
        if (entry.client_ip == client_ip && entry.client_port == client_port &&
            entry.server_ip == server_ip && entry.server_port == server_port) {
            return;
        }
        entry.client_ip = client_ip;
        entry.client_port = client_port;
        entry.server_ip = server_ip;
        entry.server_port = server_port;
        entry.flow_label = make_flow_label(client_ip, client_port, server_ip, server_port);
        register_direction_keys_locked(entry, canonical_key,
                                       entry.client_ip, entry.client_port,
                                       entry.server_ip, entry.server_port);
    };

    if (syn_only) {
        update_roles(summary.src_ip, src_port, summary.dst_ip, dst_port);
        if (!entry.syn_seen) {
            entry.syn_seen = true;
            entry.syn_ts = ts;
            entry.start_ts = ts;
        }
    } else if (synack) {
        update_roles(summary.dst_ip, dst_port, summary.src_ip, src_port);
        if (!entry.synack_seen) {
            entry.synack_seen = true;
            entry.synack_ts = ts;
        }
    } else if (entry.client_ip.empty()) {
        update_roles(summary.src_ip, src_port, summary.dst_ip, dst_port);
        if (entry.start_ts.tv_sec == 0 && entry.start_ts.tv_usec == 0) {
            entry.start_ts = ts;
        }
    }

    bool is_client_to_server = (summary.src_ip == entry.client_ip && src_port == entry.client_port);

    if (pure_ack && entry.syn_seen && entry.synack_seen && !entry.ack_seen && is_client_to_server) {
        entry.ack_seen = true;
        entry.ack_ts = ts;
    }

    if (payload_len > 0) {
        if (is_client_to_server) {
            entry.bytes_c2s += payload_len;
            if (!entry.first_payload_c2s_seen) {
                entry.first_payload_c2s_seen = true;
                entry.first_payload_c2s_ts = ts;
            }
        } else {
            entry.bytes_s2c += payload_len;
            if (!entry.first_payload_s2c_seen) {
                entry.first_payload_s2c_seen = true;
                entry.first_payload_s2c_ts = ts;
            }
        }
    }

    if ((fin_flag || rst_flag) && !entry.closed) {
        entry.closed = true;
        entry.close_ts = ts;
    }

    if (created) {
        prune_timeline_locked();
    }
}

// Parse DNS header and populate summary with query/response info.
void parse_dns(const u_char *payload, unsigned int len, PacketSummary& summary) {
    if (len < static_cast<unsigned int>(sizeof(simple_dnshdr))) return;
    const struct simple_dnshdr *dns_header = (const struct simple_dnshdr *)payload;
    
    uint16_t flags = ntohs(dns_header->flags);
    bool is_response = (flags & 0x8000) != 0;
    
    if (is_response) {
        dns_responses++;
    } else {
        dns_queries++;
    }
    
    std::stringstream ss;
    ss << (is_response ? "Response" : "Query")
       << " ID: 0x" << std::hex << ntohs(dns_header->id) << std::dec
       << " Q: " << ntohs(dns_header->qdcount)
       << " A: " << ntohs(dns_header->ancount);
    summary.info = ss.str();
}

struct TlsParseResult {
    std::string hostname;
    std::string version;
};

// Map TLS version bytes to human-readable string.
std::string get_tls_version_string(uint8_t major, uint8_t minor) {
    if (major == 0x03) {
        switch (minor) {
            case 0x00: return "SSL3";
            case 0x01: return "TLS1.0";
            case 0x02: return "TLS1.1";
            case 0x03: return "TLS1.2";
            case 0x04: return "TLS1.3";
        }
    }
    return "TLS?";
}

// Parse TLS ClientHello to extract SNI hostname and version.
TlsParseResult extract_tls_info(const u_char* payload, unsigned int len) {
    TlsParseResult result;
    
    if (len < 44) return result;
    if (payload[0] != 0x16) return result;  // TLS handshake record
    if (payload[1] != 0x03) return result;  // TLS version major
    
    uint16_t record_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
    if (static_cast<unsigned int>(record_len + 5) > len) return result;
    if (payload[5] != 0x01) return result;  // ClientHello
    
    uint8_t client_major = payload[9];
    uint8_t client_minor = payload[10];
    result.version = get_tls_version_string(client_major, client_minor);
    
    size_t pos = 5 + 4 + 2 + 32;
    if (pos >= len) return result;
    
    uint8_t session_id_len = payload[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > len) return result;
    
    uint16_t cipher_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2 + cipher_len;
    if (pos + 1 > len) return result;
    
    uint8_t comp_len = payload[pos];
    pos += 1 + comp_len;
    if (pos + 2 > len) return result;
    
    uint16_t ext_total_len = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2;
    
    size_t ext_end = pos + ext_total_len;
    if (ext_end > len) ext_end = len;
    
    bool found_supported_versions = false;
    
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
        uint16_t ext_len = (static_cast<uint16_t>(payload[pos + 2]) << 8) | payload[pos + 3];
        pos += 4;
        
        if (pos + ext_len > ext_end) break;
        
        // SNI extension (0x0000)
        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t sni_pos = pos + 2;
            if (sni_pos + 3 > pos + ext_len) { pos += ext_len; continue; }
            
            uint8_t name_type = payload[sni_pos++];
            if (name_type == 0) {
                uint16_t name_len = (static_cast<uint16_t>(payload[sni_pos]) << 8) | payload[sni_pos + 1];
                sni_pos += 2;
                if (sni_pos + name_len <= pos + ext_len && name_len > 0 && name_len < 256) {
                    result.hostname = std::string(reinterpret_cast<const char*>(payload + sni_pos), name_len);
                }
            }
        }
        
        // Supported versions extension (0x002b) for TLS 1.3 detection
        if (ext_type == 0x002b && ext_len >= 3 && !found_supported_versions) {
            uint8_t versions_len = payload[pos];
            if (versions_len >= 2 && pos + 1 + versions_len <= pos + ext_len) {
                uint8_t ver_major = payload[pos + 1];
                uint8_t ver_minor = payload[pos + 2];
                if (ver_major == 0x03 && ver_minor == 0x04) {
                    result.version = "TLS1.3";
                    found_supported_versions = true;
                }
            }
        }
        
        pos += ext_len;
    }
    
    return result;
}

// Parse TCP segment: extract ports, flags, TLS info, update timeline.
void handle_tcp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary) {
    if (l4_len < static_cast<unsigned int>(sizeof(tcphdr))) return;
    const struct tcphdr *tcp_header = (const struct tcphdr *)(l4_payload);
    
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    summary.src_port = std::to_string(src_port);
    summary.dst_port = std::to_string(dst_port);
    
    std::string flags = "";
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        port_stats_map[src_port]++;
        port_stats_map[dst_port]++;
        if (tcp_header->th_flags & TH_SYN) { flags += "SYN "; tcp_flags_count["SYN"]++; }
        if (tcp_header->th_flags & TH_ACK) { flags += "ACK "; tcp_flags_count["ACK"]++; }
        if (tcp_header->th_flags & TH_FIN) { flags += "FIN "; tcp_flags_count["FIN"]++; }
        if (tcp_header->th_flags & TH_RST) { flags += "RST "; tcp_flags_count["RST"]++; }
        if (tcp_header->th_flags & TH_PUSH) { flags += "PSH "; tcp_flags_count["PSH"]++; }
    }

    unsigned int tcp_header_size = tcp_header->th_off * 4;
    if (tcp_header_size < 20 || tcp_header_size > l4_len) return;
    
    unsigned int payload_offset = tcp_header_size;
    unsigned int payload_len = l4_len - payload_offset;
    const u_char *tcp_payload = l4_payload + payload_offset;

    ConnectionTuple tuple;
    tuple.ip_src = summary.src_ip;
    tuple.ip_dst = summary.dst_ip;
    tuple.sport = tcp_header->th_sport;
    tuple.dport = tcp_header->th_dport;
    uint32_t seq_num = ntohl(tcp_header->th_seq);

    update_conversation_timeline(summary, tcp_header, payload_len);

    std::string tls_sni = "";
    if (payload_len > 0 && (summary.dst_port == "443" || summary.src_port == "443")) {
        TlsParseResult tls_info = extract_tls_info(tcp_payload, payload_len);
        tls_sni = tls_info.hostname;
        
        if (!tls_sni.empty()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats_map["TLS"]++;
            
            auto it = tls_hosts_map.find(tls_sni);
            if (it != tls_hosts_map.end()) {
                it->second.connection_count++;
                it->second.bytes_transferred += payload_len;
                it->second.last_seen = std::chrono::steady_clock::now();
                if (!tls_info.version.empty()) {
                    it->second.tls_version = tls_info.version;
                }
            } else {
                if (tls_hosts_map.size() >= MAX_TLS_HOSTS) {
                    auto oldest = tls_hosts_map.begin();
                    for (auto check = tls_hosts_map.begin(); check != tls_hosts_map.end(); ++check) {
                        if (check->second.last_seen < oldest->second.last_seen) {
                            oldest = check;
                        }
                    }
                    tls_hosts_map.erase(oldest);
                }
                TlsHostInfo info;
                info.hostname = tls_sni;
                info.tls_version = tls_info.version;
                info.connection_count = 1;
                info.bytes_transferred = payload_len;
                info.last_seen = std::chrono::steady_clock::now();
                tls_hosts_map[tls_sni] = info;
            }
        }
    }

    if (payload_len > 0) {
        flags += handle_tcp_reassembly(tcp_payload, payload_len, seq_num, tuple);
    }
    
    if (!tls_sni.empty()) {
        summary.info = "[TLS] " + tls_sni + " " + flags;
    } else {
        summary.info = flags;
    }

    if (tcp_header->th_flags & (TH_FIN | TH_RST)) {
        PacketSummary stream_summary = handle_stream_close(tuple);
        stream_summary.id = packet_id++;
        
        if (!capture_paused) {
            std::lock_guard<std::mutex> lock(results_mutex);
            results_queue.push_back(std::move(stream_summary));
            if (results_queue.size() > MAX_RESULTS) {
                results_queue.pop_front();
            }
        }
    }
}

// Parse UDP datagram: extract ports, parse DNS if port 53.
void handle_udp_packet(const u_char *l4_payload, unsigned int l4_len, PacketSummary& summary) {
    if (l4_len < static_cast<unsigned int>(sizeof(udphdr))) return;
    const struct udphdr *udp_header = (const struct udphdr *)(l4_payload);
    
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    summary.src_port = std::to_string(src_port);
    summary.dst_port = std::to_string(dst_port);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        port_stats_map[src_port]++;
        port_stats_map[dst_port]++;
    }

    if (src_port == 53 || dst_port == 53) {
        unsigned int payload_offset = sizeof(udphdr);
        unsigned int payload_len = l4_len - payload_offset;
        parse_dns(l4_payload + payload_offset, payload_len, summary);
    }
}

// Parse ARP packet: extract sender/target IPs, format request/reply info.
void handle_arp_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(my_arphdr))) return;
    const struct my_arphdr *arp_header = (const struct my_arphdr *)l3_payload;

    uint16_t op = ntohs(arp_header->oper);
    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    summary.src_ip = spa_str;
    summary.dst_ip = tpa_str;
    
    if (op == 1) {
        summary.info = "Request: Who has " + std::string(tpa_str) + "? Tell " + std::string(spa_str);
    } else if (op == 2) {
        summary.info = "Reply: " + std::string(spa_str) + " is at " + mac_to_string(arp_header->sha);
    }
}

// Parse IPv4 header and dispatch to TCP/UDP/ICMP handler.
void handle_ipv4_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(ip))) return;
    const struct ip *ip_header = (const struct ip *)(l3_payload);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    summary.src_ip = src_ip_str;
    summary.dst_ip = dst_ip_str;
    summary.ttl = ip_header->ip_ttl;

    unsigned int ip_header_size = ip_header->ip_hl * 4;
    if (ip_header_size < 20) return;

    unsigned int l4_offset = ip_header_size;
    if (l4_offset > l3_len) return;
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

// Parse IPv6 header, skip extension headers, dispatch to L4 handler.
void handle_ipv6_packet(const u_char *l3_payload, unsigned int l3_len, PacketSummary& summary) {
    if (l3_len < static_cast<unsigned int>(sizeof(ip6_hdr))) return;
    const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)(l3_payload);

    char src_ip6[INET6_ADDRSTRLEN];
    char dst_ip6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);
    summary.src_ip = src_ip6;
    summary.dst_ip = dst_ip6;
    summary.ttl = ip6_header->ip6_hlim;

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

// Main packet parser: strip L2, dispatch by ethertype to L3 handler.
PacketSummary process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    PacketSummary summary;
    summary.id = packet_id++;
    summary.len = header->caplen;
    summary.timestamp = header->ts;
    summary.ttl = 0;

    const struct ether_header *eth_header = (const struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    unsigned int l3_offset = sizeof(struct ether_header);

    // Handle 802.1Q VLAN tag
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

} // namespace

// Handle SIGINT: set shutdown flag and break pcap loop.
void signal_handler(int signum) {
    if (signum == SIGINT) {
        shutting_down = true;
        if (g_handle) pcap_breakloop(g_handle);
        queue_cond.notify_all();
    }
}

// pcap callback: enqueue raw packet for worker threads.
void producer_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user_data;

    QueuedPacket qp;
    qp.header = *header;
    qp.data.assign(packet, packet + header->caplen);
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        packet_queue.push(std::move(qp));
    }
    queue_cond.notify_one();
}

// Worker thread: dequeue packets, parse, update stats.
void consumer_thread_loop() {
    while (true) {
        QueuedPacket packet_to_process;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cond.wait(lock, []{
                return (!packet_queue.empty() && !capture_paused) || shutting_down;
            });
            if (shutting_down && packet_queue.empty()) {
                break;
            }
            if (capture_paused) {
                continue;
            }
            packet_to_process = std::move(packet_queue.front());
            packet_queue.pop();
        }

        PacketSummary summary = process_packet(&packet_to_process.header, packet_to_process.data.data());
        unsigned int packet_len = packet_to_process.header.caplen;

        packets_processed++;
        total_bytes.fetch_add(packet_len, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats_map[summary.l3_protocol]++;
            if (!summary.l4_protocol.empty()) {
                stats_map[summary.l4_protocol]++;
            }
            if (!summary.src_ip.empty()) {
                ip_stats_map[summary.src_ip] += static_cast<long>(packet_len);
            }
            if (!summary.dst_ip.empty()) {
                ip_stats_map[summary.dst_ip] += static_cast<long>(packet_len);
            }
        }
        
        if (!capture_paused) {
            std::lock_guard<std::mutex> lock(results_mutex);
            results_queue.push_back(std::move(summary));
            if (results_queue.size() > MAX_RESULTS) {
                results_queue.pop_front();
            }
        }
    }
}

// Producer thread: run pcap_loop until done or error.
void pcap_capture_thread(pcap_t *handle, int packet_count) {
    int ret = pcap_loop(handle, packet_count, producer_callback, NULL);
    
    if (ret == -1) {
        g_pcap_error = pcap_geterr(handle);
        shutting_down = true;
        queue_cond.notify_all();
    }
    // ret == 0 means EOF (offline file complete) or packet_count reached
    // ret == -2 means pcap_breakloop was called (user quit)
    // In these cases, don't force shutdown - let UI stay open for browsing
}

// Print CLI usage and exit.
void print_usage(char *progname) {
    std::cerr << "Usage: " << progname << " [options]" << std::endl;
    std::cerr << "  -i <interface>   Live capture from <interface>" << std::endl;
    std::cerr << "  -r <file>        Read packets from pcap file" << std::endl;
    std::cerr << "  -c <count>       Stop after <count> packets" << std::endl;
    std::cerr << "  -f <filter>      Set BPF filter" << std::endl;
    std::cerr << "  -t <threads>     Number of worker threads" << std::endl;
    std::cerr << "  -h               Show this help" << std::endl;
    exit(1);
}
