/*
 * ui.cpp - ncurses TUI rendering
 * 
 * Redraws all windows each frame (~10fps). Layout auto-adjusts on resize.
 */

#include "ui.hpp"
#include "core.hpp"
#include <algorithm>
#include <chrono>
#include <iomanip>

WINDOW *stats_win = nullptr;
WINDOW *pcap_win = nullptr;
WINDOW *bandwidth_win = nullptr;
WINDOW *talkers_win = nullptr;
WINDOW *main_win = nullptr;
WINDOW *timeline_win = nullptr;

std::string display_filter = "";
bool filter_input_mode = false;

bool capture_paused = false;
int packet_scroll_offset = 0;

namespace {

// Case-insensitive substring match against packet fields.
bool packet_matches_filter(const PacketSummary& p, const std::string& filter) {
    if (filter.empty()) return true;
    
    std::string lower_filter = filter;
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);
    
    auto contains = [&lower_filter](const std::string& field) {
        std::string lower_field = field;
        std::transform(lower_field.begin(), lower_field.end(), lower_field.begin(), ::tolower);
        return lower_field.find(lower_filter) != std::string::npos;
    };
    
    return contains(p.src_ip) || 
           contains(p.dst_ip) || 
           contains(p.src_port) || 
           contains(p.dst_port) ||
           contains(p.l3_protocol) || 
           contains(p.l4_protocol) || 
           contains(p.info);
}

// Format bytes with appropriate unit (B, KB, MB, GB, etc).
std::string human_readable_bytes(double bytes) {
    static const char* suffixes[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    size_t suffix_index = 0;
    while (bytes >= 1024.0 && suffix_index < (sizeof(suffixes) / sizeof(suffixes[0])) - 1) {
        bytes /= 1024.0;
        ++suffix_index;
    }

    std::ostringstream oss;
    if (bytes >= 100.0 || suffix_index == 0) {
        oss << std::fixed << std::setprecision(0);
    } else if (bytes >= 10.0) {
        oss << std::fixed << std::setprecision(1);
    } else {
        oss << std::fixed << std::setprecision(2);
    }
    oss << bytes << " " << suffixes[suffix_index];
    return oss.str();
}

// Format bytes per second as human-readable rate.
std::string human_readable_rate(double bytes_per_second) {
    return human_readable_bytes(bytes_per_second) + "/s";
}

// Check if timeval is set (non-zero).
bool is_time_set(const struct timeval& tv) {
    return tv.tv_sec != 0 || tv.tv_usec != 0;
}

// Compute time difference in milliseconds. Returns -1.0 if invalid.
double compute_diff_ms(const struct timeval& start, const struct timeval& end) {
    if (!is_time_set(start) || !is_time_set(end)) {
        return -1.0;
    }
    double diff = static_cast<double>(end.tv_sec - start.tv_sec) * 1000.0;
    diff += static_cast<double>(end.tv_usec - start.tv_usec) / 1000.0;
    return (diff >= 0.0) ? diff : -1.0;
}

// Format duration as "12.5ms" or "2.3s", "--" if invalid.
std::string format_duration_string(double ms) {
    if (ms < 0.0) {
        return "--";
    }

    std::ostringstream oss;
    if (ms >= 1000.0) {
        double seconds = ms / 1000.0;
        if (seconds >= 100.0) {
            oss << std::fixed << std::setprecision(0);
        } else {
            oss << std::fixed << std::setprecision(1);
        }
        oss << seconds << "s";
        return oss.str();
    }

    if (ms >= 100.0) {
        oss << std::fixed << std::setprecision(0);
    } else if (ms >= 10.0) {
        oss << std::fixed << std::setprecision(1);
    } else {
        oss << std::fixed << std::setprecision(2);
    }
    oss << ms << "ms";
    return oss.str();
}

// Map well-known port to service name, empty if unknown.
std::string get_port_name(uint16_t port) {
    switch(port) {
        case 20: return "FTP-D";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP-S";
        case 68: return "DHCP-C";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 137: return "NetBIOS";
        case 138: return "NetBIOS";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 162: return "SNMP-T";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 465: return "SMTPS";
        case 500: return "IKE";
        case 514: return "Syslog";
        case 587: return "SMTP";
        case 636: return "LDAPS";
        case 853: return "DoT";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1080: return "SOCKS";
        case 1194: return "OpenVPN";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 1723: return "PPTP";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5060: return "SIP";
        case 5061: return "SIPS";
        case 5222: return "XMPP";
        case 5353: return "mDNS";
        case 5432: return "PgSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 6443: return "K8s";
        case 8080: return "HTTP-P";
        case 8443: return "HTTPS-A";
        case 9200: return "Elastic";
        case 27017: return "MongoDB";
        default: return "";
    }
}

// Format elapsed time as "1h 23m", "45m 12s", or "12s".
std::string format_elapsed_time(std::chrono::seconds elapsed) {
    int total_secs = static_cast<int>(elapsed.count());
    int hours = total_secs / 3600;
    int minutes = (total_secs % 3600) / 60;
    int seconds = total_secs % 60;
    
    std::ostringstream oss;
    if (hours > 0) {
        oss << hours << "h " << minutes << "m";
    } else if (minutes > 0) {
        oss << minutes << "m " << seconds << "s";
    } else {
        oss << seconds << "s";
    }
    return oss.str();
}

} // namespace

// Initialize ncurses with colors and input settings.
bool init_ncurses() {
    const char *term = getenv("TERM");
    if (!term) {
        std::cerr << "Error: TERM environment variable not set." << std::endl;
        std::cerr << "Try: export TERM=$TERM && sudo ./sniffer ..." << std::endl;
        return false;
    }
    
    if (strcmp(term, "dumb") == 0) {
        std::cerr << "Error: TERM is 'dumb' which doesn't support ncurses." << std::endl;
        std::cerr << "Try: sudo -E env TERM=$TERM ./sniffer ..." << std::endl;
        return false;
    }
    
    if (initscr() == NULL) {
        std::cerr << "Error: Failed to initialize ncurses." << std::endl;
        std::cerr << "Try: sudo -E ./sniffer ... (to preserve environment)" << std::endl;
        return false;
    }
    
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    curs_set(0);
    if (start_color() == OK) {
        use_default_colors();
        
        init_pair(1, COLOR_WHITE, -1);
        init_pair(2, COLOR_WHITE, -1);
        init_pair(3, COLOR_CYAN, -1);
        init_pair(4, COLOR_GREEN, -1);
        init_pair(5, COLOR_YELLOW, -1);
        init_pair(6, COLOR_RED, -1);
        init_pair(7, COLOR_BLUE, -1);
        init_pair(8, COLOR_MAGENTA, -1);
    }
    
    refresh();
    return true;
}

// Restore terminal state.
void cleanup_ncurses() {
    endwin();
}

// Calculate and create window layout based on terminal size.
void configure_windows(int screen_h, int screen_w) {
    if (screen_h <= 0 || screen_w <= 0) return;

    int top_h = screen_h / 3;
    if (top_h < 3) top_h = 3;
    if (top_h > screen_h - 3) top_h = std::max(1, screen_h - 3);
    int bottom_h = screen_h - top_h;
    if (bottom_h < 3) {
        bottom_h = std::max(1, screen_h / 2);
        top_h = screen_h - bottom_h;
    }
    if (top_h < 3) {
        top_h = std::max(1, screen_h - bottom_h);
    }
    if (bottom_h <= 0) {
        bottom_h = 1;
        top_h = screen_h - bottom_h;
    }
    if (top_h <= 0) {
        top_h = std::max(1, screen_h - 1);
        bottom_h = screen_h - top_h;
    }

    int stats_w = screen_w / 3;
    int pcap_w = screen_w / 3;
    int bandwidth_w_width = screen_w - stats_w - pcap_w;

    if (stats_w < 1) stats_w = 1;
    if (pcap_w < 1) pcap_w = 1;
    if (bandwidth_w_width < 1) bandwidth_w_width = 1;

    int top_total = stats_w + pcap_w + bandwidth_w_width;
    if (top_total > screen_w) {
        int overflow = top_total - screen_w;
        int reduce = std::min(bandwidth_w_width - 1, overflow);
        if (reduce > 0) {
            bandwidth_w_width -= reduce;
            overflow -= reduce;
        }
        if (overflow > 0) {
            reduce = std::min(stats_w - 1, overflow);
            if (reduce > 0) {
                stats_w -= reduce;
                overflow -= reduce;
            }
        }
        if (overflow > 0) {
            reduce = std::min(pcap_w - 1, overflow);
            if (reduce > 0) {
                pcap_w -= reduce;
                overflow -= reduce;
            }
        }
        if (overflow > 0) {
            bandwidth_w_width = std::max(1, bandwidth_w_width - overflow);
        }
    } else if (top_total < screen_w) {
        bandwidth_w_width += (screen_w - top_total);
    }

    int talkers_w = screen_w / 3;
    if (talkers_w < 30 && screen_w > 80) talkers_w = screen_w / 2;
    if (talkers_w < 20) talkers_w = std::max(20, screen_w / 2);
    if (talkers_w > screen_w - 30) talkers_w = screen_w - 30;
    if (talkers_w < 1) talkers_w = 1;

    int right_width = screen_w - talkers_w;
    if (right_width < 40 && screen_w > 60) {
        right_width = 40;
        talkers_w = screen_w - right_width;
    }
    if (right_width < 1) {
        right_width = std::max(1, screen_w / 2);
        talkers_w = screen_w - right_width;
    }

    int timeline_h = bottom_h / 3;
    if (timeline_h < 3 && bottom_h >= 6) timeline_h = 3;
    if (timeline_h < 1) timeline_h = 1;
    int main_height = bottom_h - timeline_h;
    if (main_height < 3 && bottom_h >= 6) {
        main_height = 3;
        timeline_h = bottom_h - main_height;
    }
    if (main_height < 1) {
        main_height = std::max(1, bottom_h / 2);
        timeline_h = bottom_h - main_height;
    }

    if (stats_win) delwin(stats_win);
    if (pcap_win) delwin(pcap_win);
    if (bandwidth_win) delwin(bandwidth_win);
    if (talkers_win) delwin(talkers_win);
    if (timeline_win) delwin(timeline_win);
    if (main_win) delwin(main_win);

    stats_win = newwin(top_h, stats_w, 0, 0);
    pcap_win = newwin(top_h, pcap_w, 0, stats_w);
    bandwidth_win = newwin(top_h, bandwidth_w_width, 0, stats_w + pcap_w);
    talkers_win = newwin(bottom_h, talkers_w, top_h, 0);
    timeline_win = newwin(timeline_h, right_width, top_h, talkers_w);
    main_win = newwin(main_height, right_width, top_h + timeline_h, talkers_w);
}

// Render protocol statistics with packet counts and percentages.
void draw_stats_window() {
    if (!stats_win) return;
    
    box(stats_win, 0, 0);
    
    wattron(stats_win, COLOR_PAIR(3));
    mvwprintw(stats_win, 0, 2, " Protocol Stats ");
    wattroff(stats_win, COLOR_PAIR(3));
    
    std::lock_guard<std::mutex> lock(stats_mutex);
    int row = 2;
    int max_y, max_x;
    getmaxyx(stats_win, max_y, max_x);
    (void)max_x;

    if (stats_map.empty()) {
        mvwprintw(stats_win, row, 2, "No packets yet.");
        wrefresh(stats_win);
        return;
    }
    
    long total_packets = 0;
    for (std::map<std::string, long>::const_iterator it = stats_map.begin();
         it != stats_map.end(); ++it) {
        if (it->first == "IPv4" || it->first == "IPv6" || it->first == "ARP" || it->first == "Other") {
            total_packets += it->second;
        }
    }
    if (total_packets == 0) total_packets = 1;
    
    std::vector<std::pair<std::string, long> > sorted_stats(stats_map.begin(), stats_map.end());
    std::sort(sorted_stats.begin(), sorted_stats.end(),
              [](const std::pair<std::string, long>& a, const std::pair<std::string, long>& b) { 
                  return a.second > b.second; 
              });
    
    for (std::vector<std::pair<std::string, long> >::const_iterator it = sorted_stats.begin();
         it != sorted_stats.end(); ++it) {
        if (row >= max_y - 1) break;
        
        const std::string& proto = it->first;
        long count = it->second;
        double pct = 100.0 * count / total_packets;
        
        int proto_color = 1;
        if (proto == "TCP") proto_color = 7;
        else if (proto == "UDP") proto_color = 5;
        else if (proto == "ICMP" || proto == "ICMPv6" || proto == "ARP" || proto == "IPv6") proto_color = 8;
        else if (proto == "TLS") proto_color = 4;
        
        wattron(stats_win, COLOR_PAIR(proto_color));
        mvwprintw(stats_win, row, 2, "%-12s", proto.c_str());
        wattroff(stats_win, COLOR_PAIR(proto_color));
        
        wprintw(stats_win, "%7ld ", count);
        
        wattron(stats_win, COLOR_PAIR(2) | A_DIM);
        wprintw(stats_win, "(%.0f%%)", pct);
        wattroff(stats_win, COLOR_PAIR(2) | A_DIM);
        
        row++;
    }
    
    if (row < max_y - 3 && !tcp_flags_count.empty()) {
        row++;
        wattron(stats_win, COLOR_PAIR(3));
        mvwprintw(stats_win, row++, 2, "TCP Flags:");
        wattroff(stats_win, COLOR_PAIR(3));
        
        long total_flags = 0;
        for (std::map<std::string, long>::const_iterator f = tcp_flags_count.begin();
             f != tcp_flags_count.end(); ++f) {
            total_flags += f->second;
        }
        if (total_flags == 0) total_flags = 1;
        
        const char* flag_order[] = {"SYN", "ACK", "FIN", "RST", "PSH"};
        for (int i = 0; i < 5 && row < max_y - 1; ++i) {
            std::map<std::string, long>::const_iterator fit = tcp_flags_count.find(flag_order[i]);
            if (fit != tcp_flags_count.end()) {
                double pct = 100.0 * fit->second / total_flags;
                mvwprintw(stats_win, row, 4, "%-4s %7ld ", flag_order[i], fit->second);
                wattron(stats_win, COLOR_PAIR(2) | A_DIM);
                wprintw(stats_win, "(%.0f%%)", pct);
                wattroff(stats_win, COLOR_PAIR(2) | A_DIM);
                row++;
            }
        }
    }
    
    wrefresh(stats_win);
}

// Render pcap stats: workers, rate, queue depth, drops, TLS hosts.
void draw_pcap_window() {
    if (!pcap_win) return;
    
    box(pcap_win, 0, 0);
    
    wattron(pcap_win, COLOR_PAIR(3));
    mvwprintw(pcap_win, 0, 2, " Capture Stats ");
    wattroff(pcap_win, COLOR_PAIR(3));
    
    if (g_handle) {
        pcap_stats(g_handle, &g_pcap_stats);
    }
    
    static unsigned long last_processed = 0;
    static auto last_rate_time = std::chrono::steady_clock::now();
    static double packets_per_sec = 0.0;
    
    unsigned long processed = packets_processed.load();
    unsigned long total_recv = g_pcap_stats.ps_recv;
    
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_rate_time).count();
    if (elapsed >= 0.5) {
        unsigned long proc_diff = processed - last_processed;
        packets_per_sec = proc_diff / elapsed;
        last_processed = processed;
        last_rate_time = now;
    }
    
    mvwprintw(pcap_win, 2, 2, "Workers:        %d threads", g_num_worker_threads);
    
    mvwprintw(pcap_win, 3, 2, "Rate:           ");
    wattron(pcap_win, COLOR_PAIR(4));
    wprintw(pcap_win, "%.0f pkt/s", packets_per_sec);
    wattroff(pcap_win, COLOR_PAIR(4));
    
    mvwprintw(pcap_win, 4, 2, "Recv (pcap):    ");
    wprintw(pcap_win, "%-10lu", total_recv);
    
    mvwprintw(pcap_win, 5, 2, "Processed:      ");
    wprintw(pcap_win, "%-10lu", processed);
    
    size_t queue_size = 0;
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue_size = packet_queue.size();
    }
    
    mvwprintw(pcap_win, 6, 2, "In Queue:       ");
    if (queue_size > 0) {
        wattron(pcap_win, COLOR_PAIR(5));
        wprintw(pcap_win, "%-10zu", queue_size);
        wattroff(pcap_win, COLOR_PAIR(5));
    } else {
        wprintw(pcap_win, "0");
    }
    
    mvwprintw(pcap_win, 7, 2, "Dropped:        ");
    if (g_pcap_stats.ps_drop > 0) {
        wattron(pcap_win, COLOR_PAIR(6));
        wprintw(pcap_win, "%-10u", g_pcap_stats.ps_drop);
        wattroff(pcap_win, COLOR_PAIR(6));
    } else {
        wprintw(pcap_win, "0");
    }

    unsigned long long bytes = total_bytes.load();
    std::string total_bytes_str = human_readable_bytes(static_cast<double>(bytes));
    mvwprintw(pcap_win, 8, 2, "Total Bytes:    ");
    wattron(pcap_win, COLOR_PAIR(3));
    wprintw(pcap_win, "%-10s", total_bytes_str.c_str());
    wattroff(pcap_win, COLOR_PAIR(3));
    
    int max_y, max_x;
    getmaxyx(pcap_win, max_y, max_x);
    
    int row = 10;
    if (row < max_y - 1) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        if (!tls_hosts_map.empty()) {
            std::vector<const TlsHostInfo*> sorted_hosts;
            for (const auto& pair : tls_hosts_map) {
                sorted_hosts.push_back(&pair.second);
            }
            std::sort(sorted_hosts.begin(), sorted_hosts.end(),
                [](const TlsHostInfo* a, const TlsHostInfo* b) {
                    return a->last_seen > b->last_seen;
                });
            
            int available_width = max_x - 6;
            int version_col = 8;
            int conns_col = 6;
            int data_col = 8;
            int host_col = available_width - version_col - conns_col - data_col - 6;
            if (host_col < 15) host_col = 15;
            
            wattron(pcap_win, A_DIM);
            std::ostringstream header;
            header << std::left << std::setw(host_col) << "TLS Host" << " "
                   << std::setw(version_col) << "Version" << " "
                   << std::right << std::setw(conns_col) << "Conns" << " "
                   << std::setw(data_col) << "Data";
            std::string header_str = header.str();
            if ((int)header_str.length() > max_x - 4) {
                header_str = header_str.substr(0, max_x - 4);
            }
            mvwprintw(pcap_win, row++, 3, "%s", header_str.c_str());
            
            std::string separator(std::min(available_width, (int)header_str.length()), '-');
            mvwprintw(pcap_win, row++, 3, "%s", separator.c_str());
            wattroff(pcap_win, A_DIM);
            
            int hosts_shown = 0;
            for (const auto* info : sorted_hosts) {
                if (row >= max_y - 1 || hosts_shown >= 8) break;
                
                std::string bytes_str = human_readable_bytes(static_cast<double>(info->bytes_transferred));
                
                std::string hostname = info->hostname;
                if ((int)hostname.length() > host_col - 1) {
                    hostname = hostname.substr(0, host_col - 4) + "...";
                }
                
                std::ostringstream row_oss;
                row_oss << std::left << std::setw(host_col) << hostname << " "
                        << std::setw(version_col) << info->tls_version << " "
                        << std::right << std::setw(conns_col) << info->connection_count << " "
                        << std::setw(data_col) << bytes_str;
                
                std::string row_str = row_oss.str();
                if ((int)row_str.length() > max_x - 4) {
                    row_str = row_str.substr(0, max_x - 4);
                }
                
                mvwprintw(pcap_win, row, 3, "%s", row_str.c_str());
                row++;
                hosts_shown++;
            }
        }
    }
    
    wrefresh(pcap_win);
}

// Render bandwidth stats: current/peak/avg rate, DNS, top ports.
void draw_bandwidth_window() {
    if (!bandwidth_win) return;
    
    box(bandwidth_win, 0, 0);
    
    wattron(bandwidth_win, COLOR_PAIR(3));
    mvwprintw(bandwidth_win, 0, 2, " Live Bandwidth ");
    wattroff(bandwidth_win, COLOR_PAIR(3));

    static unsigned long long last_total_bytes = 0;
    static auto last_timestamp = std::chrono::steady_clock::now();
    static bool initialized = false;
    static double smoothed_rate = 0.0;

    auto now = std::chrono::steady_clock::now();
    unsigned long long current_total = total_bytes.load();

    if (!initialized) {
        last_total_bytes = current_total;
        last_timestamp = now;
        initialized = true;
    }

    double elapsed = std::chrono::duration<double>(now - last_timestamp).count();
    double instantaneous_rate = 0.0;
    if (elapsed > 0.0) {
        unsigned long long byte_diff = (current_total >= last_total_bytes)
            ? (current_total - last_total_bytes)
            : current_total;
        instantaneous_rate = static_cast<double>(byte_diff) / elapsed;
    }

    // Exponential moving average for smoother display
    const double alpha = 0.4;
    if (smoothed_rate == 0.0) {
        smoothed_rate = instantaneous_rate;
    } else {
        smoothed_rate = (alpha * instantaneous_rate) + ((1.0 - alpha) * smoothed_rate);
    }

    unsigned long long peak = peak_bytes_per_sec.load();
    unsigned long long current_rate_ull = static_cast<unsigned long long>(smoothed_rate);
    if (current_rate_ull > peak) {
        peak_bytes_per_sec.store(current_rate_ull);
        peak = current_rate_ull;
    }

    last_total_bytes = current_total;
    last_timestamp = now;

    int max_y, max_x;
    getmaxyx(bandwidth_win, max_y, max_x);
    (void)max_x;
    int row = 2;

    auto capture_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - capture_start_time);
    std::string elapsed_str = format_elapsed_time(capture_elapsed);
    
    double avg_rate = 0.0;
    if (capture_elapsed.count() > 0) {
        avg_rate = static_cast<double>(current_total) / capture_elapsed.count();
    }

    std::string rate_str = human_readable_rate(smoothed_rate);
    std::string peak_str = human_readable_rate(static_cast<double>(peak));
    std::string avg_str = human_readable_rate(avg_rate);
    std::string total_str = human_readable_bytes(static_cast<double>(current_total));

    mvwprintw(bandwidth_win, row, 2, "Current:   ");
    wattron(bandwidth_win, COLOR_PAIR(4) | A_BOLD);
    wprintw(bandwidth_win, "%s", rate_str.c_str());
    wattroff(bandwidth_win, COLOR_PAIR(4) | A_BOLD);
    row++;

    mvwprintw(bandwidth_win, row, 2, "Peak:      ");
    wattron(bandwidth_win, COLOR_PAIR(6));
    wprintw(bandwidth_win, "%s", peak_str.c_str());
    wattroff(bandwidth_win, COLOR_PAIR(6));
    row++;

    mvwprintw(bandwidth_win, row, 2, "Average:   ");
    wattron(bandwidth_win, COLOR_PAIR(3));
    wprintw(bandwidth_win, "%s", avg_str.c_str());
    wattroff(bandwidth_win, COLOR_PAIR(3));
    row++;

    mvwprintw(bandwidth_win, row, 2, "Total:     ");
    wprintw(bandwidth_win, "%s", total_str.c_str());
    row++;
    
    mvwprintw(bandwidth_win, row, 2, "Duration:  ");
    wattron(bandwidth_win, COLOR_PAIR(2) | A_DIM);
    wprintw(bandwidth_win, "%s", elapsed_str.c_str());
    wattroff(bandwidth_win, COLOR_PAIR(2) | A_DIM);
    row++;

    row++;

    if (row < max_y - 1) {
        long sessions = tcp_session_count.load();
        size_t unique_ips = 0;
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            unique_ips = ip_stats_map.size();
        }
        
        mvwprintw(bandwidth_win, row, 2, "TCP Sess:  ");
        wattron(bandwidth_win, COLOR_PAIR(4));
        wprintw(bandwidth_win, "%ld", sessions);
        wattroff(bandwidth_win, COLOR_PAIR(4));
        row++;
        
        mvwprintw(bandwidth_win, row, 2, "Unique IP: ");
        wattron(bandwidth_win, COLOR_PAIR(3));
        wprintw(bandwidth_win, "%zu", unique_ips);
        wattroff(bandwidth_win, COLOR_PAIR(3));
        row++;
    }

    long queries = dns_queries.load();
    long responses = dns_responses.load();
    if ((queries > 0 || responses > 0) && row < max_y - 2) {
        mvwprintw(bandwidth_win, row, 2, "DNS Query: ");
        wattron(bandwidth_win, COLOR_PAIR(5));
        wprintw(bandwidth_win, "%ld", queries);
        wattroff(bandwidth_win, COLOR_PAIR(5));
        row++;
        
        mvwprintw(bandwidth_win, row, 2, "DNS Reply: ");
        wattron(bandwidth_win, COLOR_PAIR(5));
        wprintw(bandwidth_win, "%ld", responses);
        wattroff(bandwidth_win, COLOR_PAIR(5));
        row++;
    }

    row++;
    if (row < max_y - 2) {
        wattron(bandwidth_win, A_DIM);
        mvwprintw(bandwidth_win, row++, 3, "Port   Service    Packets");
        mvwprintw(bandwidth_win, row++, 3, "-----  -------  ---------");
        wattroff(bandwidth_win, A_DIM);
        
        std::vector<std::pair<uint16_t, long> > sorted_ports;
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            for (std::map<uint16_t, long>::const_iterator it = port_stats_map.begin();
                 it != port_stats_map.end(); ++it) {
                if (!get_port_name(it->first).empty()) {
                    sorted_ports.push_back(*it);
                }
            }
        }
        std::sort(sorted_ports.begin(), sorted_ports.end(),
                  [](const std::pair<uint16_t, long>& a, const std::pair<uint16_t, long>& b) { 
                      return a.second > b.second; 
                  });
        
        int ports_shown = 0;
        for (std::vector<std::pair<uint16_t, long> >::const_iterator p = sorted_ports.begin();
             p != sorted_ports.end(); ++p) {
            if (ports_shown >= 5 || row >= max_y - 1) break;
            
            std::string port_name = get_port_name(p->first);
            
            mvwprintw(bandwidth_win, row, 3, "%5d", p->first);
            
            wattron(bandwidth_win, COLOR_PAIR(2));
            wprintw(bandwidth_win, "  %-7s", port_name.c_str());
            wattroff(bandwidth_win, COLOR_PAIR(2));
            
            wprintw(bandwidth_win, "  %7ld", p->second);
            row++;
            ports_shown++;
        }
        
        if (ports_shown == 0) {
            wattron(bandwidth_win, A_DIM);
            mvwprintw(bandwidth_win, row++, 3, "(no service ports yet)");
            wattroff(bandwidth_win, A_DIM);
        }
    }

    wrefresh(bandwidth_win);
}

// Render top talkers table: IPs sorted by bytes with bar chart.
void draw_top_talkers_window() {
    if (!talkers_win) return;
    
    box(talkers_win, 0, 0);
    
    wattron(talkers_win, COLOR_PAIR(3));
    mvwprintw(talkers_win, 0, 2, " Top Talkers ");
    wattroff(talkers_win, COLOR_PAIR(3));

    std::vector<std::pair<std::string, long> > talkers;
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        talkers.reserve(ip_stats_map.size());
        for (std::map<std::string, long>::const_iterator it = ip_stats_map.begin();
             it != ip_stats_map.end(); ++it) {
            talkers.push_back(*it);
        }
    }

    std::sort(talkers.begin(), talkers.end(),
              [](const std::pair<std::string, long>& a, const std::pair<std::string, long>& b) {
                  return a.second > b.second;
              });

    int max_y, max_x;
    getmaxyx(talkers_win, max_y, max_x);
    int row = 2;

    if (talkers.empty()) {
        mvwprintw(talkers_win, row, 2, "No IP traffic observed yet.");
    } else {
        long max_bytes = talkers.empty() ? 1 : talkers[0].second;
        if (max_bytes == 0) max_bytes = 1;
        
        const int rank_width = 3;
        const int ip_width = 28;
        const int bytes_width = 10;
        
        int bar_start = 2 + rank_width + 1 + ip_width + 2 + 1 + bytes_width + 2 + 1;
        int bar_width = max_x - bar_start - 2;
        if (bar_width < 5) bar_width = 0;
        
        wattron(talkers_win, COLOR_PAIR(3));
        mvwprintw(talkers_win, row, 2, "%*s", rank_width, "#");
        waddch(talkers_win, ACS_VLINE);
        wprintw(talkers_win, " %-*s ", ip_width, "IP Address");
        waddch(talkers_win, ACS_VLINE);
        wprintw(talkers_win, " %*s ", bytes_width, "Bytes");
        if (bar_width > 0) {
            waddch(talkers_win, ACS_VLINE);
            wprintw(talkers_win, " Usage");
        }
        wattroff(talkers_win, COLOR_PAIR(3));
        row++;
        
        int rank = 1;
        for (std::vector<std::pair<std::string, long> >::const_iterator it = talkers.begin();
             it != talkers.end() && row < max_y - 1; ++it, ++rank, ++row) {
            std::string bytes_str = human_readable_bytes(static_cast<double>(it->second));
            
            std::string ip_str = it->first;
            if ((int)ip_str.length() > ip_width) {
                ip_str = ip_str.substr(0, ip_width - 3) + "...";
            }
            
            if (rank <= 3) {
                wattron(talkers_win, COLOR_PAIR(4));
            }
            mvwprintw(talkers_win, row, 2, "%*d", rank_width, rank);
            if (rank <= 3) {
                wattroff(talkers_win, COLOR_PAIR(4));
            }
            
            waddch(talkers_win, ACS_VLINE);
            wprintw(talkers_win, " %-*s ", ip_width, ip_str.c_str());
            waddch(talkers_win, ACS_VLINE);
            wprintw(talkers_win, " %*s ", bytes_width, bytes_str.c_str());
            
            if (bar_width > 0) {
                waddch(talkers_win, ACS_VLINE);
                waddch(talkers_win, ' ');
                
                int bar_len = (int)((double)it->second / max_bytes * (bar_width - 1));
                if (bar_len < 1 && it->second > 0) bar_len = 1;
                if (bar_len > bar_width - 1) bar_len = bar_width - 1;
                
                if (rank <= 3) {
                    wattron(talkers_win, COLOR_PAIR(4));
                }
                
                for (int b = 0; b < bar_len; b++) {
                    waddch(talkers_win, ACS_BLOCK);
                }
                
                if (rank <= 3) {
                    wattroff(talkers_win, COLOR_PAIR(4));
                }
            }
        }
    }

    wrefresh(talkers_win);
}

// Render TCP conversation timeline: handshake, response time, bytes.
void draw_timeline_window() {
    if (!timeline_win) return;
    
    box(timeline_win, 0, 0);
    
    wattron(timeline_win, COLOR_PAIR(3));
    mvwprintw(timeline_win, 0, 2, " Conversation Timeline ");
    wattroff(timeline_win, COLOR_PAIR(3));

    int max_y, max_x;
    getmaxyx(timeline_win, max_y, max_x);

    int row = 2;

    std::vector<ConversationTimelineEntry> entries;
    {
        std::lock_guard<std::mutex> lock(timeline_mutex);
        entries.reserve(conversation_timeline.size());
        for (std::map<std::string, ConversationTimelineEntry>::const_iterator it = conversation_timeline.begin();
             it != conversation_timeline.end(); ++it) {
            entries.push_back(it->second);
        }
    }

    std::sort(entries.begin(), entries.end(),
              [](const ConversationTimelineEntry& a, const ConversationTimelineEntry& b) {
                  if (a.last_ts.tv_sec == b.last_ts.tv_sec) {
                      return a.last_ts.tv_usec > b.last_ts.tv_usec;
                  }
                  return a.last_ts.tv_sec > b.last_ts.tv_sec;
              });

    if (entries.empty()) {
        if (row < max_y - 1) {
            mvwprintw(timeline_win, row, 2, "No TCP conversations tracked yet.");
        }
        wrefresh(timeline_win);
        return;
    }

    const int handshake_width = 9;
    const int response_width = 9;
    const int duration_width = 9;
    const int up_width = 12;
    const int down_width = 12;
    const int state_width = 10;
    const int spacing = 6;

    int flow_width = max_x - 4 - (handshake_width + response_width + duration_width +
                                  up_width + down_width + state_width + spacing);
    if (flow_width < 12) flow_width = 12;

    if (row < max_y - 1) {
        wattron(timeline_win, COLOR_PAIR(3));
        mvwprintw(timeline_win, row, 2, "%-*s %*s %*s %*s %*s %*s %-*s",
                 flow_width, "Flow",
                 handshake_width, "Hndshk",
                 response_width, "Resp",
                 duration_width, "Dur",
                 up_width, "Up Bytes",
                 down_width, "Down Bytes",
                 state_width, "State");
        wattroff(timeline_win, COLOR_PAIR(3));
        row++;
    }

    for (std::vector<ConversationTimelineEntry>::const_iterator it = entries.begin();
         it != entries.end() && row < max_y - 1; ++it) {
        const ConversationTimelineEntry& entry = *it;

        double handshake_ms = -1.0;
        if (entry.syn_seen && entry.ack_seen) {
            handshake_ms = compute_diff_ms(entry.syn_ts, entry.ack_ts);
        } else if (entry.syn_seen && entry.synack_seen) {
            handshake_ms = compute_diff_ms(entry.syn_ts, entry.synack_ts);
        }

        double first_response_ms = -1.0;
        if (entry.first_payload_c2s_seen && entry.first_payload_s2c_seen) {
            first_response_ms = compute_diff_ms(entry.first_payload_c2s_ts, entry.first_payload_s2c_ts);
        }

        double duration_ms = -1.0;
        if (is_time_set(entry.start_ts)) {
            if (entry.closed && is_time_set(entry.close_ts)) {
                duration_ms = compute_diff_ms(entry.start_ts, entry.close_ts);
            } else {
                duration_ms = compute_diff_ms(entry.start_ts, entry.last_ts);
            }
        }

        std::string handshake_str = format_duration_string(handshake_ms);
        std::string response_str = format_duration_string(first_response_ms);
        std::string duration_str = format_duration_string(duration_ms);
        std::string up_str = human_readable_bytes(static_cast<double>(entry.bytes_c2s));
        std::string down_str = human_readable_bytes(static_cast<double>(entry.bytes_s2c));

        std::string state;
        int state_color = 0;
        
        if (entry.closed) {
            state = "Closed";
            state_color = 6;
        } else if (entry.first_payload_s2c_seen || entry.first_payload_c2s_seen) {
            state = "Streaming";
            state_color = 4;
        } else if (entry.syn_seen && entry.ack_seen) {
            state = "Established";
            state_color = 4;
        } else if (entry.syn_seen) {
            state = "Handshake";
            state_color = 3;
        } else {
            state = "Observed";
            state_color = 0;
        }

        wmove(timeline_win, row, 2);
        
        wprintw(timeline_win, "%-*.*s ", flow_width, flow_width, entry.flow_label.c_str());
        
        wprintw(timeline_win, "%*s %*s %*s %*s %*s ",
               handshake_width, handshake_str.c_str(),
               response_width, response_str.c_str(),
               duration_width, duration_str.c_str(),
               up_width, up_str.c_str(),
               down_width, down_str.c_str());
               
        if (state_color > 0) {
            wattron(timeline_win, COLOR_PAIR(state_color));
            wprintw(timeline_win, "%-*s", state_width, state.c_str());
            wattroff(timeline_win, COLOR_PAIR(state_color));
        } else {
            wprintw(timeline_win, "%-*s", state_width, state.c_str());
        }
        
        row++;
    }

    wrefresh(timeline_win);
}

// Render packet log with filter, scrolling, and scrollbar.
void draw_main_window() {
    if (!main_win) return;
    
    box(main_win, 0, 0);

    int max_y, max_x;
    getmaxyx(main_win, max_y, max_x);
    
    std::string status_text = capture_paused ? " [PAUSED] " : " [LIVE] ";
    std::string title = " Packets " + status_text;
    
    wattron(main_win, COLOR_PAIR(3));
    mvwprintw(main_win, 0, 2, "%s", title.c_str());
    wattroff(main_win, COLOR_PAIR(3));
    
    const char* help = "[SPACE]=pause [/]=filter [a]=newest [d]=oldest [q]=quit";
    if ((int)strlen(help) + 15 < max_x) {
        mvwprintw(main_win, 0, max_x - strlen(help) - 2, "%s", help);
    }
    
    int row = 1;
    
    if (filter_input_mode) {
        wattron(main_win, COLOR_PAIR(5));
        mvwprintw(main_win, row, 2, "Filter: %s_", display_filter.c_str());
        wattroff(main_win, COLOR_PAIR(5));
        row++;
    } else if (!display_filter.empty()) {
        wattron(main_win, COLOR_PAIR(3));
        mvwprintw(main_win, row, 2, "Filter: \"%s\"", display_filter.c_str());
        wattroff(main_win, COLOR_PAIR(3));
        row++;
    }
    
    std::lock_guard<std::mutex> lock(results_mutex);
    
    std::vector<const PacketSummary*> filtered_packets;
    for (auto it = results_queue.rbegin(); it != results_queue.rend(); ++it) {
        if (packet_matches_filter(*it, display_filter)) {
            filtered_packets.push_back(&(*it));
        }
    }
    
    int total_filtered = (int)filtered_packets.size();
    int visible_rows = max_y - row - 3;
    if (visible_rows < 1) visible_rows = 1;
    
    int max_scroll = std::max(0, total_filtered - visible_rows);
    if (packet_scroll_offset > max_scroll) packet_scroll_offset = max_scroll;
    if (packet_scroll_offset < 0) packet_scroll_offset = 0;
    
    if (total_filtered > 0) {
        int showing_start = packet_scroll_offset + 1;
        int showing_end = std::min(packet_scroll_offset + visible_rows, total_filtered);
        
        mvwprintw(main_win, row, max_x - 25, "(%d-%d of %d)", showing_start, showing_end, total_filtered);
    }
    row++;
    
    if (row < max_y - 1) {
        wattron(main_win, COLOR_PAIR(3));
        mvwprintw(main_win, row, 2, "%-7s", "ID");
        waddch(main_win, ACS_VLINE);
        wprintw(main_win, " %-7s", "L3");
        waddch(main_win, ACS_VLINE);
        wprintw(main_win, " %-7s", "L4");
        waddch(main_win, ACS_VLINE);
        wprintw(main_win, " %6s", "Size");
        waddch(main_win, ACS_VLINE);
        
        if (max_x > 120) {
             wprintw(main_win, " %-12s", "Time");
             waddch(main_win, ACS_VLINE);
        }
        
        wprintw(main_win, " %-22s", "Source");
        waddch(main_win, ACS_VLINE);
        wprintw(main_win, " %-22s", "Destination");
        waddch(main_win, ACS_VLINE);
        wprintw(main_win, " %s", "Info");
        
        wattroff(main_win, COLOR_PAIR(3));
        row++;
    }
    
    int packets_shown = 0;
    for (int i = packet_scroll_offset; i < total_filtered && packets_shown < visible_rows; i++) {
        const PacketSummary& p = *filtered_packets[i];
        
        char time_str[32];
        struct tm *tm_info = localtime(&p.timestamp.tv_sec);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
        snprintf(time_str + 8, sizeof(time_str) - 8, ".%03d", (int)(p.timestamp.tv_usec / 1000));
        
        std::string ttl_str = (p.ttl > 0) ? ("TTL:" + std::to_string(p.ttl) + " ") : "";
        
        wmove(main_win, row, 2);
        
        wprintw(main_win, "%-7d", p.id);
        
        waddch(main_win, ACS_VLINE);

        if (p.l3_protocol == "ARP" || p.l3_protocol == "IPv6") {
            wattron(main_win, COLOR_PAIR(8));
            wprintw(main_win, " %-7s", p.l3_protocol.c_str());
            wattroff(main_win, COLOR_PAIR(8));
        } else {
            wprintw(main_win, " %-7s", p.l3_protocol.c_str());
        }
        
        waddch(main_win, ACS_VLINE);

        if (p.l4_protocol == "TCP") {
            wattron(main_win, COLOR_PAIR(7));
            wprintw(main_win, " %-7s", p.l4_protocol.c_str());
            wattroff(main_win, COLOR_PAIR(7));
        } else if (p.l4_protocol == "UDP") {
            wattron(main_win, COLOR_PAIR(5));
            wprintw(main_win, " %-7s", p.l4_protocol.c_str());
            wattroff(main_win, COLOR_PAIR(5));
        } else if (p.l4_protocol == "ICMP") {
            wattron(main_win, COLOR_PAIR(8));
            wprintw(main_win, " %-7s", p.l4_protocol.c_str());
            wattroff(main_win, COLOR_PAIR(8));
        } else {
            wprintw(main_win, " %-7s", p.l4_protocol.c_str());
        }
        
        waddch(main_win, ACS_VLINE);

        wprintw(main_win, " %6u", p.len);
        
        waddch(main_win, ACS_VLINE);

        if (max_x > 120) {
             wprintw(main_win, " %-12s", time_str);
             waddch(main_win, ACS_VLINE);
        }
        
        std::string src = p.src_ip + ":" + p.src_port;
        if (src.length() > 22) src = src.substr(0, 22);
        wprintw(main_win, " %-22s", src.c_str());

        waddch(main_win, ACS_VLINE);
        
        std::string dst = p.dst_ip + ":" + p.dst_port;
        if (dst.length() > 22) dst = dst.substr(0, 22);
        wprintw(main_win, " %-22s", dst.c_str());
        
        waddch(main_win, ACS_VLINE);

        int current_x = getcurx(main_win);
        int remaining = max_x - current_x - 2;
        if (remaining > 0) {
            std::string info_full = " " + ttl_str + p.info;
            if ((int)info_full.length() > remaining) {
                info_full = info_full.substr(0, remaining);
            }
            wprintw(main_win, "%s", info_full.c_str());
        }
        
        row++;
        packets_shown++;
    }
    
    int scrollbar_start = 3;
    int scrollbar_height = max_y - scrollbar_start - 2;
    
    if (scrollbar_height > 2 && total_filtered > visible_rows) {
        for (int i = 0; i < scrollbar_height; i++) {
            mvwaddch(main_win, scrollbar_start + i, max_x - 2, ACS_VLINE);
        }
        
        double view_fraction = (double)visible_rows / total_filtered;
        int thumb_size = std::max(1, (int)(scrollbar_height * view_fraction));
        
        double scroll_fraction = (max_scroll > 0) ? (double)packet_scroll_offset / max_scroll : 0;
        int thumb_pos = (int)(scroll_fraction * (scrollbar_height - thumb_size));
        
        wattron(main_win, A_REVERSE | COLOR_PAIR(3));
        for (int i = 0; i < thumb_size; i++) {
            mvwaddch(main_win, scrollbar_start + thumb_pos + i, max_x - 2, ' ');
        }
        wattroff(main_win, A_REVERSE | COLOR_PAIR(3));
        
        if (packet_scroll_offset > 0) {
            wattron(main_win, COLOR_PAIR(3));
            mvwaddch(main_win, scrollbar_start - 1, max_x - 2, ACS_UARROW);
            wattroff(main_win, COLOR_PAIR(3));
        }
        if (packet_scroll_offset < max_scroll) {
            wattron(main_win, COLOR_PAIR(3));
            mvwaddch(main_win, scrollbar_start + scrollbar_height, max_x - 2, ACS_DARROW);
            wattroff(main_win, COLOR_PAIR(3));
        }
    }
    
    wrefresh(main_win);
}

// Main loop: handle input, redraw windows at ~10fps.
void ui_loop() {
    int main_h = 0, main_w = 0;

    while (!shutting_down) {
        int new_main_h, new_main_w;
        getmaxyx(stdscr, new_main_h, new_main_w);

        if (new_main_h != main_h || new_main_w != main_w || main_h == 0) {
            main_h = new_main_h;
            main_w = new_main_w;
            configure_windows(main_h, main_w);
        }

        int ch = getch();
        
        if (filter_input_mode) {
            if (ch == 27) {
                filter_input_mode = false;
                display_filter = "";
            } else if (ch == '\n' || ch == KEY_ENTER) {
                filter_input_mode = false;
            } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                if (!display_filter.empty()) {
                    display_filter.pop_back();
                }
            } else if (ch >= 32 && ch < 127) {
                if (display_filter.length() < 64) {
                    display_filter += (char)ch;
                }
            }
        } else {
            if (ch == 'q') {
                shutting_down = true;
                if (g_handle) pcap_breakloop(g_handle);
                queue_cond.notify_all();
                break;
            } else if (ch == ' ') {
                capture_paused = !capture_paused;
                if (!capture_paused) {
                    queue_cond.notify_all();
                    packet_scroll_offset = 0;
                }
            } else if (ch == '/') {
                filter_input_mode = true;
                display_filter = "";
            } else if (ch == 27) {
                display_filter = "";
                packet_scroll_offset = 0;
            } else if (ch == KEY_UP || ch == 'w') {
                if (packet_scroll_offset > 0) {
                    packet_scroll_offset--;
                }
            } else if (ch == KEY_DOWN || ch == 's') {
                packet_scroll_offset++;
                if (!capture_paused) capture_paused = true;
            } else if (ch == KEY_PPAGE) {
                packet_scroll_offset = std::max(0, packet_scroll_offset - 10);
            } else if (ch == KEY_NPAGE) {
                packet_scroll_offset += 10;
                if (!capture_paused) capture_paused = true;
            } else if (ch == 'a' || ch == KEY_HOME) {
                packet_scroll_offset = 0;
            } else if (ch == 'd' || ch == KEY_END) {
                packet_scroll_offset = 99999;
                if (!capture_paused) capture_paused = true;
            }
        }

        if (stats_win) werase(stats_win);
        if (pcap_win) werase(pcap_win);
        if (bandwidth_win) werase(bandwidth_win);
        if (talkers_win) werase(talkers_win);
        if (timeline_win) werase(timeline_win);
        if (main_win) werase(main_win);

        draw_stats_window();
        draw_pcap_window();
        draw_bandwidth_window();
        draw_top_talkers_window();
        draw_timeline_window();
        draw_main_window();

        refresh();
        usleep(100000);
    }
}
