/*
 * ui.cpp
 *
 * ncurses-based terminal user interface.
 * Implements window management and all rendering functions.
 */

#include "ui.hpp"
#include "core.hpp"
#include <algorithm>
#include <chrono>

// --- TUI Window Handles ---
WINDOW *stats_win = nullptr;
WINDOW *pcap_win = nullptr;
WINDOW *bandwidth_win = nullptr;
WINDOW *talkers_win = nullptr;
WINDOW *main_win = nullptr;
WINDOW *timeline_win = nullptr;

// --- Helper Functions ---

namespace {

/**
 * @brief Converts byte count to human-readable format (B, KB, MB, GB, etc.)
 */
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

/**
 * @brief Converts byte rate to human-readable format with "/s" suffix.
 */
std::string human_readable_rate(double bytes_per_second) {
    return human_readable_bytes(bytes_per_second) + "/s";
}

/**
 * @brief Checks if a timeval struct has been set (non-zero).
 */
bool is_time_set(const struct timeval& tv) {
    return tv.tv_sec != 0 || tv.tv_usec != 0;
}

/**
 * @brief Computes time difference in milliseconds between two timevals.
 * @return Milliseconds elapsed, or -1.0 if invalid
 */
double compute_diff_ms(const struct timeval& start, const struct timeval& end) {
    if (!is_time_set(start) || !is_time_set(end)) {
        return -1.0;
    }
    double diff = static_cast<double>(end.tv_sec - start.tv_sec) * 1000.0;
    diff += static_cast<double>(end.tv_usec - start.tv_usec) / 1000.0;
    return (diff >= 0.0) ? diff : -1.0;
}

/**
 * @brief Formats duration in milliseconds or seconds with appropriate precision.
 * @return Formatted string like "12.5ms" or "2.3s", or "--" if invalid
 */
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

} // namespace

// --- Public Functions ---

bool init_ncurses() {
    const char *term = getenv("TERM");
    if (!term) {
        std::cerr << "Error: TERM environment variable not set. " << std::endl;
        std::cerr << "Try running: export TERM=$TERM && sudo ./sniffer ..." << std::endl;
        return false;
    }
    
    if (strcmp(term, "dumb") == 0) {
        std::cerr << "Error: TERM is set to 'dumb' which doesn't support ncurses. " << std::endl;
        std::cerr << "Try running: export TERM=xterm-256color && sudo -E ./sniffer ..." << std::endl;
        std::cerr << "Or: sudo -E env TERM=$TERM ./sniffer ..." << std::endl;
        return false;
    }
    
    if (initscr() == NULL) {
        std::cerr << "Error: Failed to initialize ncurses. " << std::endl;
        std::cerr << "This may happen when running with sudo. " << std::endl;
        std::cerr << "Try: sudo -E ./sniffer ... (to preserve environment)" << std::endl;
        return false;
    }
    
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    curs_set(0);
    if (start_color() == OK) {
        init_pair(1, COLOR_GREEN, COLOR_BLACK);
        init_pair(2, COLOR_CYAN, COLOR_BLACK);
        init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    }
    
    refresh();
    return true;
}

void cleanup_ncurses() {
    endwin();
}

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

void draw_stats_window() {
    if (!stats_win) return;
    box(stats_win, 0, 0);
    mvwprintw(stats_win, 0, 2, " Protocol Stats ");
    
    std::lock_guard<std::mutex> lock(stats_mutex);
    int row = 2;
    int max_y, max_x;
    getmaxyx(stats_win, max_y, max_x);

    if (stats_map.empty()) {
        mvwprintw(stats_win, row, 2, "No packets processed yet.");
        wrefresh(stats_win);
        return;
    }
    
    for (std::map<std::string, long>::const_iterator it = stats_map.begin(); it != stats_map.end(); ++it) {
        const std::string& key = it->first;
        long val = it->second;
        if (row >= max_y - 1) break;
        mvwprintw(stats_win, row++, 2, "%-10s: %-10ld", key.c_str(), val);
    }
    wrefresh(stats_win);
}

void draw_pcap_window() {
    if (!pcap_win) return;
    box(pcap_win, 0, 0);
    mvwprintw(pcap_win, 0, 2, " Capture Stats (pcap) ");
    
    if (g_handle) {
        pcap_stats(g_handle, &g_pcap_stats);
    }
    
    unsigned long processed = packets_processed.load();
    unsigned long total_recv = g_pcap_stats.ps_recv;
    
    wattron(pcap_win, COLOR_PAIR(1));
    mvwprintw(pcap_win, 2, 2, "Recv (pcap):    %-10lu", total_recv);
    mvwprintw(pcap_win, 3, 2, "Processed:      %-10lu", processed);
    wattroff(pcap_win, COLOR_PAIR(1));
    
    long diff = (long)total_recv - (long)processed;
    if (diff != 0) {
        wattron(pcap_win, COLOR_PAIR(2));
        mvwprintw(pcap_win, 4, 2, "In Queue/Proc:  %-10ld", diff);
        wattroff(pcap_win, COLOR_PAIR(2));
    }
    
    wattron(pcap_win, COLOR_PAIR(3));
    mvwprintw(pcap_win, 5, 2, "Dropped:        %-10u", g_pcap_stats.ps_drop);
    wattroff(pcap_win, COLOR_PAIR(3));
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        size_t queue_size = packet_queue.size();
        mvwprintw(pcap_win, 6, 2, "Queue Size:     %-10zu", queue_size);
    }

    unsigned long long bytes = total_bytes.load();
    std::string total_bytes_str = human_readable_bytes(static_cast<double>(bytes));
    mvwprintw(pcap_win, 7, 2, "Total Bytes:    %-10s", total_bytes_str.c_str());
    
    wrefresh(pcap_win);
}

void draw_bandwidth_window() {
    if (!bandwidth_win) return;
    box(bandwidth_win, 0, 0);
    mvwprintw(bandwidth_win, 0, 2, " Live Bandwidth ");

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

    const double alpha = 0.4;
    if (smoothed_rate == 0.0) {
        smoothed_rate = instantaneous_rate;
    } else {
        smoothed_rate = (alpha * instantaneous_rate) + ((1.0 - alpha) * smoothed_rate);
    }

    last_total_bytes = current_total;
    last_timestamp = now;

    std::string rate_str = human_readable_rate(smoothed_rate);
    std::string inst_rate_str = human_readable_rate(instantaneous_rate);
    std::string total_str = human_readable_bytes(static_cast<double>(current_total));

    mvwprintw(bandwidth_win, 2, 2, "Current:  %s", rate_str.c_str());
    mvwprintw(bandwidth_win, 3, 2, "Instant:  %s", inst_rate_str.c_str());
    mvwprintw(bandwidth_win, 4, 2, "Total:    %s", total_str.c_str());

    long sessions = tcp_session_count.load();
    mvwprintw(bandwidth_win, 6, 2, "Active TCP Sessions: %ld", sessions);

    wrefresh(bandwidth_win);
}

void draw_top_talkers_window() {
    if (!talkers_win) return;
    box(talkers_win, 0, 0);
    mvwprintw(talkers_win, 0, 2, " Top Talkers ");

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
        mvwprintw(talkers_win, row++, 2, "%-4s %-20s %s", "Rank", "IP", "Total Bytes");
        int rank = 1;
        for (std::vector<std::pair<std::string, long> >::const_iterator it = talkers.begin();
             it != talkers.end() && row < max_y - 1; ++it, ++rank, ++row) {
            std::string bytes_str = human_readable_bytes(static_cast<double>(it->second));
            mvwprintw(talkers_win, row, 2, "%-4d %-20s %s", rank, it->first.c_str(), bytes_str.c_str());
        }
    }

    wrefresh(talkers_win);
}

void draw_timeline_window() {
    if (!timeline_win) return;
    box(timeline_win, 0, 0);
    mvwprintw(timeline_win, 0, 2, " Conversation Timeline ");

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
        std::vector<char> header(max_x + 1, 0);
        snprintf(header.data(), max_x,
                 "%-*s %-*s %-*s %-*s %-*s %-*s %-*s",
                 flow_width, "Flow",
                 handshake_width, "Hndshk",
                 response_width, "Resp",
                 duration_width, "Dur",
                 up_width, "Up Bytes",
                 down_width, "Down Bytes",
                 state_width, "State");
        mvwprintw(timeline_win, row++, 2, "%s", header.data());
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
        if (entry.closed) {
            state = "Closed";
        } else if (entry.first_payload_s2c_seen || entry.first_payload_c2s_seen) {
            state = "Streaming";
        } else if (entry.syn_seen && entry.ack_seen) {
            state = "Established";
        } else if (entry.syn_seen) {
            state = "Syn-Sent";
        } else {
            state = "Observed";
        }

        std::vector<char> line(max_x + 1, 0);
        snprintf(line.data(), max_x,
                 "%-*.*s %-*s %-*s %-*s %-*s %-*s %-*s",
                 flow_width, flow_width, entry.flow_label.c_str(),
                 handshake_width, handshake_str.c_str(),
                 response_width, response_str.c_str(),
                 duration_width, duration_str.c_str(),
                 up_width, up_str.c_str(),
                 down_width, down_str.c_str(),
                 state_width, state.c_str());

        mvwprintw(timeline_win, row++, 2, "%s", line.data());
    }

    wrefresh(timeline_win);
}

void draw_main_window() {
    if (!main_win) return;
    box(main_win, 0, 0);
    mvwprintw(main_win, 0, 2, " Live Packet Log (Press 'q' to quit) ");

    int max_y, max_x;
    getmaxyx(main_win, max_y, max_x);
    
    int row = 2;
    std::lock_guard<std::mutex> lock(results_mutex);
    
    if (row < max_y - 1) {
        std::vector<char> header(max_x + 1, 0);
        snprintf(header.data(), max_x, "%-6s %-6s %-6s %-5s %-20s -> %-20s %s",
                 "ID", "L3", "L4", "Size", "Source", "Destination", "Info");
        mvwprintw(main_win, row++, 2, header.data());
    }
    
    for (auto it = results_queue.rbegin(); it != results_queue.rend(); ++it) {
        if (row >= max_y - 1) break;
        
        const PacketSummary& p = *it;
        
        char time_str[32];
        struct tm *tm_info = localtime(&p.timestamp.tv_sec);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
        snprintf(time_str + 8, sizeof(time_str) - 8, ".%03d", (int)(p.timestamp.tv_usec / 1000));
        
        std::string ttl_str = (p.ttl > 0) ? ("TTL:" + std::to_string(p.ttl)) : "";
        
        std::vector<char> line(max_x + 1, 0);
        if (max_x > 120) {
            snprintf(line.data(), max_x, "%-6d %-6s %-6s %-5u %-9s %-20s -> %-20s %s %s",
                     p.id,
                     p.l3_protocol.c_str(),
                     p.l4_protocol.c_str(),
                     p.len,
                     time_str,
                     (p.src_ip + ":" + p.src_port).c_str(),
                     (p.dst_ip + ":" + p.dst_port).c_str(),
                     ttl_str.c_str(),
                     p.info.c_str()
                     );
        } else {
            snprintf(line.data(), max_x, "%-6d %-6s %-6s %-5u %-20s -> %-20s %s",
                     p.id,
                     p.l3_protocol.c_str(),
                     p.l4_protocol.c_str(),
                     p.len,
                     (p.src_ip + ":" + p.src_port).c_str(),
                     (p.dst_ip + ":" + p.dst_port).c_str(),
                     p.info.c_str()
                     );
        }
        
        line.data()[max_x - 2] = 0;
        mvwprintw(main_win, row++, 2, line.data());
    }
    wrefresh(main_win);
}

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
        if (ch == 'q') {
            shutting_down = true;
            if (g_handle) pcap_breakloop(g_handle);
            queue_cond.notify_all();
            break;
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

