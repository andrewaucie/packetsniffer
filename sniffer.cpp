/*
 * sniffer.cpp
 *
 * This is the main "driver" file for the TUI.
 *
 * It is responsible for:
 * 1. Initializing and running the ncurses TUI (View/Controller).
 * 2. Parsing command-line arguments.
 * 3. Launching the Producer thread (pcap_capture_thread).
 * 4. Launching the pool of Consumer worker threads.
 * 5. Handling user input ('q') and graceful shutdown.
 */

#include "sniffer.h"
#include "parsers.h"

#include <algorithm>
#include <chrono>

// --- Global Variable Definitions ---
// All global variables are defined *only* in this file.
//
pcap_t *g_handle = NULL;
std::atomic<bool> shutting_down(false);

// (FIX) This global string will store the pcap error
std::string g_pcap_error = "";

// --- Producer-Consumer Queue Components ---
std::queue<QueuedPacket> packet_queue;
std::mutex queue_mutex;
std::condition_variable queue_cond;

// --- Statistics Model ---
std::mutex stats_mutex;
std::map<std::string, long> stats_map;
std::map<std::string, long> ip_stats_map;
struct pcap_stat g_pcap_stats;
std::atomic<unsigned long> packets_processed(0); // Count of filtered/processed packets
std::atomic<unsigned long long> total_bytes(0); // Total bytes processed
std::atomic<long> tcp_session_count(0); // Active TCP sessions

// --- Results Model ---
std::mutex results_mutex;
std::deque<PacketSummary> results_queue;
const size_t MAX_RESULTS = 100;


// --- TUI UI Windows ---
WINDOW *stats_win = nullptr;
WINDOW *pcap_win = nullptr;
WINDOW *bandwidth_win = nullptr;
WINDOW *talkers_win = nullptr;
WINDOW *main_win = nullptr;

namespace {
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

std::string human_readable_rate(double bytes_per_second) {
    return human_readable_bytes(bytes_per_second) + "/s";
}
} // namespace

/**
 * @brief Destructor-like class to guarantee ncurses cleanup.
 */
struct NcursesManager {
    bool initialized;
    NcursesManager() : initialized(false) {
        // Check if TERM environment variable is set (required for ncurses)
        const char *term = getenv("TERM");
        if (!term) {
            std::cerr << "Error: TERM environment variable not set. " << std::endl;
            std::cerr << "Try running: export TERM=$TERM && sudo ./sniffer ..." << std::endl;
            return;
        }
        
        // Check if TERM is set to "dumb" which doesn't support ncurses
        if (strcmp(term, "dumb") == 0) {
            std::cerr << "Error: TERM is set to 'dumb' which doesn't support ncurses. " << std::endl;
            std::cerr << "Try running: export TERM=xterm-256color && sudo -E ./sniffer ..." << std::endl;
            std::cerr << "Or: sudo -E env TERM=$TERM ./sniffer ..." << std::endl;
            return;
        }
        
        // Initialize ncurses and check for errors
        if (initscr() == NULL) {
            std::cerr << "Error: Failed to initialize ncurses. " << std::endl;
            std::cerr << "This may happen when running with sudo. " << std::endl;
            std::cerr << "Try: sudo -E ./sniffer ... (to preserve environment)" << std::endl;
            return;
        }
        initialized = true;
        
        cbreak();
        noecho();
        nodelay(stdscr, TRUE);
        curs_set(0);
        if (start_color() == OK) {
            init_pair(1, COLOR_GREEN, COLOR_BLACK);
            init_pair(2, COLOR_CYAN, COLOR_BLACK);
            init_pair(3, COLOR_YELLOW, COLOR_BLACK);
        }
        
        // Initial refresh to clear the screen
        refresh();
    }
    ~NcursesManager() {
        if (initialized) {
            endwin(); // Restore terminal
        }
    }
    bool is_initialized() const { return initialized; }
};

/**
 * @brief Helper to (re)create the ncurses windows based on current terminal size.
 */
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

    int main_width = screen_w - talkers_w;
    if (main_width < 30 && screen_w > 50) {
        main_width = 30;
        talkers_w = screen_w - main_width;
    }
    if (main_width < 1) {
        main_width = std::max(1, screen_w / 2);
        talkers_w = screen_w - main_width;
    }

    if (stats_win) delwin(stats_win);
    if (pcap_win) delwin(pcap_win);
    if (bandwidth_win) delwin(bandwidth_win);
    if (talkers_win) delwin(talkers_win);
    if (main_win) delwin(main_win);

    stats_win = newwin(top_h, stats_w, 0, 0);
    pcap_win = newwin(top_h, pcap_w, 0, stats_w);
    bandwidth_win = newwin(top_h, bandwidth_w_width, 0, stats_w + pcap_w);
    talkers_win = newwin(bottom_h, talkers_w, top_h, 0);
    main_win = newwin(bottom_h, main_width, top_h, talkers_w);
}

/**
 * @brief Signal handler for Ctrl+C (SIGINT) and window resize (SIGWINCH).
 */
void signal_handler(int signum) {
    if (signum == SIGINT) {
        shutting_down = true;
        if (g_handle) pcap_breakloop(g_handle);
        queue_cond.notify_all();
    }
    if (signum == SIGWINCH) {
        clear();
        if (main_win) wrefresh(main_win);
        if (stats_win) wrefresh(stats_win);
        if (pcap_win) wrefresh(pcap_win);
        if (bandwidth_win) wrefresh(bandwidth_win);
        if (talkers_win) wrefresh(talkers_win);
    }
}

/**
 * @brief Prints the command-line help menu (to standard error).
 */
void print_usage(char *progname) {
    std::cerr << "Professional Sniffer Tool (TUI Edition)" << std::endl;
    std::cerr << "Usage: " << progname << " [options]" << std::endl;
    std::cerr << "  -i <interface>   Live capture from <interface> (e.g., en0)" << std::endl;
    std::cerr << "  -r <file>        Read packets from <file> (e.g., capture.pcap)" << std::endl;
    std::cerr << "  -c <count>       Stop after <count> packets (default: -1, infinite)" << std::endl;
    std::cerr << "  -f <filter>      Set BPF filter (e.g., \"tcp port 80\")" << std::endl;
    std::cerr << "  -h               Show this help menu" << std::endl;
    std::cerr << "  -t <threads>     Number of worker threads (default: auto [N-1 cores])" << std::endl;
    exit(1);
}

// --- TUI Drawing Functions ---

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
    
    // C++11 compatible loop
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
    
    // Note: When a BPF filter is active, ps_recv counts only packets that
    // matched the filter (delivered to callback), not all packets on the wire.
    // So ps_recv and processed should be similar (with small differences due to
    // packets still in queue or being processed).
    
    wattron(pcap_win, COLOR_PAIR(1));
    mvwprintw(pcap_win, 2, 2, "Recv (pcap):    %-10lu", total_recv);
    mvwprintw(pcap_win, 3, 2, "Processed:      %-10lu", processed);
    wattroff(pcap_win, COLOR_PAIR(1));
    
    // Show difference (packets in queue or being processed)
    long diff = (long)total_recv - (long)processed;
    if (diff != 0) {
        wattron(pcap_win, COLOR_PAIR(2));
        mvwprintw(pcap_win, 4, 2, "In Queue/Proc:  %-10ld", diff);
        wattroff(pcap_win, COLOR_PAIR(2));
    }
    
    wattron(pcap_win, COLOR_PAIR(3));
    mvwprintw(pcap_win, 5, 2, "Dropped:        %-10u", g_pcap_stats.ps_drop);
    wattroff(pcap_win, COLOR_PAIR(3));
    
    // Show queue size
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

    // Exponential moving average for smoother display
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

void draw_main_window() {
    if (!main_win) return;
    box(main_win, 0, 0);
    mvwprintw(main_win, 0, 2, " Live Packet Log (Press 'q' to quit) ");

    int max_y, max_x;
    getmaxyx(main_win, max_y, max_x);
    
    int row = 2;
    std::lock_guard<std::mutex> lock(results_mutex);
    
    // Print header
    if (row < max_y - 1) {
        std::vector<char> header(max_x + 1, 0);
        snprintf(header.data(), max_x, "%-6s %-6s %-6s %-5s %-20s -> %-20s %s",
                 "ID", "L3", "L4", "Size", "Source", "Destination", "Info");
        mvwprintw(main_win, row++, 2, header.data());
    }
    
    for (auto it = results_queue.rbegin(); it != results_queue.rend(); ++it) {
        if (row >= max_y - 1) break; 
        
        const PacketSummary& p = *it;
        
        // Format timestamp
        char time_str[32];
        struct tm *tm_info = localtime(&p.timestamp.tv_sec);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
        snprintf(time_str + 8, sizeof(time_str) - 8, ".%03d", (int)(p.timestamp.tv_usec / 1000));
        
        // Format TTL if available
        std::string ttl_str = (p.ttl > 0) ? ("TTL:" + std::to_string(p.ttl)) : "";
        
        std::vector<char> line(max_x + 1, 0);
        // Try to fit: ID, L3, L4, Size, Time, Src, Dst, Info
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
            // Compact format for smaller screens
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

/**
 * @brief The main UI loop. Runs in the main thread.
 */
void ui_loop() {
    int main_h = 0, main_w = 0;

    while (!shutting_down) {
        int new_main_h, new_main_w;
        getmaxyx(stdscr, new_main_h, new_main_w);

        // Only recreate windows if size changed (or first iteration)
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
        if (main_win) werase(main_win);

        draw_stats_window();
        draw_pcap_window();
        draw_bandwidth_window();
        draw_top_talkers_window();
        draw_main_window();

        refresh();
        usleep(100000); 
    }
}

/**
 * @brief Main entry point.
 */
int main(int argc, char *argv[]) {
    // --- 0. Handle Ctrl+C signal ---
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *dev_name = NULL;
    char *pcap_file = NULL;
    int packet_count = -1;
    char *filter_exp = (char *)"";
    pcap_if_t *alldevs = NULL;
    
    unsigned int num_cores = std::thread::hardware_concurrency();
    int num_threads = (num_cores > 2) ? (num_cores - 1) : 1;

    // --- 1. Argument Parsing ---
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-i") == 0) { if (i + 1 < argc) dev_name = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-r") == 0) { if (i + 1 < argc) pcap_file = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-c") == 0) { if (i + 1 < argc) packet_count = atoi(argv[++i]); else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-f") == 0) { if (i + 1 < argc) filter_exp = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-t") == 0) { if (i + 1 < argc) num_threads = atoi(argv[++i]); else { print_usage(argv[0]); return 1; } }
        else { print_usage(argv[0]); return 1; }
    }

    // --- 2. Setup pcap Capture Session (BEFORE NCURSES) ---
    if (pcap_file != NULL) {
        handle = pcap_open_offline(pcap_file, errbuf);
    } else {
        if (dev_name == NULL) {
            if (pcap_findalldevs(&alldevs, errbuf) == -1) { std::cerr << "Couldn't find devices: " << errbuf << std::endl; return 2; }
            if (alldevs == NULL) { std::cerr << "No devices found." << std::endl; return 2; }
            dev_name = alldevs->name;
        }
        handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    }
    
    if (handle == NULL) { 
        std::cerr << "pcap_open failed: " << errbuf << std::endl; 
        if (alldevs) pcap_freealldevs(alldevs); 
        return 2; 
    }
    g_handle = handle; 

    // --- 3. Compile and Apply BPF Filter (BEFORE NCURSES) ---
    struct bpf_program fp;
    bpf_u_int32 net_mask = 0, net_ip = 0;
    if (pcap_file == NULL) pcap_lookupnet(dev_name, &net_ip, &net_mask, errbuf);
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net_mask) == -1) { 
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl; 
        if (alldevs) pcap_freealldevs(alldevs); 
        return 2; 
    }
    if (pcap_setfilter(handle, &fp) == -1) { 
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl; 
        if (alldevs) pcap_freealldevs(alldevs); 
        return 2; 
    }

    // --- 4. Initialize ncurses (AFTER pcap setup) ---
    NcursesManager ncm;
    if (!ncm.is_initialized()) {
        std::cerr << "Failed to initialize ncurses. Exiting." << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return 3;
    }
    signal(SIGWINCH, signal_handler);

    // Initialize windows before launching threads
    int main_h, main_w;
    getmaxyx(stdscr, main_h, main_w);
    configure_windows(main_h, main_w);
    
    // Draw initial empty windows
    werase(stdscr);
    if (stats_win) werase(stats_win);
    if (pcap_win) werase(pcap_win);
    if (bandwidth_win) werase(bandwidth_win);
    if (talkers_win) werase(talkers_win);
    if (main_win) werase(main_win);
    draw_stats_window();
    draw_pcap_window();
    draw_bandwidth_window();
    draw_top_talkers_window();
    draw_main_window();
    refresh();

    // --- 5. Launch Threads ---
    
    // Launch Consumer (Model) Threads
    std::vector<std::thread> worker_threads;
    for (int i = 0; i < num_threads; ++i) {
        worker_threads.emplace_back(consumer_thread_loop);
    }
    
    // Launch Producer (Capture) Thread
    std::thread pcap_thread(pcap_capture_thread, handle, packet_count);

    // --- 6. Run the UI (View/Controller) ---
    ui_loop();

    // --- 7. Graceful Shutdown ---
    pcap_thread.join();
    for (std::thread &t : worker_threads) {
        t.join();
    }
    
    // ncurses is cleaned up automatically by the NcursesManager destructor
    
    // --- 8. Final Cleanup ---
    pcap_freecode(&fp);
    pcap_close(handle);
    if (alldevs) pcap_freealldevs(alldevs);
    
    // (FIX) Print the final pcap error message, if one occurred
    if (!g_pcap_error.empty()) {
        std::cerr << "\n[CAPTURE ERROR]: " << g_pcap_error << std::endl;
    }

    // Print final stats to standard cout after ncurses has closed
    std::cout << "\n--- Capture Statistics ---" << std::endl;
    std::cout << "Packets Received (by pcap): " << g_pcap_stats.ps_recv << std::endl;
    std::cout << "Packets Dropped (by kernel/driver): " << g_pcap_stats.ps_drop << std::endl;
    std::cout << "\n--- Protocol Statistics ---" << std::endl;
    for (std::map<std::string, long>::const_iterator it = stats_map.begin(); it != stats_map.end(); ++it) {
        std::cout << it->first << ": " << it->second << std::endl;
    }
    std::cout << "Sniffer shut down gracefully." << std::endl;
    
    return 0;
}