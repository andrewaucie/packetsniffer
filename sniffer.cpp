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
struct pcap_stat g_pcap_stats;

// --- Results Model ---
std::mutex results_mutex;
std::deque<PacketSummary> results_queue;
const size_t MAX_RESULTS = 100;


// --- TUI UI Windows ---
WINDOW *stats_win, *pcap_win, *main_win;

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
    
    // C++11 compatible loop
    for (std::map<std::string, long>::const_iterator it = stats_map.begin(); it != stats_map.end(); ++it) {
        const std::string& key = it->first;
        long val = it->second;
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
    
    wattron(pcap_win, COLOR_PAIR(1));
    mvwprintw(pcap_win, 2, 2, "Packets Recv:   %-10u", g_pcap_stats.ps_recv);
    wattroff(pcap_win, COLOR_PAIR(1));
    
    wattron(pcap_win, COLOR_PAIR(3));
    mvwprintw(pcap_win, 3, 2, "Packets Dropped: %-10u", g_pcap_stats.ps_drop);
    wattroff(pcap_win, COLOR_PAIR(3));
    
    wrefresh(pcap_win);
}

void draw_main_window() {
    if (!main_win) return;
    box(main_win, 0, 0);
    mvwprintw(main_win, 0, 2, " Live Packet Log (Press 'q' to quit) ");

    int max_y, max_x;
    getmaxyx(main_win, max_y, max_x);
    
    int row = 2;
    std::lock_guard<std::mutex> lock(results_mutex);
    
    for (auto it = results_queue.rbegin(); it != results_queue.rend(); ++it) {
        if (row >= max_y - 1) break; 
        
        const PacketSummary& p = *it;
        
        std::vector<char> line(max_x + 1, 0); 
        snprintf(line.data(), max_x, "%-6d %-6s %-6s %-22s -> %-22s %s",
                 p.id,
                 p.l3_protocol.c_str(),
                 p.l4_protocol.c_str(),
                 (p.src_ip + ":" + p.src_port).c_str(),
                 (p.dst_ip + ":" + p.dst_port).c_str(),
                 p.info.c_str()
                 );
        
        line.data()[max_x - 2] = 0; 
        mvwprintw(main_win, row++, 2, line.data());
    }
    wrefresh(main_win);
}

/**
 * @brief The main UI loop. Runs in the main thread.
 */
void ui_loop() {
    int main_h = 0, main_w = 0, stats_h, stats_w;
    
    while (!shutting_down) {
        int new_main_h, new_main_w;
        getmaxyx(stdscr, new_main_h, new_main_w);
        
        // Only recreate windows if size changed (or first iteration)
        if (new_main_h != main_h || new_main_w != main_w || main_h == 0) {
            main_h = new_main_h;
            main_w = new_main_w;
            stats_h = 10;
            stats_w = main_w / 2;
            
            if (stats_win) delwin(stats_win);
            if (pcap_win) delwin(pcap_win);
            if (main_win) delwin(main_win);
            
            stats_win = newwin(stats_h, stats_w, 0, 0);
            pcap_win = newwin(stats_h, main_w - stats_w, 0, stats_w);
            main_win = newwin(main_h - stats_h, main_w, stats_h, 0);
        }
        
        int ch = getch();
        if (ch == 'q') {
            shutting_down = true;
            if (g_handle) pcap_breakloop(g_handle);
            queue_cond.notify_all();
            break;
        }

        werase(stats_win);
        werase(pcap_win);
        werase(main_win);
        
        draw_stats_window();
        draw_pcap_window();
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
    int main_h, main_w, stats_h, stats_w;
    getmaxyx(stdscr, main_h, main_w);
    stats_h = 10;
    stats_w = main_w / 2;
    
    stats_win = newwin(stats_h, stats_w, 0, 0);
    pcap_win = newwin(stats_h, main_w - stats_w, 0, stats_w);
    main_win = newwin(main_h - stats_h, main_w, stats_h, 0);
    
    // Draw initial empty windows
    werase(stdscr);
    werase(stats_win);
    werase(pcap_win);
    werase(main_win);
    draw_stats_window();
    draw_pcap_window();
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