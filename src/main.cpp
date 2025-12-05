/*
 * main.cpp - Entry point
 * 
 * Sets up pcap capture, spawns worker threads, runs UI loop.
 */

#include "core.hpp"
#include "ui.hpp"
#include "reassembly.hpp"

// Parse args, init pcap, spawn threads, run UI, cleanup.
int main(int argc, char *argv[]) {
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

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-i") == 0) { if (i + 1 < argc) dev_name = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-r") == 0) { if (i + 1 < argc) pcap_file = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-c") == 0) { if (i + 1 < argc) packet_count = atoi(argv[++i]); else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-f") == 0) { if (i + 1 < argc) filter_exp = argv[++i]; else { print_usage(argv[0]); return 1; } }
        else if (strcmp(argv[i], "-t") == 0) { if (i + 1 < argc) num_threads = atoi(argv[++i]); else { print_usage(argv[0]); return 1; } }
        else { print_usage(argv[0]); return 1; }
    }

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

    if (!init_ncurses()) {
        std::cerr << "Failed to initialize ncurses." << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return 3;
    }
    signal(SIGWINCH, signal_handler);

    int main_h, main_w;
    getmaxyx(stdscr, main_h, main_w);
    configure_windows(main_h, main_w);
    
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

    g_num_worker_threads = num_threads;
    capture_start_time = std::chrono::steady_clock::now();
    std::vector<std::thread> worker_threads;
    for (int i = 0; i < num_threads; ++i) {
        worker_threads.emplace_back(consumer_thread_loop);
    }
    std::thread pcap_thread(pcap_capture_thread, handle, packet_count);

    ui_loop();

    pcap_thread.join();
    for (std::thread &t : worker_threads) {
        t.join();
    }
    cleanup_ncurses();
    
    pcap_freecode(&fp);
    pcap_close(handle);
    if (alldevs) pcap_freealldevs(alldevs);
    
    if (!g_pcap_error.empty()) {
        std::cerr << "\n[CAPTURE ERROR]: " << g_pcap_error << std::endl;
    }

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
