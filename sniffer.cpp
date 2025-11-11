/*
 * sniffer.cpp
 *
 * This is the main "driver" file. It contains only main()
 * and a usage helper function.
 *
 * It is responsible for:
 * 1. Registering a signal handler for graceful shutdown (Ctrl+C).
 * 2. Parsing command-line arguments.
 * 3. Launching the pool of Consumer worker threads.
 * 4. Setting up the pcap capture (live or offline).
 * 5. Running the Producer (pcap_loop) in this main thread.
 * 6. Handling graceful shutdown of all threads.
 */

#include "sniffer.h"
#include "parsers.h"

// Define the global pcap handle (declared in sniffer.h)
pcap_t *g_handle = NULL;

/**
 * @brief Graceful shutdown signal handler
 * This function is called by the OS when (Ctrl+C) is pressed.
 * It is a C-style function, so it cannot be a class member.
 * It must be *very* fast and only use async-safe functions
 * (which we are slightly violating, but is common practice).
 * @param signum The signal number (e.g., SIGINT).
 */
void signal_handler(int signum) {
    // Use the thread-safe print mutex
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\n[!] Caught signal " << signum << " (Ctrl+C). Shutting down..." << std::endl;
    }

    // Set the atomic flag to tell workers to stop
    shutting_down = true;

    // Wake up any sleeping worker threads
    queue_cond.notify_all();

    // Tell pcap_loop() to break, which will unblock main()
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
}

/**
 * @brief Prints the command-line help menu and exits.
 * @param progname The name of the executable (argv[0]).
 */
void print_usage(char *progname) {
    // Lock the print mutex for this block to prevent
    // jumbling with worker thread startup messages.
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "Professional Sniffer Tool (Stateful, Multi-Protocol, Multithreaded)" << std::endl;
    std::cout << "Usage: " << progname << " [options]" << std::endl;
    std::cout << "  -i <interface>   Live capture from <interface> (e.g., en0)" << std::endl;
    std::cout << "  -r <file>        Read packets from <file> (e.g., capture.pcap)" << std::endl;
    std::cout << "  -c <count>       Stop after <count> packets (default: -1, infinite)" << std::endl;
    std::cout << "  -f <filter>      Set BPF filter (e.g., \"tcp port 80\")" << std::endl;
    std::cout << "  -h               Show this help menu" << std::endl;
    std::cout << "  -t <threads>     Number of worker threads (default: auto [N-1 cores])" << std::endl;
    exit(1);
}

/**
 * @brief Main entry point.
 */
int main(int argc, char *argv[]) {
    // --- 0. Register Signal Handler ---
    // This tells the OS to call signal_handler()
    // instead of terminating the program on Ctrl+C.
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // This is the local handle
    char *dev_name = NULL;
    char *pcap_file = NULL;
    int packet_count = -1; // Default to -1 (infinite)
    char *filter_exp = (char *)"";
    pcap_if_t *alldevs = NULL;
    
    unsigned int num_cores = std::thread::hardware_concurrency();
    int num_threads = (num_cores > 2) ? (num_cores - 1) : 1;

    // --- 1. Argument Parsing ---
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { print_usage(argv[0]); }
        else if (strcmp(argv[i], "-i") == 0) { if (i + 1 < argc) dev_name = argv[++i]; else print_usage(argv[0]); }
        else if (strcmp(argv[i], "-r") == 0) { if (i + 1 < argc) pcap_file = argv[++i]; else print_usage(argv[0]); }
        else if (strcmp(argv[i], "-c") == 0) { if (i + 1 < argc) packet_count = atoi(argv[++i]); else print_usage(argv[0]); }
        else if (strcmp(argv[i], "-f") == 0) { if (i + 1 < argc) filter_exp = argv[++i]; else print_usage(argv[0]); }
        else if (strcmp(argv[i], "-t") == 0) { if (i + 1 < argc) num_threads = atoi(argv[++i]); else print_usage(argv[0]); }
        else { print_usage(argv[0]); }
    }

    // --- 2. Launch Consumer Threads ---
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Starting " << num_threads << " worker thread(s)..." << std::endl;
    }
    std::vector<std::thread> worker_threads;
    for (int i = 0; i < num_threads; ++i) {
        worker_threads.emplace_back(consumer_thread_loop);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // --- 3. Setup pcap Capture Session ---
    if (pcap_file != NULL) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Reading from file: " << pcap_file << std::endl;
        handle = pcap_open_offline(pcap_file, errbuf);
    } else {
        if (dev_name == NULL) {
            if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                std::cerr << "Couldn't find devices: " << errbuf << std::endl; return 2;
            }
            if (alldevs == NULL) {
                std::cerr << "No devices found." << std::endl; return 2;
            }
            dev_name = alldevs->name;
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "No interface specified, using default: " << dev_name << std::endl;
        }
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Sniffing on device: " << dev_name << std::endl;
        handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    }
    
    if (handle == NULL) { 
        std::cerr << "pcap_open failed: " << errbuf << std::endl; 
        if (alldevs) pcap_freealldevs(alldevs);
        shutting_down = true;
        queue_cond.notify_all();
        for (std::thread &t : worker_threads) t.join();
        return 2; 
    }

    // Assign the local handle to the global handle
    // so the signal handler can access it.
    g_handle = handle;

    // --- 4. Compile and Apply BPF Filter ---
    struct bpf_program fp;
    bpf_u_int32 net_mask = 0;
    bpf_u_int32 net_ip = 0;

    if (pcap_file == NULL) {
        pcap_lookupnet(dev_name, &net_ip, &net_mask, errbuf);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        if (alldevs) pcap_freealldevs(alldevs);
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        if (alldevs) pcap_freealldevs(alldevs);
        return 2;
    }
    
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Filter: \"" << (strlen(filter_exp) == 0 ? "None" : filter_exp) << "\"" << std::endl;
    }

    // --- 5. Run the PRODUCER (Main Thread) ---
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Capture started. Main thread is now producing..." << std::endl;
        if (packet_count == -1) {
             std::cout << "(Capturing indefinitely. Press Ctrl+C to stop)" << std::endl;
        }
    }
    
    // This blocks until pcap_breakloop() is called (from our
    // signal handler) or 'packet_count' packets are received.
    pcap_loop(handle, packet_count, producer_callback, NULL);

    // --- 6. Graceful Shutdown ---
    // This section is now reachable after Ctrl+C!
    
    // Get and print capture statistics
    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\n--- Capture Statistics ---" << std::endl;
        std::cout << "Packets Received (by pcap): " << stats.ps_recv << std::endl;
        std::cout << "Packets Dropped (by kernel/driver): " << stats.ps_drop << std::endl;
    }
    
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\n--- Capture finished ---" << std::endl;
        std::cout << "Signaling worker threads to shut down..." << std::endl;
    }
    
    // Set the atomic shutdown flag (in case pcap_loop
    // finished naturally without Ctrl+C).
    shutting_down = true;
    
    // Notify all waiting threads so they can check the flag
    queue_cond.notify_all();

    // Wait for all worker threads to finish
    for (std::thread &t : worker_threads) {
        t.join();
    }
    
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "All workers shut down." << std::endl;
    }

    // --- 7. Final Cleanup ---
    pcap_freecode(&fp);
    pcap_close(handle);
    if (alldevs) pcap_freealldevs(alldevs);
    return 0;
}