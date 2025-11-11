/*
 * parsers.h
 *
 * Declares the main producer/consumer functions
 * for the multithreaded architecture.
 */

#ifndef PARSERS_H
#define PARSERS_H

#include "sniffer.h" // For pcap_t

/**
 * @brief The PRODUCER callback.
 * This is the *only* function called by pcap_loop.
 * Its only job is to copy the packet and put it in the queue.
 * This function must be as fast as possible to avoid drops.
 */
void producer_callback(
    u_char *user_data,
    const struct pcap_pkthdr *header,
    const u_char *packet
);

/**
 * @brief The CONSUMER loop.
 * This is the function that all worker threads will run.
 * It waits for packets, pops them from the queue, and
 * calls the real processing function.
 */
void consumer_thread_loop();


#endif // PARSERS_H