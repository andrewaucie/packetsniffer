/*
 * ui.hpp
 *
 * ncurses-based terminal user interface.
 * Provides window management and rendering functions.
 */

#ifndef UI_HPP
#define UI_HPP

#include <ncurses.h>

// --- TUI Window Handles ---
extern WINDOW *stats_win;
extern WINDOW *pcap_win;
extern WINDOW *bandwidth_win;
extern WINDOW *talkers_win;
extern WINDOW *main_win;
extern WINDOW *timeline_win;

// --- Function Declarations ---

/**
 * @brief Initialize ncurses and check for errors.
 * @return true if initialization succeeded, false otherwise.
 */
bool init_ncurses();

/**
 * @brief Clean up ncurses and restore terminal.
 */
void cleanup_ncurses();

/**
 * @brief Helper to (re)create the ncurses windows based on current terminal size.
 */
void configure_windows(int screen_h, int screen_w);

/**
 * @brief Draw the protocol statistics window.
 */
void draw_stats_window();

/**
 * @brief Draw the pcap capture statistics window.
 */
void draw_pcap_window();

/**
 * @brief Draw the bandwidth monitoring window.
 */
void draw_bandwidth_window();

/**
 * @brief Draw the top talkers window.
 */
void draw_top_talkers_window();

/**
 * @brief Draw the conversation timeline window.
 */
void draw_timeline_window();

/**
 * @brief Draw the main packet log window.
 */
void draw_main_window();

/**
 * @brief The main UI loop. Runs in the main thread.
 */
void ui_loop();

#endif // UI_HPP

