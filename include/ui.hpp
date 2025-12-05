/*
 * ui.hpp - ncurses TUI declarations
 */

#ifndef UI_HPP
#define UI_HPP

#include <ncurses.h>
#include <string>

extern WINDOW *stats_win;
extern WINDOW *pcap_win;
extern WINDOW *bandwidth_win;
extern WINDOW *talkers_win;
extern WINDOW *main_win;
extern WINDOW *timeline_win;

extern std::string display_filter;
extern bool filter_input_mode;

extern bool capture_paused;
extern int packet_scroll_offset;

bool init_ncurses();
void cleanup_ncurses();
void configure_windows(int screen_h, int screen_w);
void draw_stats_window();
void draw_pcap_window();
void draw_bandwidth_window();
void draw_top_talkers_window();
void draw_timeline_window();
void draw_main_window();
void ui_loop();

#endif
