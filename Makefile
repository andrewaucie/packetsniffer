#
# Makefile for the C++ Professional Packet Sniffer
#
# This Makefile builds the multithreaded TUI application and correctly
# links all necessary libraries (libpcap, pthread, and ncurses).
#

# --- Variables ---

# Compiler
CXX = g++

# Compiler Flags:
# -std=c++11 : Use the C++11 standard
# -Wall      : Enable all common warnings
# -Wextra    : Enable extra warnings
# -g         : Include debugging symbols (for GDB)
# -O2        : Optimization level 2 (for a release build)
# -pthread   : Enable and link the POSIX threads library
CXXFLAGS = -std=c++11 -Wall -Wextra -g -O2 -pthread

# Linker Flags:
# -lpcap     : Link the libpcap library
# -pthread   : Required at the linking stage for std::thread
# -lncurses  : Link the ncurses TUI library
LDFLAGS = -lpcap -pthread -lncurses

# Executable Name
TARGET = sniffer

# Source Files (.cpp)
SOURCES = sniffer.cpp parsers.cpp reassembly.cpp

# Object Files (.o)
# Automatically generates a list like: sniffer.o parsers.o reassembly.o
OBJECTS = $(SOURCES:.cpp=.o)

# Header Files (.h)
# Used to ensure .o files are rebuilt if a header they depend on changes.
HEADERS = sniffer.h parsers.h reassembly.h

# --- Rules ---

# The default rule ('all') is the first one in the file.
# Running 'make' will execute this rule.
all: $(TARGET)

# Rule to build the final executable (the "linking" step).
# This rule links all the compiled .o files together.
$(TARGET): $(OBJECTS)
	@echo "Linking executable: $@"
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete. Run with: ./$(TARGET)"

# Generic pattern rule to build .o files from .cpp files.
# This says "To build any .o file, you need its .cpp file and all headers."
# If any .cpp or .h file changes, this rule will re-run for the relevant .o.
%.o: %.cpp $(HEADERS)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@
	# $< is the first prerequisite (the .cpp file)
	# $@ is the target (the .o file)

# "Phony" target for cleaning up the directory.
# This rule doesn't build a file, so it's marked as .PHONY.
.PHONY: clean
clean:
	@echo "Cleaning up object files and executable..."
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete."