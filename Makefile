# Packet sniffer build - requires libpcap and ncurses

CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -g -O2 -pthread -Iinclude
LDFLAGS = -lpcap -pthread -lncurses

TARGET = sniffer
SOURCES = src/main.cpp src/core.cpp src/ui.cpp src/reassembly.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = include/core.hpp include/ui.hpp include/reassembly.hpp

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET)
