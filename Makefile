EXE = packets
CFLAGS = -Wall
CXXFLAGS = -Wall
LDLIBS = -lpcap
CC = gcc
CXX = g++

.PHONY: all
all: $(EXE)

# Implicit rules defined by Make, but you can redefine if needed
#
#packets: packets.c
#	$(CC) $(CFLAGS) packets.c $(LDLIBS) -o packets
#
# OR
#
#packets: packets.cc
#	$(CXX) $(CXXFLAGS) packets.cc $(LDLIBS) -o packets

.PHONY: clean
clean:
	rm -rf $(EXE)

