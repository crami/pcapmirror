# Makefile for pcapmirror

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Libraries
LIBS = -lpcap

# Source files
SRCS = main.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = pcapmirror

# Installation directory
PREFIX = /usr/local

# Default rule
all: $(TARGET)

# Create executable
$(TARGET): $(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Create object files
%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

# Clean up object files and executable
clean:
		rm -f $(OBJS) $(TARGET)

# Install the executable
install: $(TARGET)
		sudo install -D $(TARGET) $(PREFIX)/bin/$(TARGET)

# Uninstall the executable
uninstall:
		sudo rm -f $(PREFIX)/bin/$(TARGET)

# Run the executable (example)
run: $(TARGET)
		sudo ./$(TARGET) -i eth0 -f "tcp port 80" -v