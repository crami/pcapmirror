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
PREFIX = /usr

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
		rm -f -f $(OBJS) $(TARGET)

# Install the executable
install: $(TARGET)
		mkdir -p $(DESTDIR)$(PREFIX)/bin
		install -D  $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

# Uninstall the executable
uninstall:
		rm -f $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

# Run the executable (example)
run: $(TARGET)
		./$(TARGET) -i eth0 -f "tcp port 80" -v
