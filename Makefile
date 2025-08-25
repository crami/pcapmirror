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
all: $(TARGET) man

static: $(OBJS)
		$(CC) $(CFLAGS) -static $(OBJS) -o $(TARGET) $(LIBS) -ldbus-1 -lsystemd -lcap

# Create executable
$(TARGET): $(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Create object files
%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

man:
	gzip -9 -c pcapmirror.8 > pcapmirror.8.gz

# Clean up object files and executable
clean:
		rm -f -f $(OBJS) $(TARGET)

# Install the executable
install: $(TARGET)
		mkdir -p $(DESTDIR)$(PREFIX)/bin
		install -D $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
		install -D $(TARGET).8 $(DESTDIR)$(PREFIX)/share/man/man8/$(TARGET).8
		

# Uninstall the executable
uninstall:
		rm -f $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
		rm -f $(TARGET).8.gz $(DESTDIR)$(PREFIX)/share/man/man8/$(TARGET).8.gz

# Run the executable (example)
run: $(TARGET)
		./$(TARGET) -i eth0 -f "tcp port 80" -v
