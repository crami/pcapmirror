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

# Run the executable (example)
run: $(TARGET)
		sudo ./$(TARGET) -i eth0 -f "tcp port 80" -v