# pcapmirror

pcapmirror is a command-line tool for capturing network traffic and mirroring it to a remote destination using TZSP encapsulation. It leverages the `libpcap` library for packet capture and provides options for filtering traffic based on BPF syntax. This tool is useful for network monitoring, intrusion detection, and remote packet analysis.

## Usage

```bash
pcapmirror [options]
```

Options:

-i <interface>: Specify the capture interface (e.g., eth0).
-f <filter>: Specify the capture filter in BPF syntax (e.g., tcp port 80).
-v: Enable verbose mode (prints packet information).
-h: Show this help message.
Example:

To capture traffic on the eth0 interface, filter for TCP port 80, and send it to the destination, use the following command:

```bash
sudo pcapmirror -i eth0 -f "tcp port 80" -v
```

Note: Running pcapmirror typically requires root privileges due to the use of libpcap for capturing network traffic.

## Compile and Install

Compile the program:
```bash
make
```

Install the program:
```bash
make install
```

This will copy the pcapmirror executable to bin. You may need to adjust the PREFIX variable in the Makefile if you want to install it to a different location.

Dependencies
libpcap: You need to have libpcap installed on your system. On Debian/Ubuntu systems, you can install it using:
```bash
sudo apt-get install libpcap-dev
```

On Fedora/CentOS/RHEL systems, you can install it using:
```bash
sudo yum install libpcap-devel
```


