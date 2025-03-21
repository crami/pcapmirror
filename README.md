# pcapmirror
pcapmirror is a command-line tool for capturing network traffic and mirroring it to a remote destination using [TZSP encapsulation](https://en.wikipedia.org/wiki/TZSP). It leverages the `libpcap` library for packet capture and provides options for filtering traffic based on BPF syntax. This tool is useful for network monitoring, intrusion detection, and remote packet analysis.

## Usage

```bash
pcapmirror [options]
```

### Options:

* -i <interface>: Specify the capture interface (e.g., eth0).
* -f <filter>: Specify the capture filter in BPF syntax (e.g., tcp port 80).
* -r <ip_address>: Specify the destination IP address (required).
* -p <port>: Specify the destination port (default: 37008).
* -v: Enable verbose mode (prints packet information).
* -h: Show this help message.

### Example:

To capture traffic on the eth0 interface, filter for TCP port 80, and send it to the destination, use the following command:

```bash
sudo pcapmirror -i eth0 -f "tcp port 80" -r 192.168.1.100 -p 47008 -v
```
*Note*: Running pcapmirror typically requires root privileges due to the use of libpcap for capturing network traffic.

## Usage with wireshark

With this tool, you can mirror traffic directly to a running [Wireshark](https://www.wireshark.org/).

To avoid capturing traffic from your own monitoring machine, configure Wireshark with a capture filter of udp port 37008 or udp dst port 37008. Also, verify that your firewall permits this UDP traffic.

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


