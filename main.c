/*
pcapmirror - A simple packet mirroring tool using libpcap

Copyright (c) 2025, Matthias Cramer, cramer@freestone.net
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/ip6.h>

#define DEFAULT_DEST_PORT 37008 // Default TZSP port
#define TZSP_ENCAP_LEN 4       // Length of TZSP encapsulation header
#define TZSP_TAGGED_LEN 1      // Length of TZSP tagged field header (type)
#define ETHERNET_HEADER_LENGTH 14

// TZSP Header Structure
struct tzsp_header {
    unsigned char version;      // Version (usually 1 or 2)
    unsigned char type;         // Type (0x01 for packet)
    unsigned short encapsulated_protocol; // Encapsulated protocol (Ethernet = 1)
    unsigned short length;      // Length of the payload + header
};

// TZSP Tagged Field Structure
struct tzsp_tagged {
    unsigned char type;         // Tag type
};

// Function to check if the system is little-endian
int is_little_endian() {
    volatile unsigned int i=0x01234567;
    return (((unsigned char*)&i)[0] == 0x67);
}

void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>       Specify the capture interface\n");
    printf("  -f <filter>          Specify the capture filter (BPF syntax)\n");
    printf("  -r <host/ipv4/ipv6>  Specify the destination host (required)\n");
    printf("  -p <port>            Specify the destination port (default: %d)\n", DEFAULT_DEST_PORT);
    printf("  -4                   Force IPv4 host lookup\n");
    printf("  -6                   Force IPv6 host lookup\n");
    printf("  -v                   Enable verbose mode\n");
    printf("  -h                   Show this help message\n");
    printf("Example:\n");
    printf("  %s -i eth0 -f 'tcp port 80' -v -r 192.168.1.100 -p 47008\n", program_name);
}

int main(int argc, char *argv[]) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = "tcp port 8088"; // Default filter
    char *dev_name = NULL; // Device name
    char *mirror_host = NULL; // Destination IP, no default value
    int dest_port = DEFAULT_DEST_PORT; // Destination port, default value
    int i;
    int verbose = 0; // Verbose flag, default is false
    int force_ipv4 = 0; // Flag to force IPv4 lookup
    int force_ipv6 = 0; // Flag to force IPv6 lookup

    // Socket variables
    int sockfd;
    struct addrinfo hints, *res;
    struct sockaddr_storage dest_addr; // Declare dest_addr

    // Check if no arguments are given or if help is requested
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    // Parse command-line arguments
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filter_exp = argv[i + 1];
            i++; // Skip the filter value
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            dev_name = argv[i + 1];
            i++; // Skip the interface value
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1; // Enable verbose mode
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            mirror_host = argv[i + 1]; // Set destination IP from command line
            i++; // Skip the IP value
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            dest_port = atoi(argv[i + 1]); // Set destination port from command line
            i++; // Skip the port value
        } else if (strcmp(argv[i], "-4") == 0) {
            force_ipv4 = 1; // Force IPv4 lookup
        } else if (strcmp(argv[i], "-6") == 0) {
            force_ipv6 = 1; // Force IPv6 lookup
        }
    }

    // Check if destination IP is provided
    if (mirror_host == NULL) {
        fprintf(stderr, "Error: Destination IP address is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Resolve the destination address
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM; // Datagram socket

    if (force_ipv4) {
        hints.ai_family = AF_INET; // Force IPv4
    } else if (force_ipv6) {
        hints.ai_family = AF_INET6; // Force IPv6
    }

    if (getaddrinfo(mirror_host, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    // Create UDP socket
    sockfd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    // Set the destination address
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        ipv4->sin_port = htons(dest_port);
        memcpy(&dest_addr, ipv4, sizeof(struct sockaddr_in));
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        ipv6->sin6_port = htons(dest_port);
        memcpy(&dest_addr, ipv6, sizeof(struct sockaddr_in6));
    }

    // Resolve the destination IP address
    char resolved_ip[INET6_ADDRSTRLEN];
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), resolved_ip, INET6_ADDRSTRLEN);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), resolved_ip, INET6_ADDRSTRLEN);
    }

    // Free the address info
    freeaddrinfo(res);

    printf("Using interface: %s\n", dev_name);
    printf("Using filter: %s\n", filter_exp);
    printf("Resolved Destination IP: %s\n", resolved_ip);
    printf("Destination Port: %d\n", dest_port);

    // If no interface is specified, find all devices
    if (dev_name == NULL) {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return(1);
        }

        // Print the available devices for debugging
        /*
        pcap_if_t *device;
        printf("Available devices:\n");
        for (device = alldevs; device != NULL; device = device->next) {
            printf("%s - %s\n", device->name, (device->description != NULL) ? device->description : "No description available");
        }
        */

        // Use the first device if no device is specified
        if (alldevs == NULL) {
            fprintf(stderr, "No devices found. Make sure you have permissions to capture traffic.\n");
            return 1;
        }

        dev_name = alldevs->name; // Use the name of the first device
    } else {
        // Interface specified via command line, no need to find all devices
        alldevs = NULL; // Set alldevs to NULL to avoid potential issues
    }

    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s: %s\n", dev_name, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        pcap_close(handle);
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        pcap_close(handle);
        return(2);
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    char source_ip_str[INET6_ADDRSTRLEN], dest_ip_str[INET6_ADDRSTRLEN];
    struct ip *ip_header; // Declare ip4_header
    struct ip6_hdr *ip6_header; // Declare ip6_header
    int ip_protocol = 0;

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL)
            continue;

        // Assuming Ethernet header is 14 bytes
        // Check IP version
        ip_header = (struct ip*)(packet + ETHERNET_HEADER_LENGTH);
        ip_protocol = ip_header->ip_v;

        if (ip_protocol == 4) {
            // IPv4
            inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET6_ADDRSTRLEN);

            if (verbose) {
                printf("IPv4 Packet: %s -> %s, IP Protocol: %d\n",
                       source_ip_str, dest_ip_str, ip_header->ip_p);
            }
        } else if (ip_protocol == 6) {
            // IPv6
            ip6_header = (struct ip6_hdr*)(packet + ETHERNET_HEADER_LENGTH);
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), source_ip_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dest_ip_str, INET6_ADDRSTRLEN);

            if (verbose) {
                printf("IPv6 Packet: %s -> %s, Next Header: %d\n",
                       source_ip_str, dest_ip_str, ip6_header->ip6_nxt);
            }
        } else {
            printf("Non-IP Packet\n");
            continue;
        }

        // Create TZSP Header
        struct tzsp_header tzsp;
        tzsp.version = 1;          // TZSP Version 1
        tzsp.type = 1;          // Type 1 for packet
        tzsp.encapsulated_protocol = htons(1); // Ethernet

        // Create TZSP Tagged Field for End of Fields
        struct tzsp_tagged end_tag;
        end_tag.type = 1;             // End of Fields

        // Calculate total length
        unsigned short total_length = header.caplen + TZSP_ENCAP_LEN + TZSP_TAGGED_LEN;
        tzsp.length = htons(total_length);

        // Allocate memory for TZSP packet
        unsigned char *tzsp_packet = (unsigned char *)malloc(total_length);
        if (tzsp_packet == NULL) {
            perror("malloc");
            continue; // Skip this packet
        }

        // Copy TZSP header and tagged field and packet data into the new buffer
        unsigned char *ptr = tzsp_packet;
        memcpy(ptr, &tzsp, TZSP_ENCAP_LEN);
        ptr += TZSP_ENCAP_LEN;
        memcpy(ptr, &end_tag, TZSP_TAGGED_LEN);
        ptr += TZSP_TAGGED_LEN;
        memcpy(ptr, packet, header.caplen);

        // Send packet via UDP with TZSP encapsulation
        if (sendto(sockfd, tzsp_packet, total_length, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
            perror("sendto");
        }

        free(tzsp_packet); // Free allocated memory
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs); // Free the device list only if devices were found
    }
    close(sockfd);
    return(0);
}