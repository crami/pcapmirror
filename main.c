#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define DEST_IP "193.5.68.11" // Replace with your destination IP
#define DEST_PORT 37008       // TZSP uses port 37008
#define TZSP_ENCAP_LEN 4       // Length of TZSP encapsulation header
#define TZSP_TAGGED_LEN 1      // Length of TZSP tagged field header (type)

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
    printf("  -i <interface>  Specify the capture interface\n");
    printf("  -f <filter>     Specify the capture filter (BPF syntax)\n");
    printf("  -v              Enable verbose mode\n");
    printf("  -h              Show this help message\n");
    printf("Example:\n");
    printf("  %s -i eth0 -f 'tcp port 80' -v\n", program_name);
}

int main(int argc, char *argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = "tcp port 8088"; // Default filter
    char *dev_name = NULL; // Device name
    int i;
    int verbose = 0; // Verbose flag, default is false

    // Socket variables
    int sockfd;
    struct sockaddr_in dest_addr;

    // Check if no arguments are given or if help is requested
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return 1;
    }

    // Set destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    if (inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return 1;
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
            close(sockfd);
            return 0;
        }
    }

    // If no interface is specified, find all devices
    if (dev_name == NULL) {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            close(sockfd);
            return(1);
        }

        // Print the available devices
        printf("Available devices:\n");
        for (device = alldevs; device != NULL; device = device->next) {
            printf("%s - %s\n", device->name, (device->description != NULL) ? device->description : "No description available");
        }

        // Use the first device if no device is specified
        if (alldevs == NULL) {
            fprintf(stderr, "No devices found. Make sure you have permissions to capture traffic.\n");
            close(sockfd);
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
        close(sockfd);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        pcap_close(handle);
        close(sockfd);
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        pcap_close(handle);
        close(sockfd);
        return(2);
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    printf("Using interface: %s\n", dev_name);
    printf("Using filter: %s\n", filter_exp);

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL)
            continue;

        ip_header = (struct ip*)(packet + 14); // Assuming Ethernet header is 14 bytes
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4)); // IP header length in 4-byte words

        if (verbose) {
            printf("Packet: %s:%d -> %s:%d\n",
               source_ip, ntohs(tcp_header->source), dest_ip, ntohs(tcp_header->dest));
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