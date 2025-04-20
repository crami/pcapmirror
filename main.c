/*
pcapmirror - A simple packet mirroring tool using libpcap

Copyright (c) 2025, Matthias Cramer, cramer@freestone.net
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h> // For Ethernet and ARP headers
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define DEFAULT_DEST_PORT 37008 // Default TZSP port
#define TZSP_ENCAP_LEN 4       // Length of TZSP encapsulation header
#define TZSP_TAGGED_LEN 1      // Length of TZSP tagged field header (type)
#define ETHERNET_HEADER_LENGTH 14 // Assuming Ethernet header is 14 bytes

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

// GRE Header Structure
struct gre_header {
    uint16_t flags;      // GRE flags
    uint16_t protocol;   // Protocol type (0x88BE for ERSPAN)
};

// ERSPAN Header Structure
// ERSPAN Type II Header Structure
struct erspan_header {
    uint32_t ver_vlan_cos_en_t_session; // Ver (4 bits), VLAN (12 bits), COS (3 bits), En (1 bit), T (1 bit), Session ID (10 bits)
    uint32_t reserved_index;            // Reserved (12 bits), Index (20 bits)
};

// Add this structure for ARP header parsing
struct arp_header {
    uint16_t htype;    // Hardware type
    uint16_t ptype;    // Protocol type
    uint8_t hlen;      // Hardware address length
    uint8_t plen;      // Protocol address length
    uint16_t oper;     // Operation (1 = request, 2 = reply)
    uint8_t sha[6];    // Sender hardware address
    uint8_t spa[4];    // Sender protocol address
    uint8_t tha[6];    // Target hardware address
    uint8_t tpa[4];    // Target protocol address
};

void list_interfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    printf("Available network interfaces:\n");
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("%s", d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }
    pcap_freealldevs(alldevs);
}

// Function to lookup protocol name or return protocol number as a string
const char *lookup_protocol_name(int protocol) {
    static char buf[5]; // Buffer to hold protocol number as a string

    switch (protocol) {
        case 1:
            return "ICMP";
        case 2:
            return "IGMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 41:
            return "IPv6";
        case 47:
            return "GRE";
        case 50:
            return "ESP";
        case 51:
            return "AH";
        case 58:
            return "ICMPv6";
        case 89:
            return "OSPF";
        case 112:
            return "VRRP";
        case 124:
            return "ISIS";
        case 132:
            return "SCTP";
        default:
            snprintf(buf, sizeof(buf), "%d", protocol); // Convert protocol number to string
            return buf;
    }
}

void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>       Specify the capture interface\n");
    printf("  -f <filter>          Specify the capture filter (BPF syntax)\n");
    printf("  -r <host/ipv4/ipv6>  Specify the destination host (required)\n");
    printf("  -p <port>            Specify the destination port (default: %d)\n", DEFAULT_DEST_PORT);
    printf("  -e                   Use ERSPAN encapsulation (default: TZSP)\n");
    printf("  -s <source_ip>       Specify the source IP address (required for ERSPAN)\n");
    printf("  -S <session_id>      Specify the session ID (default: 42, must be between 0 and 1023)\n");
    printf("  -4                   Force IPv4 host lookup\n");
    printf("  -6                   Force IPv6 host lookup\n");
    printf("  -l                   List available network interfaces\n");
    printf("  -v                   Enable verbose mode\n");
    printf("  -c                   Count matching packets (overrides verbose mode)\n");
    printf("  -h                   Show this help message\n");
    printf("Example:\n");
    printf("  %s -i eth0 -f 'tcp port 80' -v -r 192.168.1.100 -p 47008\n", program_name);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = ""; // Default filter
    char *dev_name = NULL; // Device name
    char *mirror_host = NULL; // Destination IP, no default value
    int dest_port = DEFAULT_DEST_PORT; // Destination port, default value
    int i;
    int verbose = 0; // Verbose flag, default is false
    int force_ipv4 = 0; // Flag to force IPv4 lookup
    int force_ipv6 = 0; // Flag to force IPv6 lookup
    int list_interfaces_flag = 0; // Flag to list interfaces

    // Add a variable to track the count of matching packets
    int count_packets = 0; // Flag for counting packets
    unsigned long long int packet_count = 0;  // Counter for matching packets (64bit)

    int use_erspan = 0; // Flag for ERSPAN encapsulation
    char *source_address = NULL; // Source IP address, default is NULL
    uint32_t session_id = 42;      // Session ID (10 bits)

    // Socket variables
    int sockfd;
    struct addrinfo hints, *res;
    struct sockaddr_storage dest_addr; // Declare dest_addr
    int dest_addr_size;

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
        } else if (strcmp(argv[i], "-l") == 0) {
            list_interfaces_flag = 1; // Set flag to list interfaces
        } else if (strcmp(argv[i], "-c") == 0) {
            count_packets = 1; // Enable packet counting
            verbose = 0;       // Disable verbose mode if -c is set
        } else if (strcmp(argv[i], "-e") == 0) {
            use_erspan = 1; // Enable ERSPAN encapsulation
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            source_address = argv[i + 1]; // Set source IP from command line
            i++; // Skip the source IP value
        } else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            session_id = atoi(argv[i + 1]); // Set session ID from command line
            if (session_id > 1023) { // Validate session ID (must fit in 10 bits)
                fprintf(stderr, "Error: Session ID must be between 0 and 1023.\n");
                return 1;
            }
            i++; // Skip the session ID value
        }
    }

    if (list_interfaces_flag) {
        list_interfaces();
        return 0;
    }

    // Check if destination IP is provided
    if (mirror_host == NULL && !list_interfaces_flag) {
        fprintf(stderr, "Error: Destination IP address is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Check that interface is not any
    if (dev_name != NULL && strcmp(dev_name, "any") == 0) {
        fprintf(stderr, "Error: Interface 'any' is not supported.\n");
        return 1;
    }

    // Check if the interface is specified
    if (dev_name == NULL) {
        fprintf(stderr, "Error: Interface must be specified\n");
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

    // Calculate dest_addr size
    if (res->ai_family == AF_INET) {
        dest_addr_size = sizeof(struct sockaddr_in);
    } else if (res->ai_family == AF_INET6) {
        dest_addr_size = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "Unknown address family\n");
        freeaddrinfo(res);
        return 1;
    }

    if (use_erspan) {
        // Create a raw socket for ERSPAN
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
        if (sockfd == -1) {
            perror("socket");
            freeaddrinfo(res);
            return 1;
        }
    
        // Set the IP_HDRINCL option to include the IP header in the packet
        int optval = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
            perror("setsockopt");
            close(sockfd);
            freeaddrinfo(res);
            return 1;
        }
    } else {
        // Create a UDP socket for TZSP
        sockfd = socket(res->ai_family, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("socket");
            freeaddrinfo(res);
            return 1;
        }
    }

    memset(&dest_addr, 0, sizeof(dest_addr));

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

    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s: %s\n", dev_name, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev_name, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    char source_ip_str[INET6_ADDRSTRLEN], dest_ip_str[INET6_ADDRSTRLEN];
    struct ip *ip_header; // Declare ip4_header
    struct ip6_hdr *ip6_header; // Declare ip6_header
    int ip_protocol = 0;
    struct timeval current_time, last_count;
    static uint32_t sequence_number = 0; // Sequence number for ERSPAN packets

    gettimeofday(&last_count, NULL);
    printf("\n");

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL)
            continue;

        if (count_packets) {
            packet_count++;

            gettimeofday(&current_time, NULL);

            long elapsed_ms = current_time.tv_sec * 1000 + (current_time.tv_usec /1000)-
                              (last_count.tv_sec * 1000 + (last_count.tv_usec /1000));

            if (elapsed_ms >= 500) {
                printf("\rPacket count: %llu", packet_count);
                fflush(stdout);
                last_count = current_time; // Reset the timer
            }
        }

        if (verbose) {

            // Parse Ethernet header
            struct ether_header *eth_header = (struct ether_header *)packet;

            // Check EtherType
            uint16_t ether_type = ntohs(eth_header->ether_type);
            
            int vlan_offset = 0; // Offset for VLAN-tagged packets

            // Check for VLAN tags (including Q-in-Q)
            while (ether_type == 0x8100 || ether_type == 0x88A8) {
                // VLAN tag is present
                vlan_offset += 4; // Each VLAN tag adds 4 bytes
                uint16_t vlan_tag = ntohs(*(uint16_t *)(packet + ETHERNET_HEADER_LENGTH + vlan_offset - 4));
                uint16_t vlan_id = vlan_tag & 0x0FFF; // Extract VLAN ID (12 bits)
                uint8_t vlan_pcp = (vlan_tag >> 13) & 0x07; // Extract Priority Code Point (3 bits)
                uint8_t vlan_dei = (vlan_tag >> 12) & 0x01; // Extract Drop Eligible Indicator (1 bit)

                printf("VLAN Tag: VLAN ID=%d, PCP=%d, DEI=%d\n", vlan_id, vlan_pcp, vlan_dei);

                // Update EtherType to the next protocol
                ether_type = ntohs(*(uint16_t *)(packet + ETHERNET_HEADER_LENGTH + vlan_offset - 2));
            }
        
            if (ether_type == ETHERTYPE_IP) {
                // Handle IPv4 traffic
                ip_header = (struct ip *)(packet + ETHERNET_HEADER_LENGTH + vlan_offset);
                ip_protocol = ip_header->ip_v & 0x0F; // Get IP version
        
                if (ip_protocol == 4) {
                    inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), source_ip_str, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), dest_ip_str, INET6_ADDRSTRLEN);
        
                    printf("IPv4 Packet: %s -> %s, IP Protocol: %s\n",
                           source_ip_str, dest_ip_str, lookup_protocol_name(ip_header->ip_p));
                }
            } else if (ether_type == ETHERTYPE_IPV6) {
                // Handle IPv6 traffic
                ip6_header = (struct ip6_hdr *)(packet + ETHERNET_HEADER_LENGTH + vlan_offset);
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), source_ip_str, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dest_ip_str, INET6_ADDRSTRLEN);
        
                printf("IPv6 Packet: %s -> %s, Next Header: %s\n",
                       source_ip_str, dest_ip_str, lookup_protocol_name(ip6_header->ip6_nxt));
            } else if (ether_type == ETHERTYPE_ARP) {
                // Handle ARP traffic
                struct arp_header *arp = (struct arp_header *)(packet + ETHERNET_HEADER_LENGTH + vlan_offset);
        
                printf("ARP Packet: Operation: %s\n",
                       (ntohs(arp->oper) == 1) ? "Request" : "Reply");
                printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x, Sender IP: %d.%d.%d.%d\n",
                       arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
                       arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
                printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x, Target IP: %d.%d.%d.%d\n",
                       arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5],
                       arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
            } else {
                printf("Non-IP/ARP Packet, EtherType: 0x%04x\n", ether_type);
            }
        }

        // Encapsulation logic
        if (use_erspan) {
            // ERSPAN Encapsulation
            struct ip ip_header;
            struct gre_header gre;
            struct erspan_header erspan;
        
            // Set IP header fields
            memset(&ip_header, 0, sizeof(ip_header));
            ip_header.ip_hl = 5; // Header length (5 * 4 = 20 bytes)
            ip_header.ip_v = 4;  // IPv4
            ip_header.ip_tos = 0; // Type of Service
            ip_header.ip_len = htons(sizeof(ip_header) + sizeof(gre) + sizeof(sequence_number) + sizeof(erspan) + header.caplen);
            ip_header.ip_id = htons(0); // Identification
            ip_header.ip_off = 0; // Fragment offset
            ip_header.ip_ttl = 64; // Time to live
            ip_header.ip_p = IPPROTO_GRE; // Protocol (GRE)
            ip_header.ip_dst.s_addr = ((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr;
            
            if (source_address != NULL) {
                if (inet_pton(AF_INET, source_address, &(ip_header.ip_src)) != 1) {
                    fprintf(stderr, "Error: Invalid source IP address '%s'\n", source_address);
                    return 1;
                }
            } else {
                ip_header.ip_src.s_addr = inet_addr("192.168.1.1"); // Default source IP
            }

            ip_header.ip_src.s_addr = inet_addr("192.168.1.1"); // Replace with your source IP
        
            // Set GRE header fields
            gre.flags = htons(0x1000); // GRE flags (S bit set for Sequence Number Present)
            gre.protocol = htons(0x88BE); // ERSPAN protocol type
        
            // Set ERSPAN header fields
            uint32_t version = 1;          // Version (4 bits)
            uint32_t vlan = 100;           // VLAN ID (12 bits)
            uint32_t cos = 5;              // Class of Service (3 bits)
            uint32_t en = 0;               // Trunk Encapsulation Type (2 bit)
            uint32_t t = 1;                // Truncated (1 bit)

            // Combine fields into the 32-bit ver_vlan_cos_en_t_session field
            erspan.ver_vlan_cos_en_t_session = 
                ((version & 0xF) << 28) |  // Version (4 bits, shifted to bits 28-31)
                ((vlan & 0xFFF) << 16) |   // VLAN ID (12 bits, shifted to bits 16-27)
                ((cos & 0x7) << 13) |      // Class of Service (3 bits, shifted to bits 13-15)
                ((en & 0x3) << 11) |       // Trunk Encapsulation Type (2 bit, bit 12)
                ((t & 0x1) << 10) |        // Truncated (1 bit, bit 11)
                (session_id & 0x3FF);      // Session ID (10 bits, bits 0-9)

            // Convert to network byte order
            erspan.ver_vlan_cos_en_t_session = htonl(erspan.ver_vlan_cos_en_t_session);

            // Set the reserved and index fields
            uint32_t reserved = 0;         // Reserved (12 bits)
            uint32_t index = 12345;        // Index (20 bits)

            // Combine fields into the 32-bit reserved_index field
            erspan.reserved_index = 
                ((reserved & 0xFFF) << 20) | // Reserved (12 bits, bits 20-31)
                (index & 0xFFFFF);           // Index (20 bits, bits 0-19)

            // Convert to network byte order
            erspan.reserved_index = htonl(erspan.reserved_index);
        
            // Calculate total length
            unsigned short total_length = sizeof(ip_header) + sizeof(gre) + sizeof(sequence_number) + sizeof(erspan) + header.caplen;
        
            // Allocate memory for ERSPAN packet
            unsigned char *erspan_packet = (unsigned char *)malloc(total_length);
            if (erspan_packet == NULL) {
                perror("malloc");
                continue; // Skip this packet
            }
        
            // Copy IP header, GRE header, sequence number, ERSPAN header, and packet data into the new buffer
            unsigned char *ptr = erspan_packet;
            memcpy(ptr, &ip_header, sizeof(ip_header));
            ptr += sizeof(ip_header);
            memcpy(ptr, &gre, sizeof(gre));
            ptr += sizeof(gre);
            uint32_t seq_num_network_order = htonl(sequence_number++);
            memcpy(ptr, &seq_num_network_order, sizeof(sequence_number));
            ptr += sizeof(sequence_number);
            memcpy(ptr, &erspan, sizeof(erspan));
            ptr += sizeof(erspan);
            memcpy(ptr, packet, header.caplen);
        
            // Send packet via raw socket
            if (sendto(sockfd, erspan_packet, total_length, 0, (struct sockaddr *)&dest_addr, dest_addr_size) == -1) {
                perror("sendto");
            }
        
            free(erspan_packet); // Free allocated memory
            printf("Sent ERSPAN packet with sequence number: %u\n", sequence_number - 1);
        } else {
            // TZSP Encapsulation

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
            if (sendto(sockfd, tzsp_packet, total_length, 0, (struct sockaddr *)&dest_addr, dest_addr_size) == -1) {
                perror("sendto");
            }

            free(tzsp_packet); // Free allocated memory
        }
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    close(sockfd);
    return(0);
}