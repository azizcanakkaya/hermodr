#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define VLAN_HLEN 4
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8

struct vlan_header {
    uint16_t tci;
    uint16_t eth_proto;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int build_packet(
    unsigned char *packet,
    const unsigned char *dst_mac,
    const unsigned char *src_mac,
    uint16_t vlan_id,
    uint8_t cos,
    in_addr_t src_ip,
    in_addr_t dst_ip,
    uint8_t dscp,
    int payload_len
) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_8021Q);

    struct vlan_header *vlan = (struct vlan_header *)(packet + ETH_HDR_LEN);
    vlan->tci = htons(((cos & 0x7) << 13) | (vlan_id & 0x0FFF));
    vlan->eth_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(packet + ETH_HDR_LEN + VLAN_HLEN);
    ip->version = 4;
    ip->ihl = IP_HDR_LEN / 4;
    ip->tos = (dscp & 0x3F) << 2;
    ip->tot_len = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_len);
    ip->id = htons(0);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = checksum(ip, IP_HDR_LEN);

    struct udphdr *udp = (struct udphdr *)(packet + ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN);
    udp->source = htons(12345);
    udp->dest = htons(12345);
    udp->len = htons(UDP_HDR_LEN + payload_len);
    udp->check = 0;

    memset(packet + ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN, 'X', payload_len);

    return ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN + payload_len;
}

void display_help(void) {
    printf("Traffic Generator Options:\n"
           "  -m, --dst-mac   Destination MAC (required)\n"
           "  -M, --src-mac   Source MAC (optional)\n"
           "  -i, --dst-ip    Destination IP (required)\n"
           "  -I, --src-ip    Source IP (optional, default: 0.0.0.0)\n"
           "  -f, --iface     Interface (required)\n"
           "  -d, --duration  Duration in seconds (default: 10)\n"
           "  -u, --mtu       MTU size (default: 1000 bytes)\n"
           "  -r, --rate      Rate in Gbps (default: 1.0)\n"
           "  -b, --vlan      VLAN ID (default: 0)\n"
           "  -q, --qos       DSCP value (default: 0)\n"
           "  -c, --cos       CoS value (default: 0)\n"
           "  -h, --help      Show this help and exit\n");
}

int main(int argc, char **argv) {
    char *dst_mac_str = NULL, *src_mac_str = NULL;
    char *dst_ip_str = NULL, *src_ip_str = "0.0.0.0", *iface = NULL;
    int vlan_id = 0, cos = 0, dscp = 0, duration = 10, mtu = 1000;
    float rate_gbps = 1.0;

    const char *short_opts = "m:M:i:I:f:d:u:r:b:q:c:h";
    static struct option long_opts[] = {
        {"dst-mac", required_argument, 0, 'm'},
        {"src-mac", required_argument, 0, 'M'},
        {"dst-ip",  required_argument, 0, 'i'},
        {"src-ip",  required_argument, 0, 'I'},
        {"iface",   required_argument, 0, 'f'},
        {"duration",required_argument, 0, 'd'},
        {"mtu",     required_argument, 0, 'u'},
        {"rate",    required_argument, 0, 'r'},
        {"vlan",    required_argument, 0, 'b'},
        {"qos",     required_argument, 0, 'q'},
        {"cos",     required_argument, 0, 'c'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
            case 'm': dst_mac_str = optarg; break;
            case 'M': src_mac_str = optarg; break;
            case 'i': dst_ip_str = optarg; break;
            case 'I': src_ip_str = optarg; break;
            case 'f': iface = optarg; break;
            case 'd': duration = atoi(optarg); break;
            case 'u': mtu = atoi(optarg); break;
            case 'r': rate_gbps = atof(optarg); break;
            case 'b': vlan_id = atoi(optarg); break;
            case 'q': dscp = atoi(optarg); break;
            case 'c': cos = atoi(optarg); break;
            case 'h': display_help(); exit(EXIT_SUCCESS);
            default: display_help(); exit(EXIT_FAILURE);
        }
    }

    if (!dst_mac_str || !dst_ip_str || !iface) {
        fprintf(stderr, "Missing required arguments.\n");
        display_help();
        return EXIT_FAILURE;
    }

    unsigned char dst_mac[6], src_mac[6];
    if (sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2],
               &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "Invalid destination MAC format\n");
        return EXIT_FAILURE;
    }

    in_addr_t src_ip = inet_addr(src_ip_str);
    in_addr_t dst_ip = inet_addr(dst_ip_str);
    if (src_ip == INADDR_NONE || dst_ip == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address\n");
        return EXIT_FAILURE;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return EXIT_FAILURE; }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl"); close(sock); return EXIT_FAILURE;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (src_mac_str) {
        if (sscanf(src_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &src_mac[0], &src_mac[1], &src_mac[2],
                   &src_mac[3], &src_mac[4], &src_mac[5]) != 6) {
            fprintf(stderr, "Invalid source MAC format\n");
            return EXIT_FAILURE;
        }
    }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex(iface);
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6);
    device.sll_halen = 6;

    if (bind(sock, (struct sockaddr *)&device, sizeof(device)) < 0) {
        perror("bind"); close(sock); return EXIT_FAILURE;
    }

    if (mtu < ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN + 1) {
        fprintf(stderr, "MTU too small for headers\n");
        return EXIT_FAILURE;
    }

    unsigned char *packet = malloc(mtu);
    if (!packet) { perror("malloc"); close(sock); return EXIT_FAILURE; }

    int payload_len = mtu - (ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN);
    int pkt_len = build_packet(packet, dst_mac, src_mac, vlan_id, cos, src_ip, dst_ip, dscp, payload_len);

    long rate_pps = (long)((rate_gbps * 1e9) / (mtu * 8));
    long total_packets = rate_pps * duration;

    struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = (long)(1e9 / rate_pps)
    };

    struct timespec next_send;
    clock_gettime(CLOCK_MONOTONIC, &next_send);

    printf("Sending %ld packets (~%.2f Mbps) on interface %s\n",
           total_packets, (double)(mtu * 8 * rate_pps) / 1e6, iface);

    for (long i = 0; i < total_packets; i++) {
        sendto(sock, packet, pkt_len, 0, (struct sockaddr *)&device, sizeof(device));

        next_send.tv_nsec += interval.tv_nsec;
        if (next_send.tv_nsec >= 1e9) {
            next_send.tv_sec++;
            next_send.tv_nsec -= 1e9;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        if ((now.tv_sec < next_send.tv_sec) || 
            (now.tv_sec == next_send.tv_sec && now.tv_nsec < next_send.tv_nsec)) {
            struct timespec sleep_time = {
                .tv_sec = next_send.tv_sec - now.tv_sec,
                .tv_nsec = next_send.tv_nsec - now.tv_nsec
            };
            if (sleep_time.tv_nsec < 0) {
                sleep_time.tv_nsec += 1e9;
                sleep_time.tv_sec--;
            }
            nanosleep(&sleep_time, NULL);
        }
    }

    free(packet);
    close(sock);
    return 0;
}
