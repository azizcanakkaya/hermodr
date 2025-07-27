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
#include <cjson/cJSON.h>

#define VLAN_HLEN 4
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8

struct vlan_header {
    uint16_t tci;
    uint16_t eth_proto;
};

struct stream_package {
    unsigned char* packet;
    int size;
};

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
);

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

void parse_stream(const char *stream_name, cJSON *stream, struct stream_package* stream_pack) {
    if (!stream || !stream_pack) return;

    const char *dst_mac_str = cJSON_GetObjectItem(stream, "destination_mac") ?
                              cJSON_GetObjectItem(stream, "destination_mac")->valuestring : "00:00:00:00:00:00";
    const char *src_mac_str = cJSON_GetObjectItem(stream, "source-mac") ?
                              cJSON_GetObjectItem(stream, "source-mac")->valuestring : "00:00:00:00:00:00";
    const char *dst_ip_str  = cJSON_GetObjectItem(stream, "destination_ip") ?
                              cJSON_GetObjectItem(stream, "destination_ip")->valuestring : "0.0.0.0";
    const char *src_ip_str  = cJSON_GetObjectItem(stream, "source_ip") ?
                              cJSON_GetObjectItem(stream, "source_ip")->valuestring : "0.0.0.0";

    int mtu = cJSON_GetObjectItem(stream, "mtu") ?
              cJSON_GetObjectItem(stream, "mtu")->valueint : 1500;
    uint16_t vlan_id = cJSON_GetObjectItem(stream, "vlan") ?
                       cJSON_GetObjectItem(stream, "vlan")->valueint : 0;
    uint8_t dscp = cJSON_GetObjectItem(stream, "qos") ?
                   cJSON_GetObjectItem(stream, "qos")->valueint : 0;
    uint8_t cos = cJSON_GetObjectItem(stream, "cos") ?
                  cJSON_GetObjectItem(stream, "cos")->valueint : 0;

    in_addr_t src_ip = inet_addr(src_ip_str);
    in_addr_t dst_ip = inet_addr(dst_ip_str);

    unsigned char dst_mac[6], src_mac[6];
    if (sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2],
               &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "[%s] Invalid destination MAC format.\n", stream_name);
        stream_pack->packet = NULL;
        stream_pack->size = 0;
        return;
    }

    if (sscanf(src_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &src_mac[0], &src_mac[1], &src_mac[2],
               &src_mac[3], &src_mac[4], &src_mac[5]) != 6) {
        fprintf(stderr, "[%s] Invalid source MAC format.\n", stream_name);
        stream_pack->packet = NULL;
        stream_pack->size = 0;
        return;
    }

    int min_required = ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN + 1;
    if (mtu < min_required) {
        fprintf(stderr, "[%s] Skipped: MTU too small (%d < %d required)\n", stream_name, mtu, min_required);
        stream_pack->packet = NULL;
        stream_pack->size = 0;
        return;
    }

    stream_pack->packet = malloc(mtu);
    if (!stream_pack->packet) {
        perror("malloc");
        stream_pack->size = 0;
        return;
    }

    int payload_len = mtu - (ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN + UDP_HDR_LEN);
    int pkt_len = build_packet(stream_pack->packet, dst_mac, src_mac, vlan_id, cos, src_ip, dst_ip, dscp, payload_len);
    stream_pack->size = pkt_len;

    printf("[%s] %s -> %s | %s -> %s | MTU: %d | VLAN: %d | QoS: %d | CoS: %d\n",
           stream_name, src_mac_str, dst_mac_str, src_ip_str, dst_ip_str,
           mtu, vlan_id, dscp, cos);
}


void send_stream(const char* iface, const int duration, const float rate_gbps, const char* config_file)
{
    FILE *fp = fopen(config_file, "rb");
    struct stream_package packets[16] = {0};

    if (!fp) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    rewind(fp);

    char *data = malloc(length + 1);
    fread(data, 1, length, fp);
    data[length] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        fprintf(stderr, "JSON Parse Error\n");
        exit(EXIT_FAILURE);
    }

    cJSON *stream = NULL;
    int stream_count = 0;
    cJSON_ArrayForEach(stream, root) {
        if (stream_count >= 16) break;
        parse_stream(stream->string, stream, &packets[stream_count]);
        if (packets[stream_count].packet != NULL && packets[stream_count].size > 0)
            stream_count++;
    }
    cJSON_Delete(root);

    if (stream_count == 0) {
        fprintf(stderr, "No valid stream packets loaded.\n");
        return;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex(iface);
    device.sll_family = AF_PACKET;
    device.sll_halen = ETH_ALEN;

    if (device.sll_ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return;
    }

    // Time and rate control
    const double target_bps = rate_gbps * 1e9; // bits per second
    const double target_bits_per_ns = target_bps / 1e9;

    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    long long bits_sent = 0;
    int stream_idx = 0;

    printf("Sending in round-robin (%d streams) for %d seconds at %.2f Gbps...\n", stream_count, duration, rate_gbps);

    while (1) {
        // Check if time is up
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        double elapsed_ns = (current_time.tv_sec - start_time.tv_sec) * 1e9 +
                            (current_time.tv_nsec - start_time.tv_nsec);
        if (elapsed_ns >= duration * 1e9)
            break;

        struct stream_package *sp = &packets[stream_idx];
        if (sp->packet && sp->size > 0) {
            sendto(sock, sp->packet, sp->size, 0, (struct sockaddr*)&device, sizeof(device));
            bits_sent += sp->size * 8;
        }

        stream_idx = (stream_idx + 1) % stream_count;

        // Rate control
        double ideal_bits = elapsed_ns * target_bits_per_ns;
        if ((double)bits_sent > ideal_bits) {
            long long overshoot_bits = bits_sent - ideal_bits;
            double overshoot_ns = overshoot_bits / target_bits_per_ns;

            if (overshoot_ns > 1000) { // Sleep if delay > 1us
                struct timespec ts;
                ts.tv_sec = (long)(overshoot_ns / 1e9);
                ts.tv_nsec = (long)overshoot_ns % (long)1e9;
                nanosleep(&ts, NULL);
            }
        }
    }

    for (int i = 0; i < stream_count; i++) {
        free(packets[i].packet);
    }
    close(sock);
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
    if (!packet || !dst_mac || !src_mac || payload_len < 0) return -1;

    // Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)packet;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_8021Q);

    // VLAN Header
    struct vlan_header *vlan = (struct vlan_header *)(packet + ETH_HDR_LEN);
    vlan->tci = htons(((cos & 0x7) << 13) | (vlan_id & 0x0FFF));
    vlan->eth_proto = htons(ETH_P_IP);

    // IP Header
    struct iphdr *ip = (struct iphdr *)(packet + ETH_HDR_LEN + VLAN_HLEN);
    ip->version = 4;
    ip->ihl = 5;
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

    // UDP Header
    struct udphdr *udp = (struct udphdr *)(packet + ETH_HDR_LEN + VLAN_HLEN + IP_HDR_LEN);
    udp->source = htons(12345);
    udp->dest = htons(12345);
    udp->len = htons(UDP_HDR_LEN + payload_len);
    udp->check = 0;  // Optional in IPv4

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
           "  -u, --mtu       MTU size (default: 1000 bytes, at least give out 1000 bytes due to CPU bottleneck)\n"
           "  -r, --rate      Rate in Gbps (default: 1.0)\n"
           "  -b, --vlan      VLAN ID (default: 0)\n"
           "  -q, --qos       DSCP value (default: 0)\n"
           "  -c, --cos       CoS value (default: 0)\n"
           "  -s, --stream    Config file path to send in stream (optional)\n"
           "  -h, --help      Show this help and exit\n"
           "Example single stream usage: hermodr --dst-mac AA:AA:AA:AA:AA:AA --src-mac BB:BB:BB:BB:BB:BB "
           "--dst-ip 1.1.1.1 --src-ip 0.0.0.0 --iface eth0 --duration 10 --mtu 1500 --rate 1.0 --vlan 10 --qos 0 --cos 0\n"
           "Example multiple stream: hermodr --iface eth0 --duration 10 --rate 1.0 --stream <json_file_path>\n");
}

int main(int argc, char **argv) {
    char *dst_mac_str = NULL, *src_mac_str = NULL, *stream_config = NULL;
    char *dst_ip_str = NULL, *src_ip_str = "0.0.0.0", *iface = NULL;
    int vlan_id = 0, cos = 0, dscp = 0, duration = 10, mtu = 1000;
    float rate_gbps = 1.0;

    const char *short_opts = "m:M:i:I:f:d:u:r:b:q:c:h:s";
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
        {"stream",  required_argument, 0, 's'},
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
            case 's': stream_config = optarg; break;
            case 'h': display_help(); exit(EXIT_SUCCESS);
            default: display_help(); exit(EXIT_FAILURE);
        }
    }

    if (stream_config) {
        if (!iface) {
            fprintf(stderr, "Missing required argument: --iface\n");
            display_help();
            return EXIT_FAILURE;
        }
        send_stream(iface, duration, rate_gbps, stream_config);
        return 0;
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
