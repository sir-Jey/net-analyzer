#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#define DEFAULT_PROTOCOL    "tcp"

#define COLOR_GREEN         "\033[32m"
#define COLOR_RED           "\033[31m"
#define COLOR_YELLOW        "\033[33m"
#define COLOR_RESET         "\033[0m"

pcap_t *dev;
int user_num_pckgs = -1;
char user_device[256]; 
int user_flag_dev = 0;
char user_protocol[256] = DEFAULT_PROTOCOL;
int user_flag_prot = 0;
int user_port = -1;

void help_manual(void);
int calculate_tcp_distance(const struct ip *ip_header);
void calculate_tcp_options(const struct tcphdr *tcp_header, int *mss, int *wscale, int *sack, int *tsval, int *tsecr);
void sigint_handler(int signo);
int get_user_opt(int argc, char *argv[]);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void static_printable(void);
const char *detect_os(int ttl, int winsize, int mss, int wscale, int sack, int tsval, int tsecr);
void generate_tcp_addr(const struct tcphdr *tcp_header, char *addr_src, char *addr_dst);
void generate_udp_addr(const struct udphdr *udp_header, char *addr_src, char *addr_dst);


struct statics_tcp_packet {
    int total_tcp_packets;
    int syn_packets;
    int rst_ack_packets;
    int oth_tcp_packets;
};
struct statics_tcp_packet stat_tcp;


int main(int argc, char *argv[])
{
    if (get_user_opt(argc, argv) == -1) {
        fprintf(stderr, "usage: неверное использвоание опций\n");
        exit(0);
    }

    struct sigaction mask;
    sigemptyset(&mask.sa_mask);
    mask.sa_flags =0;
    mask.sa_handler = sigint_handler;
    if (sigaction(SIGINT, &mask, NULL) == -1) {
        fprintf(stderr, "error: неудалось перехватить сигнал SIGINT: sigaction: %s\n",
            strerror(errno));
        exit(0);
    }


    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    if (user_flag_dev) {
        while (alldevs != NULL && strcmp(alldevs->name, user_device) != 0)
            alldevs = alldevs->next;
        if (alldevs == NULL) {
            fprintf(stderr, "интерфейс %s не найден!\n", user_device);
            pcap_freealldevs(alldevs);
            exit(1);
        }
    }

    if ((dev = pcap_open_live(alldevs->name, 65535, 1, 2000, errbuf)) == NULL) {
        fprintf(stderr, "open live: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    pcap_freealldevs(alldevs);

    struct bpf_program filter;

    char text_filter[256];

    if (user_flag_prot && user_port != -1) {
        snprintf(text_filter, 256, "%s and port %d", user_protocol, user_port);
    } else if (!user_flag_prot && user_port != -1) {
        snprintf(text_filter, 256, "%s and port %d", DEFAULT_PROTOCOL, user_port);
    } else if (user_flag_dev && user_port == -1) {
        snprintf(text_filter, 256, "%s", user_protocol);
    } else {
        strcpy(text_filter, DEFAULT_PROTOCOL);
    }

    // printf("фильтр: %s\n\n", text_filter);

    if (pcap_compile(dev, &filter, text_filter, 1, 0xFFFFFFFF) < 0) {
        fprintf(stderr, "ошибка компиляции фильтра: pcap_compile: %s\n", pcap_geterr(dev));
        pcap_close(dev);
        return 3;
    }

    if (pcap_setfilter(dev, &filter) == -1) {
        fprintf(stderr, "setfilter: %s\n", pcap_geterr(dev));
        pcap_freecode(&filter);
        pcap_close(dev);
        return 4;
    } 

    if (user_num_pckgs == -1) {
        printf("перехваченые пакеты:\n\n");
    } else {
        printf("%d перехваченных %s-пакетов:\n\n", user_num_pckgs, user_protocol);
    }

    int ret = pcap_loop(dev, -1, packet_handler, (u_char *)dev);
    if (ret < 0) {
        if (ret == -1) {
            fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(dev));
            pcap_freecode(&filter);
            pcap_close(dev);
            return 5;
        }
        else if (ret == -2) {
            static_printable();
        }
    }

    pcap_freecode(&filter);
    pcap_close(dev);

    return (0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
{
    stat_tcp.total_tcp_packets ++;

    pcap_t *dev = (pcap_t *)user;
    u_short ether_type = (packet[12] << 8) | packet[13];

    if (ether_type == 0x800) {
        const struct ip *ip_header = (struct ip *)(packet + 14);
        char addr_src[BUFSIZ], addr_dst[BUFSIZ];
        inet_ntop(AF_INET, &(ip_header->ip_src), addr_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), addr_dst, INET_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));

            generate_tcp_addr(tcp_header, addr_src, addr_dst);

            int syn_packet = 0;
            if (tcp_header->th_flags & 0x02 && !(tcp_header->th_flags & 0x10))  {
                syn_packet = 1;
                if (user_num_pckgs != -1) {
                    if (stat_tcp.syn_packets == user_num_pckgs) 
                        pcap_breakloop(dev);
                }
            }

            int is_rst_packet = 0;
            if (tcp_header->th_flags & 0x04 && tcp_header->th_flags & 0x10) {
                is_rst_packet = 1;
            }
            
            int distance_ttl = calculate_tcp_distance(ip_header);

            int mss = 0, wscale = -1, sack = 0, tsval = 0, tsecr = 0;

            calculate_tcp_options(tcp_header, &mss, &wscale, &sack, &tsval, &tsecr);
            

            const char *type_host = detect_os(
                ip_header->ip_ttl, 
                tcp_header->th_win, 
                mss,
                wscale,
                sack,
                tsval,
                tsecr
            );

            if (syn_packet) {
                stat_tcp.syn_packets ++;
                printf(COLOR_GREEN "%s -> %s | расстояние=%d роутеров | df=%d id = %d | предполагаемая ОС=%s | win=%d | mss=%d sack=%s wscale=%d tsval=%d tsecr=%d\n", 
                    addr_src,
                    addr_dst,
                    distance_ttl,
                    ip_header->ip_off & 0x4000,
                    ntohs(ip_header->ip_id),
                    type_host,
                    tcp_header->th_win,
                    mss, sack ? "yes" : "no",
                    wscale, tsval, tsecr);
            }

            if (is_rst_packet) {
                stat_tcp.rst_ack_packets ++;
                printf(COLOR_RED "%s -> %s | флаги=RST+ACK | расстояние= - | df=%d id=%d | предполагаемая ОС=%s | win=%d | mss=%d sack=%s wscale=%d tsval=%d tsecr=%d\n",
                    addr_src, 
                    addr_dst,
                    ip_header->ip_off & 0x4000,
                    ntohs(ip_header->ip_id),
                    type_host,
                    tcp_header->th_win,
                    mss, sack ? "yes" : "no",
                    wscale, tsval, tsecr);
            }
        }

        if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            
            generate_udp_addr(udp_header, addr_src, addr_dst);
            printf("%s -> %s | длина UDP-пакета %d\n", 
                addr_src, 
                addr_dst, 
                htons(udp_header->uh_ulen));
        }

        if (ip_header->ip_p == IPPROTO_ICMP) {
            const struct icmp *icmp_header = (struct icmp *)(packet + 14 + (ip_header->ip_hl * 4));

            printf("типа ICMP-сообщения=%d | %s -> %s | длина IP-пакета %d\n", 
                icmp_header->icmp_type, 
                addr_src, addr_dst, ip_header->ip_len);
        }
    }
}

void help_manual(void) 
{
    printf(
        "СПРАВКА:\n"
        "-i <интерфейс> - указать сетевой интерфейс для прослушки. Если флаг не указан -- выбирается первый подходящий интерфейс (не loopback).\n"
        "-c <количество> - количество SYN-пакетов, после которых программа завершается. Если флаг не указан — программа работает бесконечно до нажатия Ctrl+C.\n"
        "-p <протокол> - \n"
        "\t-p tcp - только TCP (по умолчанию)\n"
        "\t-p udp - только UDP\n"
        "\t-p icmp - только ICMP\n"
        "--port <номер_порта> - выводить только пакеты, у которых порт источника или порт назначения равен "
        "заданному. Работает только для TCP и UDP"
    );
}

int calculate_tcp_distance(const struct ip *ip_header) 
{
    if ( ip_header->ip_ttl > 0 && ip_header->ip_ttl <= 64) {
        return 64 - ip_header->ip_ttl;
    } else if ( ip_header->ip_ttl > 64 && ip_header->ip_ttl <= 128) {
        return 128 - ip_header->ip_ttl;
    } else if ( ip_header->ip_ttl > 128 && ip_header->ip_ttl <= 255) {
        return 255 - ip_header->ip_ttl;
    }

    return 0;
}

void calculate_tcp_options(const struct tcphdr *tcp_header, int *mss, int *wscale, int *sack, int *tsval, int *tsecr) 
{
    const u_char *opts = (const u_char *)tcp_header + (tcp_header->th_off * 4);
    const u_char *opts_end = opts + (tcp_header->th_off * 4) - sizeof(struct tcphdr);
    while (opts < opts_end) {
        u_char kind = opts[0];
        if (kind == 0) break;     
        if (kind == 1) {          
            opts++;
            continue;
        }
        u_char len = opts[1];
        if (len < 2 || opts + len > opts_end) break;
        switch (kind) {
            case 2:  
                if (len == 4) *mss = (opts[2] << 8) | opts[3]; break;
            case 3:
                if (len == 3) *wscale = opts[2]; break;
            case 4:  
                *sack = 1; break;
            case 8: 
                if (len == 10) {
                    *tsval = (opts[2] << 24) | (opts[3] << 16) | (opts[4] << 8) | opts[5];
                    *tsecr = (opts[6] << 24) | (opts[7] << 16) | (opts[8] << 8) | opts[9];
                }
                break;
        }
        opts += len;
   }
}

void sigint_handler(int signo)
{
    const char *buf = "Получен сигнал завершения. Останавливаю захват...\n";
    write(STDOUT_FILENO, buf, strlen(buf));
    pcap_close(dev);

    static_printable();
    
    exit(0);
}

int get_user_opt(int argc, char *argv[])
{
    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            help_manual();
            exit(0);
        }
        if (strcmp(argv[i], "-i") == 0) {
            if (argv[i+1] == NULL) {
                return -1;
            } else {
                user_flag_dev = 1;
                strcpy(user_device, argv[i+1]);
                user_device[strcspn(user_device, "\n")] = 0;
            }
        }

        if (strcmp(argv[i], "-c") == 0) {
            if (argv[i+1] == NULL) {
                return -1;
            } else {
                user_num_pckgs = atoi(argv[i+1]);
            }
        }

        if (strcmp(argv[i], "-p") == 0) {
            if (argv[i+1] == NULL) {
                return -1;
            } else {
                user_flag_prot = 1;
                strcpy(user_protocol, argv[i+1]);
                user_protocol[strcspn(user_protocol, "\n")] = 0;
            }
        }

        if (strcmp(argv[i], "--port") == 0) {
            if (argv[i+1] == NULL) {
                return -1;
            } else {
                user_port = atoi(argv[i+1]);
            }
        }
    }

    return 0;
}

void static_printable(void)
{
    if (strcmp(user_protocol, "tcp") == 0) {
        printf(COLOR_YELLOW "\n\n=== СТАТИСТИКА ===\n");
        printf(COLOR_YELLOW "Количество перехваченных TCP-пакетов: %d\n", stat_tcp.total_tcp_packets);
        printf(COLOR_YELLOW "SYN пакетов: %d\n", stat_tcp.syn_packets);
        printf(COLOR_YELLOW "RST+ACK пакетов: %d\n", stat_tcp.rst_ack_packets);

        stat_tcp.oth_tcp_packets = stat_tcp.total_tcp_packets - stat_tcp.syn_packets - stat_tcp.rst_ack_packets;
        printf(COLOR_YELLOW "Другие TCP пакеты: %d\n", stat_tcp.oth_tcp_packets);
        printf("\n");
    }
}

const char *detect_os(int ttl, int winsize, int mss, int wscale, int sack, int tsval, int tsecr)
{
    if (ttl == 64 && (winsize == 65535 || winsize == 64512) && (tsval == 0 && tsecr == 0)) {
        return("macOS");
    } else if (ttl ==128 && winsize == 65535 && mss == 0 && sack == 0) {
        return("Windows 10/11");
    } else if (ttl == 64 && (winsize == 29200 || winsize == 32120) && mss == 0 && sack == 0 && (tsval == 0 && tsecr == 0) && wscale == 0) {
        return ("Linux");
    }

    return ("Notknown");
}

void generate_tcp_addr(const struct tcphdr *tcp_header, char *addr_src, char *addr_dst)
{
    char port[10];
    snprintf(port, 10, "%d", ntohs(tcp_header->th_sport));
    strcat(addr_src, ":");
    strcat(addr_src, port);

    snprintf(port, 10, "%d", ntohs(tcp_header->th_dport));
    strcat(addr_dst, ":");
    strcat(addr_dst, port);
}


void generate_udp_addr(const struct udphdr *udp_header, char *addr_src, char *addr_dst)
{
    char port[10];
    snprintf(port, 10, "%d", ntohs(udp_header->uh_sport));
    strcat(addr_src, ":");
    strcat(addr_src, port);

    snprintf(port, 10, "%d", ntohs(udp_header->uh_dport));
    strcat(addr_dst, ":");
    strcat(addr_dst, port);
}
