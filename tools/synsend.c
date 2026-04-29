/* инструмент тестирования сниффера: 
 * отправка SYN-пакета используя TCP-протокол. 
 *
 * Другие поля для заголовка TCP указаны в функциях libnet_build_tcp() и libnet_build_ipv4()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>

#define DEVICE "en0" // for test  

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <ip> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *dst_ip = argv[1];
    int dst_port = atoi(argv[2]);

    if (dst_port < 1 || dst_port > 65535) {
        fprintf(stderr, "invalid port\n");
        exit(EXIT_FAILURE);
    }

    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_LINK, DEVICE, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    libnet_seed_prand(l);

    libnet_ptag_t eth = libnet_build_ethernet(
        (u_int8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 
        (u_int8_t[]){0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        ETHERTYPE_IP,
        NULL,
        0,
        l,
        0
    );
    if (eth == -1) {
        fprintf(stderr, "невозможно сформировать ethernet-заголовок для кадра: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    libnet_ptag_t tcp = libnet_build_tcp(
        31123,                     
        dst_port,                  
        libnet_get_prand(LIBNET_PR2), 
        0,                        
        TH_SYN,                    
        4096,                      
        0,                        
        0,                         
        0,                        
        NULL,                     
        0,                         
        l,                        
        0                          
    );
    if (tcp == -1) {
        fprintf(stderr, "невозможно сформировать tcp-заголовок для сегмента: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    libnet_ptag_t ip = libnet_build_ipv4(
        libnet_getpacket_size(l), 
        0,                         
        0,                         
        0x4000,                    
        64,                        
        IPPROTO_TCP,               
        0,                        
        inet_addr("192.168.0.4"), 
        inet_addr(dst_ip),        
        NULL,
        0,
        l,
        0
    );
    if (ip == -1) {
        fprintf(stderr, "невозможно сформировать ipv4-заголовок для дейтаграммы: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    if (libnet_write(l) == -1) {
        fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    printf("SYN отправлен %s:%d\n", dst_ip, dst_port);
    libnet_destroy(l);
    exit(EXIT_SUCCESS);
}
