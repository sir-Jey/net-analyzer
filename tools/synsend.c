#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>

#define DEVICE "en0"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    const char *dst_ip = argv[1];
    int dst_port = atoi(argv[2]);

    if (dst_port < 1 || dst_port > 65535) {
        fprintf(stderr, "invalid port\n");
        return 1;
    }

    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_LINK, DEVICE, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init: %s\n", errbuf);
        return 1;
    }

    libnet_seed_prand(l);

    libnet_ptag_t eth = libnet_build_ethernet(
        (u_int8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // dst (broadcast)
        (u_int8_t[]){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // src (заполнится)
        ETHERTYPE_IP,
        NULL,
        0,
        l,
        0
    );
    if (eth == -1) {
        fprintf(stderr, "can't build ethernet: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
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
        fprintf(stderr, "can't build tcp: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
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
        fprintf(stderr, "can't build ipv4: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    if (libnet_write(l) == -1) {
        fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    printf("SYN sent to %s:%d\n", dst_ip, dst_port);
    libnet_destroy(l);
    return 0;
}
