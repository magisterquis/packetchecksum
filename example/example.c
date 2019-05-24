/*
 * example.c
 * Use packetchecksum
 * By J. Stuart McMurray
 * Created 20190521
 * Last Modified 20190521
 */

#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if_arp.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <err.h>
#include <fcntl.h>
#include <pcap.h>
#include <string.h>
#include <strings.h>

#include "packetchecksum.h"

/* BUFLEN is the size of the packet buffer */
#define BUFLEN 2048

void inject(pcap_t *p, uint8_t *buf, size_t len,
                const void *l2h, size_t l2hlen,
                const void *l3h, size_t l3hlen,
                const void *l4h, size_t l4hlen);

/* The following program makes and sends out a handful of packets to serve the
 * dual purposes of demonstrating and testing packetchecksum_calculate() */
int
main(int argc, char **argv)
{
        struct ether_header  eh;
        struct ip            i4h;
        struct ip6_hdr       i6h;
        struct tcphdr        th;
        struct udphdr        uh;
        struct icmp          icmph;
        struct icmp6_hdr     icmp6h;
        uint8_t              buf[BUFLEN];
        char                 errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_t              *p;

        bzero(&eh,     sizeof(eh));
        bzero(&i4h,    sizeof(i4h));
        bzero(&i6h,    sizeof(i6h));
        bzero(&th,     sizeof(th));
        bzero(&uh,     sizeof(uh));
        bzero(&icmph,  sizeof(icmph));
        bzero(&icmp6h, sizeof(icmp6h));
        bzero(errbuf,  sizeof(errbuf));

        /* Load headers */
        memcpy(&eh.ether_dhost, "\xfe\xe1\xba\x11\x11\x11",
                        sizeof(eh.ether_dhost));
        memcpy(&eh.ether_shost, "\xfe\xe1\xba\x22\x22\x22",
                        sizeof(eh.ether_shost));
        /* Will need to set eh->ether_type */
        i4h.ip_hl = 5;
        i4h.ip_v = 4;
        i4h.ip_ttl = 250;
        memcpy(&i4h.ip_src, "\x0b\x0b\x0b\x0b", sizeof(i4h.ip_src));
        memcpy(&i4h.ip_dst, "\x0a\x0a\x0a\x0a", sizeof(i4h.ip_dst));
        /* Will need to set i4h.ip_len and i4h.ip_p */
        i6h.ip6_vfc = IPV6_VERSION;
        i6h.ip6_hlim = 250;
        memcpy(&i6h.ip6_src, "AAAAAAAAAAAAAAAA", sizeof(i6h.ip6_src));
        memcpy(&i6h.ip6_dst, "BBBBBBBBBBBBBBBB", sizeof(i6h.ip6_dst));
        /* Will need to set i6h.ip6_plen and i6h.ip6_next */
        th.th_sport = htons(5432);
        th.th_dport = htons(6543);
        th.th_off = 5;
        th.th_flags |= (TH_SYN | TH_FIN);
        uh.uh_sport = htons(5432);
        uh.uh_dport = htons(6543);
        uh.uh_ulen = htons(8);
        icmph.icmp_type = ICMP_ECHO;
        icmph.icmp_id = 1234;
        icmph.icmp_seq = 7654;
        icmp6h.icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6h.icmp6_id = 2234;
        icmp6h.icmp6_seq = 8654;

        /* Set up pcap */
        if (2 != argc) {
                fprintf(stderr, "Usage: %s interface\n", argv[0]);
                return 1;
        }
        if (NULL == (p = pcap_open_live(argv[1], 65535, 0, 10, errbuf)))
                errx(1, "pcap_open_live: %s", errbuf);
        
        /* IPv4 / TCP */
        eh.ether_type = htons(ETHERTYPE_IP);
        i4h.ip_len = htons(sizeof(i4h) + sizeof(th));
        i4h.ip_p = IPPROTO_TCP;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i4h, sizeof(i4h), 
                        &th,  sizeof(th));

        /* IPv6 / TCP */
        eh.ether_type = htons(ETHERTYPE_IPV6);
        i6h.ip6_plen = htons(sizeof(th));
        i6h.ip6_nxt = IPPROTO_TCP;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i6h, sizeof(i6h), 
                        &th,  sizeof(th));

        /* IPv4 / UDP */
        eh.ether_type = htons(ETHERTYPE_IP);
        i4h.ip_len = htons(sizeof(i4h) + sizeof(uh));
        i4h.ip_p = IPPROTO_UDP;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i4h, sizeof(i4h), 
                        &uh,  sizeof(uh));

        /* IPv6 / UDP */
        eh.ether_type = htons(ETHERTYPE_IPV6);
        i6h.ip6_plen = htons(sizeof(uh));
        i6h.ip6_nxt = IPPROTO_UDP;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i6h, sizeof(i6h), 
                        &uh,  sizeof(uh));

        /* IPv4 / ICMP */
        eh.ether_type = htons(ETHERTYPE_IP);
        i4h.ip_len = htons(sizeof(i4h) + sizeof(icmph));
        i4h.ip_p = IPPROTO_ICMP;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i4h, sizeof(i4h), 
                        &icmph,  sizeof(icmph));
        
        /* IPv6 / ICMPv6 */
        eh.ether_type = htons(ETHERTYPE_IPV6);
        i6h.ip6_plen = htons(sizeof(icmp6h));
        i6h.ip6_nxt = IPPROTO_ICMPV6;
        inject(p, buf, sizeof(buf),
                        &eh,  sizeof(eh),
                        &i6h, sizeof(i6h), 
                        &icmp6h,  sizeof(icmp6h));

        return 0;
}

void
inject(pcap_t *p, uint8_t *buf, size_t len,
                const void *l2h, size_t l2hlen,
                const void *l3h, size_t l3hlen,
                const void *l4h, size_t l4hlen)
{
        size_t n;
        int ret;
        int i;

        /* Roll the packet */
        n = 0;
        bzero(buf, len);
        memcpy(buf, l2h, l2hlen);
        n += l2hlen;
        memcpy(buf + n, l3h, l3hlen);
        n += l3hlen;
        memcpy(buf + n, l4h, l4hlen);
        n += l4hlen;

        /* Calculate checksums */
        if (0 != (ret = packetchecksum_calculate(buf + l2hlen, n - l2hlen)))
                switch (ret) {
                        case PACKETCHECKSUM_TOOSHORT:
                                errx(4, "packet too short");
                        case PACKETCHECKSUM_INVALID:
                                errx(5, "invalid packet contents");
                        default:
                                errx(6, "unknown error");
                }

        /* Dump the packet we're about to send */
        for (i = 0; i < n; ++i)
                printf("%02x", buf[i]);
        printf("\n");

        /* Send it out */
        if (-1 == (ret = pcap_inject(p, buf, n)))
                errx(2, "pcap_inject: %s", pcap_geterr(p));
        if (n != ret)
                errx(3, "short send (%i < %lu)", ret, n);
}
