PacketChecksum
==============
Will add checksums to a packet, for use with
[`pcap_inject`](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html).

Usage
-----
```c
uint8_t              packet[BUFLEN];
struct ether_header *eh;
struct ip           *ih;
struct tcphdr       *th;
pcap_t              *p = magic_pcap_init();
int ret;

/* Roll a packet */
eh = packet;
/* set Ethernet header things here */
ih = packet + sizeof(struct ether_header);
/* Set IP header things here */
th = packet + sizeof(struct ether_header) + sizeof(struct ip);
/* Set TCP header things here */

/* Calculate checksums */
switch (packetchecksum_calculate(packet, sizeof(packet))) {
case PACKETCHECKSUM_TOOSHORT:
        errx(1, "packet buffer too small");
case PACKETCHECKSUM_INVALID:
        errx(2, "packet contents invalid");
}

/* Send it out */
if (sizeof(packet) != (ret = pcap_inject(p, packet, sizeof(packet)))) {
        if (-1 == ret)
                errx(3, "pcap_inject: %s", pcap_geterr(p));
        else
                errx(4, "short write (%i < %i)", ret, sizeof(packet));
}
```
