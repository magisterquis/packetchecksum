PacketChecksum
==============
Simple library to add layer-3 and layer-4 checksums to an IP packet.
Originally designed to make using
[`pcap_inject`](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html) a bit
easier.

Currently supports:
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ICMPv6

Quite a bit of the source was taken from OpenBSD's
[tcpdump](https://github.com/openbsd/src/tree/master/usr.sbin/tcpdump).

Usage
-----
There is currently one function in this library, `packetchecksum_calculate()`.
It expects two arguments: a pointer to the start of the Layer-3 header and the
total length of the packet.  Upon return the layer-3 and layer-4 checksum
fields will be populated.

Compiling into a project should be as simple as dropping the source and header
files in with the rest of the project's source.

Example:
```c
uint8_t              packet[BUFLEN];
struct ether_header *eh;
struct ip           *ih;
struct tcphdr       *th;
pcap_t              *p = magic_pcap_init();
int ret;

bzero(packet, sizeof(packet));

/* Roll a packet */
eh = packet;
/* set Ethernet header things here */
ih = packet + sizeof(struct ether_header);
/* Set IP header things here */
th = packet + sizeof(struct ether_header) + sizeof(struct ip);
/* Set TCP header things here */

/* Calculate checksums */
switch (packetchecksum_calculate(packet, sizeof(packet))) { /* <-- This */
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

A more complete example can be found in [`example.c`](./example/example.c).

IPv6
----
While the IPv6 header itself doesn't have a checksum field, skipping past the
optional headers isn't quite as straightforward as one would like.  In general
this should work pretty well except for the ESP optional header.
