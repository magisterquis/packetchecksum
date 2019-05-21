/*
 * packetchecksum.c
 * Calculate IP/TCP/UDP checksums
 * By J. Stuart McMurray
 * Created 20190520
 * Last Modified 20190520
 */

/*
Copyright (c) 2019, J. Stuart McMurray
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the the copyright holder nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL J. STUART McMURRAY BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <string.h>

#include "packetchecksum.h"

/* Various offsets and such, to avoid depending on netinet structs. */
#define IPv6NEXTHEADER 6
#define IPv4CSUMOFF    10

static int ipv4_calculate_checksum(uint8_t *packet, size_t len, int *hlen);
static int tcp_calculate_checksum(uint8_t ipv, const void *iph,
                struct tcphdr *tp, int length);
static int udp_calculate_checksum(uint8_t ipv, const void *iph,
                struct udphdr *uh, int length);
static uint16_t in_cksum(const void *addr, size_t len, uint32_t sum);
static uint16_t tcp_cksum(const struct ip *ip, const struct tcphdr *tp,
                int len);
static uint16_t tcp6_cksum(const struct ip6_hdr *ip6, const struct tcphdr *tp,
                u_int len);
static uint32_t in_cksum_add(const void *buf, size_t len, uint32_t sum);

int
packetchecksum_calculate(uint8_t *packet, size_t len)
{
        int ret, hlen;
        uint8_t ipv, l4p;
        void *l4; /* Start of l4 header */

        /* Calculate L3 checksum, get L4 type, get start of L4 header, and
         * shrink len by the size of the L3 header. */
        switch (ipv = *packet >> 4) {
                case 4:
                        if (0 != (ret = ipv4_calculate_checksum(packet, len,
                                                        &hlen)))
                                return ret;
                        /* No length check, as ipv4_calculate_checksum did it
                         * for us. */
                        l4p = ((struct ip *)packet)->ip_p;
                        l4 = packet + hlen;
                        len -= hlen;
                        break;
                case 6:
                        /* No checksum here */
                        if (sizeof(struct ip6_hdr) >= len)
                                return PACKETCHECKSUM_TOOSHORT;
                        l4p = ((struct ip6_hdr *)packet)->ip6_nxt;
                        l4 = packet + sizeof(struct ip6_hdr);
                        len -= sizeof(struct ip6_hdr);
                        break;
                default:
                        /* We don't support this IP version */
                        return PACKETCHECKSUM_INVALID;
        }

        /* If we're out of packet we're just sending a bare IP header */
        if (0 == len)
                return 0;

        /* Calculate L4 checksum */
        switch (l4p) {
                case IPPROTO_TCP:
                        return tcp_calculate_checksum(ipv, packet,
                                        (struct tcphdr *)l4, len); 
                case IPPROTO_UDP:
                        return udp_calculate_checksum(ipv, packet,
                                        (struct udphdr *)l4, len);
                default:
                        /* Not having a supported type isn't an error.  We
                         * simply don't calculate the checksum. */
                        return 0;
        }
}

/* ipv4_calculate_checksum updates packet, which is assumed to point to an IPv4
 * header with the proper checksum. */
static int
ipv4_calculate_checksum(uint8_t *packet, size_t len, int *hlen)
{
        uint16_t sum;

        /* Make sure we have a full header */
        if (sizeof(struct ip) > len)
                return PACKETCHECKSUM_TOOSHORT;

        /* Only use as much packet as we've IPv4 header */
        if (len <= (*hlen = (4 * (*packet & 0x0F))))
                return PACKETCHECKSUM_TOOSHORT;

        /* Zero out the checksum field, for calculating */
        *(uint16_t *)(packet + IPv4CSUMOFF) = 0;

        /* Calculate the checksum and update the packet */
        sum = in_cksum(packet, *hlen, 0);
        *(uint16_t *)(packet + IPv4CSUMOFF) = sum;

        return 0;
}

/* tcp_calculate_checksum calculates the checksum for the len bytes at tp and
 * updates the checksum in tp. iph will be interpreted as either an IPv6 or
 * IPv6 header based on ipv. */
static int
tcp_calculate_checksum(uint8_t ipv, const void *iph, struct tcphdr *tp,
                int length)
{
        /* Validate length */
        if (4 * tp->th_off >= length)
                return PACKETCHECKSUM_TOOSHORT;

        /* Zero checksum field */
        tp->th_sum = 0;

        /* Calculate the checksum */
        switch (ipv) {
                case 4:
                        tp->th_sum = tcp_cksum((struct ip *)iph, tp, length);
                        break;
                case 6:
                        tp->th_sum = tcp6_cksum((struct ip6_hdr *)iph, tp,
                                        length);
                        break;
        }

        return 0;
}

/* udp_calculate_checksum is the UDP analogue to tcp_calculate_checksum */
static int
udp_calculate_checksum(uint8_t ipv, const void *iph, struct udphdr *up,
                int length)
{
/* Nearly all of the code in this function was copy/pasted from OpenBSD's
 * tcpdump which is released under the following license: */

/*	$OpenBSD: print-udp.c,v 1.51 2018/10/22 16:12:45 kn Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

        const struct ip *ip4;
        const struct ip6_hdr *ip6;
        const u_char *cp;
        uint32_t cksum = 0;

        /* Validate length */
        if (sizeof(*up) >= length)
                return PACKETCHECKSUM_TOOSHORT;

        /* Add IP pseudoheader to checksum */
        switch (ipv) {
                case 6:
                        ip6 = iph;
			cksum = in_cksum_add(&ip6->ip6_src,
                                        sizeof(ip6->ip6_src), cksum);
			cksum = in_cksum_add(&ip6->ip6_dst,
                                        sizeof(ip6->ip6_dst), cksum);
			break;
		case 4:
                        ip4 = iph;
			cksum = in_cksum_add(&ip4->ip_src,
                                        sizeof(ip4->ip_src), cksum);
			cksum = in_cksum_add(&ip4->ip_dst,
                                        sizeof(ip4->ip_dst), cksum);
			break;
        }
        cksum += htons(length);
	cksum += htons(IPPROTO_UDP);

        /* Add UDP header to checksum */
        cksum += up->uh_sport;
        cksum += up->uh_dport;
        cksum += up->uh_ulen;

        /* Add rest of packet */
        cp = (const u_char *)(up + 1);
        length -= sizeof(*up);
        up->uh_sum = in_cksum(cp, length, cksum);

        return 0;
}

/* The below from OpenBSD */

/*	$OpenBSD: in_cksum.c,v 1.2 2018/07/06 04:49:21 dlg Exp $	*/

/*
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */

/* #include <sys/types.h> */ /* DEBUG */

/* #include "interface.h" */ /* DEBUG */

static uint32_t
in_cksum_add(const void *buf, size_t len, uint32_t sum)
{
	const uint16_t *words = buf;

	while (len > 1) {
		sum += *words++;
		len -= sizeof(*words);
	}

	if (len == 1) {
		uint8_t byte = *(const uint8_t *)words;
		sum += htons(byte << 8);
	}

	return (sum);
}

static uint16_t
in_cksum_fini(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */

	return (~sum);
}

/*
 * compute an IP header checksum.
 * don't modifiy the packet.
 */
static uint16_t
in_cksum(const void *addr, size_t len, uint32_t sum)
{
	return (in_cksum_fini(in_cksum_add(addr, len, sum)));
}

/*	$OpenBSD: print-tcp.c,v 1.38 2018/10/22 16:12:45 kn Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

static uint16_t
tcp_cksum(const struct ip *ip, const struct tcphdr *tp, int len)
{
	union phu {
		struct phdr {
			u_int32_t src;
			u_int32_t dst;
			u_char mbz;
			u_char proto;
			u_int16_t len;
		} ph;
		u_int16_t pa[6];
	} phu;
	const u_int16_t *sp;
	u_int32_t sum;

	/* pseudo-header.. */
	phu.ph.len = htons((u_int16_t)len);
	phu.ph.mbz = 0;
	phu.ph.proto = IPPROTO_TCP;
	memcpy(&phu.ph.src, &ip->ip_src.s_addr, sizeof(u_int32_t));
	memcpy(&phu.ph.dst, &ip->ip_dst.s_addr, sizeof(u_int32_t));

	sp = &phu.pa[0];
	sum = sp[0]+sp[1]+sp[2]+sp[3]+sp[4]+sp[5];

	return in_cksum((u_short *)tp, len, sum);
}

static uint16_t
tcp6_cksum(const struct ip6_hdr *ip6, const struct tcphdr *tp, u_int len)
{
	union {
		struct {
			struct in6_addr ph_src;
			struct in6_addr ph_dst;
			u_int32_t       ph_len;
			u_int8_t        ph_zero[3];
			u_int8_t        ph_nxt;
		} ph;
		u_int16_t pa[20];
	} phu;
	size_t i;
	u_int32_t sum = 0;

	/* pseudo-header */
	memset(&phu, 0, sizeof(phu));
	phu.ph.ph_src = ip6->ip6_src;
	phu.ph.ph_dst = ip6->ip6_dst;
	phu.ph.ph_len = htonl(len);
	phu.ph.ph_nxt = IPPROTO_TCP;

	for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
		sum += phu.pa[i];

	return in_cksum((u_short *)tp, len, sum);
}

/* TODO: Note we don't support IPv6 extension headers */
