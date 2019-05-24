/*
 * packetchecksum.h
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

#ifndef HAVE_PACKETCHECKSUM_H
#define HAVE_PACKETCHECKSUM_H

/* The following can be returned by packetchecksum */
#define PACKETCHECKSUM_TOOSHORT 1 /* Not enough packet data */
#define PACKETCHECKSUM_INVALID  2 /* Packet had invalid or unsupported data */

/* packetchecksum calculates the checksums for the IP packet packet, which may
 * be an IPv4 or IPv6 packet.  If the packet contains a TCP or UDP payload,
 * its checksum will be calculated as well.  The packet's length is given in
 * len.  It returns 0 on success, 1 if packet contains invalid data, or any of
 * the PACKETCHECKSUM_* constansts. */
extern int packetchecksum_calculate(uint8_t *packet, size_t len);

/* Sorry for the long name.  One day we may have a packetchecksum_validate. */

#endif /* #ifdef HAVE_PACKETCHECKSUM_H */
