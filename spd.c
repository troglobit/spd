/* Very stupid packet dumper
 *
 * Copyright (c) 2020  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define __USE_MISC
#include <netinet/ip.h>		/* For struct ip */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef DEBUG
#define dbg printf
#else
#define dbg
#endif

void cb(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ether_header *ether = (struct ether_header *)packet;

	dbg("dhost: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
	    ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
	dbg(" type: %04x\n", ntohs(ether->ether_type));
	if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
		struct ip *ip = (struct ip *)(packet + sizeof(*ether));
		
		dbg("daddr: %s\n", inet_ntoa(ip->ip_dst));
		switch (ip->ip_p) {
		case IPPROTO_IGMP:
			putchar('i');
			break;
		case IPPROTO_ICMP:
			putchar('.');
			break;
		default:
			putchar(':');
			break;
		}
	} else
		putchar('_');
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		return 1;
	}

	p = pcap_open_offline(argv[1], errbuf);
	if (!p)
		errx(1, "Failed opening %s: %s", argv[1], errbuf);

	pcap_loop(p, -1, cb, NULL);
	putchar('\n');

	return 0;
}
