#ifndef PROTOCOL_H
#define PROTOCOL_H

#pragma once
#include "pcap.h"

#define PROTO_ARP 0x0806//ARP
#define PROTO_IPV4 0x0800//IPv4
#define PROTO_IPV6 0x86dd//IPv6

#define V4_PROTO_ICMP 1//ICMPv4
#define V4_PROTO_TCP 6//TCP
#define V4_PROTO_UDP 17//UDP

#define V6_PROTO_ICMPV6 0x3a//ICMPv6
#define V6_PROTO_TCP 0x06//TCP
#define V6_PROTO_UDP 0x11//UDP

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321

// MAC
struct eth_header {
	u_char dest[6];
	u_char src[6];
	u_short type;
};
// ARP
struct arp_header {
	u_short hard_type;
	u_short pro_type;
	u_char hard_len;
	u_char pro_len;
	u_short oper;
	u_char src_mac[6];
	u_char src_ip[4];
	u_char dest_mac[6];
	u_char dest_ip[4];
};
// IPv4
struct ipv4_header {
#if defined(LITTLE_ENDIAN)
	u_char ihl : 4;
	u_char version : 4;
#elif defined(BIG_ENDIAN)
	u_char version : 4;
	u_char  ihl : 4;
#endif
	u_char tos;
	u_short total_len;
	u_short id;
	u_short frag_off;
	u_char ttl;
	u_char proto;
	u_short check;
	u_int src_addr;
	u_int dest_addr;
	u_int opt;
};
// IPv6
struct ipv6_header {
	u_int version : 4,
		flowtype : 8,
		flowid : 20;
	u_short plen;
	u_char next_head;
	u_char hop_limit;
	u_short src_addr[8];
	u_short dest_addr[8];
};
// ICMPv4
struct icmpv4_header{
	u_char type;
	u_char code;
	u_char seq;
	u_char check;
};
// ICMPv6
struct icmpv6_header{
	u_char type;
	u_char code;
	u_char seq;
	u_char check;
	u_char op_type;
	u_char op_len;
	u_char op_eth_addr[6];
};
// UDP
struct udp_header {
	u_short sport;
	u_short dport;
	u_short len;
	u_short check;
};
// TCP
struct tcp_header {
	u_short src_port;
	u_short dest_port;
	u_int seq;
	u_int ack_seq;
#if defined(LITTLE_ENDIAN)
	u_short res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(BIG_ENDIAN)
	u_short doff : 4,
		res1 : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#endif
	u_short window;
	u_short check;
	u_short urg_ptr;
	u_int opt;
};
// Count
struct packet_count{
	int num_arp;//ARP
	int num_ip4;//IPv4
	int num_ip6;//IPv6
	int num_icmp4;//ICMPv4
	int num_icmp6;//ICMPv6
	int num_udp;//UDP
	int num_tcp;//TCP
	int num_http;//HTTP
	int num_other;
	int num_sum;
};
// Save
struct data_packet {
	char type[8];
	int time[6];
	int len;

	struct eth_header *ethh;//MAC

	struct arp_header *arph;//ARP
	struct ipv4_header *ip4h;//IPv4
	struct ipv6_header *ip6h;//IPv6

	struct icmpv4_header *icmp4h;//ICMPv4
	struct icmpv6_header *icmp6h;//ICMPv6
	struct udp_header *udph;//UDP
	struct tcp_header *tcph;//TCP
	void *apph;
};

#endif
