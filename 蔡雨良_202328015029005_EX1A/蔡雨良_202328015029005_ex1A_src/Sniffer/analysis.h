#pragma once
#include "protocol.h"

int analyse_data_frame(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ARP(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_IPv4(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_IPv6(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ICMPv4(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ICMPv6(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_TCP(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_UDP(const u_char *packet, struct data_packet *data, struct packet_count *count);


// MAC
int analyse_data_frame(const u_char *packet, struct data_packet *data, struct packet_count *count){
	struct eth_header *ethh = (struct eth_header*)packet;
	data->ethh = (struct eth_header*)malloc(sizeof(struct eth_header));
	if (data->ethh == NULL)
		return -1;
	count->num_sum++;
	data->ethh->type = ntohs(ethh->type);

	switch (data->ethh->type) {
		case PROTO_ARP://ARP
			return analyse_ARP((u_char*)packet + 14, data, count);
			break;
		case PROTO_IPV4://IPv4
			return analyse_IPv4((u_char*)packet + 14, data, count);
			break;
		case PROTO_IPV6://IPv6
			return analyse_IPv6((u_char*)packet + 14, data, count);
			break;
		default://Others
			count->num_other++;
			return -1;
	}
	return 1;
}

// ARP
int analyse_ARP(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct arp_header *arph = (struct arp_header*)packet;
	data->arph = (struct arp_header*)malloc(sizeof(struct arp_header));

	if (data->arph == NULL)
		return -1;

	strcpy(data->type, "ARP");

	count->num_arp++;
	return 1;
}

// IPv4
int analyse_IPv4(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct ipv4_header *iph = (struct ipv4_header*)packet;
	data->ip4h = (struct ipv4_header*)malloc(sizeof(struct ipv4_header));

	if (data->ip4h == NULL)
		return -1;

	data->ip4h->proto = iph->proto;

	count->num_ip4++;

	int iplen = iph->ihl * 4;
	switch (iph->proto) {
		case V4_PROTO_UDP:
			return analyse_UDP((u_char*)iph + iplen, data, count);
			break;
		case V4_PROTO_TCP:
			return analyse_TCP((u_char*)iph + iplen, data, count);
			break;
		case V4_PROTO_ICMP:
			return analyse_ICMPv4((u_char*)iph + iplen, data, count);
			break;
		default:
			return-1;
	}
	return 1;
}

// IPv6
int analyse_IPv6(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct ipv6_header *iph6 = (struct ipv6_header*)packet;
	data->ip6h = (struct ipv6_header*)malloc(sizeof(struct ipv6_header));

	if (data->ip6h == NULL)
		return -1;

	data->ip6h->next_head = iph6->next_head;
	
	count->num_ip6++;

	switch (iph6->next_head){
		case V6_PROTO_ICMPV6:
			return analyse_ICMPv6((u_char*)iph6 + 40, data, count);
			break;
		case V6_PROTO_UDP:
			return analyse_UDP((u_char*)iph6 + 40, data, count);
			break;
		case V6_PROTO_TCP:
			return analyse_TCP((u_char*)iph6 + 40, data, count);
			break;
		default:
			return-1;
	}
	return 1;
}

// ICMPv4
int analyse_ICMPv4(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct icmpv4_header* icmph = (struct icmpv4_header*)packet;
	data->icmp4h = (struct icmpv4_header*)malloc(sizeof(struct icmpv4_header));

	if (data->icmp4h == NULL)
		return -1;

	strcpy(data->type, "ICMP");

	count->num_icmp4++;
	return 1;
}

// ICMPv6
int analyse_ICMPv6(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct icmpv6_header* icmph6 = (struct icmpv6_header*)packet;
	data->icmp6h = (struct icmpv6_header*)malloc(sizeof(struct icmpv6_header));

	if (data->icmp6h == NULL)
		return -1;
	
	strcpy(data->type, "ICMPv6");

	count->num_icmp6++;
	return 1;
}

// TCP
int analyse_TCP(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct tcp_header *tcph = (struct tcp_header*)packet;
	data->tcph = (struct tcp_header*)malloc(sizeof(struct tcp_header));

	if (NULL == data->tcph)
		return -1;

	data->tcph->dest_port = ntohs(tcph->dest_port);
	data->tcph->src_port = ntohs(tcph->src_port);

	// HTTP
	if (ntohs(tcph->dest_port) == 80 || ntohs(tcph->src_port) == 80) {
		count->num_http++;
		strcpy(data->type, "HTTP");
	}
	else {
		count->num_tcp++;
		strcpy(data->type, "TCP");
	}
	return 1;
}

// UDP
int analyse_UDP(const u_char *packet, struct data_packet *data, struct packet_count *count) {
	struct udp_header* udph = (struct udp_header*)packet;
	data->udph = (struct udp_header*)malloc(sizeof(struct udp_header));
	
	if (NULL == data->udph)
		return -1;

	strcpy(data->type, "UDP");

	count->num_udp++;
	return 1;
}
