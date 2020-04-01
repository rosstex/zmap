/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing arbitrary UDP scans over IPv6

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_udp.h"

#define ICMP_UNREACH_HEADER_SIZE 8

static int num_ports;

probe_module_t module_ipv6_nmap_udp;

int ipv6_nmap_udp_global_initialize(struct state_conf *conf) {
	num_ports = conf->source_port_last - conf->source_port_first + 1;

	return EXIT_SUCCESS;
}

int ipv6_nmap_udp_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,\
		void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t payload_len = 308; // 8 UDP + 300 Payload. htons is called by make_ip6_header
	make_ip6_header(ipv6_header, IPPROTO_UDP, payload_len);

	struct udphdr *udp_header = (struct udphdr*)(&ipv6_header[1]);
	make_udp_header(udp_header, zconf.target_port, payload_len);

	char* payload = (char*)(&udp_header[1]);
	memset(payload, 0x43, 300);

	return EXIT_SUCCESS;
}

int ipv6_nmap_udp_make_packet(void *buf, UNUSED size_t *buf_len, __attribute__((unused)) ipaddr_n_t src_ip,
		__attribute__((unused)) ipaddr_n_t dst_ip, uint8_t ttl, uint32_t *validation, int probe_num, void *arg)
{
	// From module_ipv6_nmap_udp_dns
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip6_header[1];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	// ip_header->ip_id = htons(0x1042); doesn't exist in IPv6
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num, validation));

	udp_header->uh_sum = ipv6_udp_checksum(&ip6_header->ip6_src, &ip6_header->ip6_dst, udp_header);

	return EXIT_SUCCESS;
}

void ipv6_nmap_udp_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) &iph[1];
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void ipv6_nmap_udp_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
	uint32_t packet_size = ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ether_header);

	fs_add_binary(fs, "bitstring", packet_size, (void *) packet, 0);
    fs_add_bool(fs, "success", 1);
}


int ipv6_nmap_udp_validate_packet(const struct ip *ip_hdr, uint32_t len,
		UNUSED uint32_t *src_ip, uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;

	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected UDP header, i.e. IPv6 payload
		return 0;
	}
	if (!ipv6_udp_validate_packet(ipv6_hdr, len, NULL, validation)) {
		return 0;
	}
	return 1;
}

static fielddef_t fields[] = {
	{.name = "bitstring", .type= "binary", .desc = "bitstring of packet"},
	{.name = "sport", .type = "int", .desc = "UDP source port"},
	{.name = "dport", .type = "int", .desc = "UDP destination port"},
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
};

probe_module_t module_ipv6_nmap_udp = {
	.name = "ipv6_nmap_udp",
	.packet_length = 362, // 14 Ethernet, 40 IPv6, 8 UDP, 300 Payload
	.pcap_filter = "ip6 proto 17",
	.pcap_snaplen = 1500,
	.port_args = 1,
	.thread_initialize = &ipv6_nmap_udp_init_perthread,
	.global_initialize = &ipv6_nmap_udp_global_initialize,
	.make_packet = &ipv6_nmap_udp_make_packet,
	.print_packet = &ipv6_nmap_udp_print_packet,
	.validate_packet = &ipv6_nmap_udp_validate_packet,
	.process_packet = &ipv6_nmap_udp_process_packet,
	.close = NULL,
	.helptext = "Probe module that implements nmap closed port probes",
	.output_type = OUTPUT_TYPE_STATIC,
	.fields = fields,
	.numfields = 6};
