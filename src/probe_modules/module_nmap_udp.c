/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for NMAP TCP nmap_udp probe

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

#define ICMP_UNREACH_HEADER_SIZE 8

probe_module_t module_nmap_udp;

static uint32_t num_ports;

void nmap_udp_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct udphdr *udph = (struct udphdr *)(&iph[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int nmap_udp_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;

	return EXIT_SUCCESS;
}

static int nmap_udp_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				  port_h_t dst_port,
				  __attribute__((unused)) void **arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t ip_len = htons(328);
	make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
	uint32_t len = 308;
	make_udp_header(udp_header, zconf.target_port, len);

    char *payload = (char *)(&udp_header[1]);
    memset(payload, 0x43, 300);

	return EXIT_SUCCESS;
}

static int nmap_udp_make_packet(void *buf, UNUSED size_t *buf_len,
			       ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
			       uint32_t *validation, int probe_num,
			       UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr *)&ip_header[1];

    ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_id = htons(0x1042);
	ip_header->ip_ttl = ttl;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num, validation));

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int nmap_udp_validate_packet(const struct ip *ip_hdr, UNUSED uint32_t len,
				   __attribute__((unused)) uint32_t *src_ip,
				   uint32_t *validation)
{
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp
			// header
			return PACKET_INVALID;
		}
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
		uint16_t sport = ntohs(udp->uh_dport);
		if (!check_dst_port(sport, num_ports, validation)) {
			return PACKET_INVALID;
		}
		// if (!blacklist_is_allowed(*src_ip)) {
		// 	return PACKET_INVALID;
		// }
	} else {
		return PACKET_INVALID;
	}

	return PACKET_VALID;
}

static void nmap_udp_process_packet(const u_char *packet,
				   __attribute__((unused)) uint32_t len,
				   fieldset_t *fs,
				   __attribute__((unused)) uint32_t *validation)

{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    uint32_t packet_size = htons(ip_hdr->ip_len) + sizeof(struct ether_header); // add ethernet bytes

    fs_add_binary(fs, "bitstring", packet_size, (void *) packet, 0);
    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = "bitstring", .type= "binary", .desc = "bitstring of packet"},
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"}};

probe_module_t module_nmap_udp = {
    .name = "nmap_udp",
    .packet_length = 342,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 1500,
    .port_args = 1,
    .global_initialize = &nmap_udp_global_initialize,
    .thread_initialize = &nmap_udp_init_perthread,
    .make_packet = &nmap_udp_make_packet,
    .print_packet = &nmap_udp_print_packet,
    .process_packet = &nmap_udp_process_packet,
    .validate_packet = &nmap_udp_validate_packet,
    .close = NULL,
    .helptext = "Probe module that implements nmap closed port probes",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = 6};
