/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_icmp6_nmap_echo_2;

int icmp6_nmap_echo_2_global_initialize(struct state_conf *conf)
{
	// Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
	if (asprintf((char ** restrict) &module_icmp6_nmap_echo_2.pcap_filter, "%s && ip6 dst host %s", module_icmp6_nmap_echo_2.pcap_filter, conf->ipv6_source_ip) == -1) {
		return 1;
	}

	return EXIT_SUCCESS;
}

static int icmp6_nmap_echo_2_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);

    struct ip6_hdr *ip6_header = (struct ip6_hdr *) (&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len = sizeof(struct icmp6_hdr) + 8 + 150; // includes extra bits for validation
    make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(&ip6_header[1]);
	make_icmp6_header(icmp6_header);

	char *payload = (char *)(&icmp6_header[2]);
	memset(payload, 0x00, 150);

	return EXIT_SUCCESS;
}

static int icmp6_nmap_echo_2_make_packet(void *buf, UNUSED size_t *buf_len, UNUSED ipaddr_n_t src_ip,  UNUSED ipaddr_n_t dst_ip, uint8_t ttl, uint32_t *validation, UNUSED int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(&ip6_header[1]);
	
	// uint16_t icmp_idnum = validation[2] & 0xFFFF;

	// // Include validation in ICMPv6 payload data
	icmp6_header->icmp6_data32[1] = validation[0];
	icmp6_header->icmp6_data32[2] = validation[1];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	// icmp6_header->icmp6_id= icmp_idnum;


	icmp6_header->icmp6_id = htons(1000);
	icmp6_header->icmp6_seq = htons(296);

	// TODO: add sensible TOS value

	icmp6_header->icmp6_cksum = 0;
	icmp6_header->icmp6_cksum= (uint16_t) icmp6_checksum(
                &ip6_header->ip6_src,
		        &ip6_header->ip6_dst,
				icmp6_header,
				158
                );

	return EXIT_SUCCESS;
}

static void icmp6_nmap_echo_2_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*) (&iph[1]);

	fprintf(fp, "icmp { type: %u | code: %u "
			"| checksum: %#04X | id: %u | seq: %u }\n",
			icmp6_header->icmp6_type,
			icmp6_header->icmp6_code,
			ntohs(icmp6_header->icmp6_cksum),
			ntohs(icmp6_header->icmp6_id),
			ntohs(icmp6_header->icmp6_seq)
		);
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}


static int icmp6_validate_packet(const struct ip *ip_hdr,
		uint32_t len, __attribute__((unused)) uint32_t *src_ip, uint32_t *validation)
{
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr*) ip_hdr;

	if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
		return 0;
	}

    // IPv6 header is fixed length at 40 bytes + ICMPv6 header + 8 bytes of ICMPv6 data
	if ( ( sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 2 * sizeof(uint32_t)) > len) {
		// buffer not large enough to contain expected icmp header
		return 0;
	}

    // offset iphdr by ip header length of 40 bytes to shift pointer to ICMP6 header
	struct icmp6_hdr *icmp6_h = (struct icmp6_hdr *) (&ip6_hdr[1]);

	// validate icmp id
	if (ntohs(icmp6_h->icmp6_id) != 1000 || ntohs(icmp6_h->icmp6_seq) != 296)  {
		return 0;
	}

	if (icmp6_h->icmp6_data32[1] != validation[0] || icmp6_h->icmp6_data32[2] != validation[1]) {
		return 0;
	}

	return 1;
}

static void icmp6_nmap_echo_2_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation)
{
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
	uint32_t packet_size = ntohs(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ether_header);

	fs_add_binary(fs, "bitstring", packet_size, (void *) packet, 0);
    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
	{.name = "bitstring", .type = "binary", .desc = "bitstring of packet"},
	{.name="type", .type="int", .desc="icmp message type"},
	{.name="code", .type="int", .desc="icmp message sub type code"},
	{.name="icmp-id", .type="int", .desc="icmp id number"},
	{.name="seq", .type="int", .desc="icmp sequence number"},
    {.name="classification", .type="string", .desc="probe module classification"},
	{.name="success", .type="int", .desc="did probe module classify response as success"}
};


probe_module_t module_icmp6_nmap_echo_2 = {
	.name = "icmp6_nmap_echo_2",
	.packet_length = 220, // 
	.pcap_filter = "icmp6",
	.pcap_snaplen = 300, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
	.port_args = 1,
	.global_initialize = &icmp6_nmap_echo_2_global_initialize,
	.thread_initialize = &icmp6_nmap_echo_2_init_perthread,
	.make_packet = &icmp6_nmap_echo_2_make_packet,
	.print_packet = &icmp6_nmap_echo_2_print_packet,
	.process_packet = &icmp6_nmap_echo_2_process_packet,
	.validate_packet = &icmp6_validate_packet,
	.close = NULL,
	.output_type = OUTPUT_TYPE_STATIC,
	.fields = fields,
	.numfields = 7};

