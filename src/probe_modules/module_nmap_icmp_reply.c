/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP reply request (ping) scans

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

probe_module_t module_nmap_icmp_reply;

static int nmap_icmp_reply_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				    __attribute__((unused)) port_h_t dst_port,
				    __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(20 + 8 + 4);
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
	make_icmp_header(icmp_header);

	return EXIT_SUCCESS;
}

static int nmap_icmp_reply_make_packet(void *buf, UNUSED size_t *buf_len,
				 ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				 uint32_t *validation, UNUSED int probe_num,
				 UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
    uint32_t *pload = (uint32_t *)(icmp_header) + 2;

	uint16_t icmp_idnum = htons(999);
	uint16_t icmp_seqnum = htons(295);

	ip_header->ip_id = htons(100);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

    icmp_header->icmp_type = 0;
    icmp_header->icmp_code = 0;
	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_seq = icmp_seqnum;
    *pload = htonl(3345);

	icmp_header->icmp_cksum = 0;
	ip_header->ip_sum = 0;

	icmp_header->icmp_cksum = icmp_checksum((unsigned short *)icmp_header);
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static void nmap_icmp_reply_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct icmp *icmp_header = (struct icmp *)(&iph[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp_header->icmp_type, icmp_header->icmp_code,
		ntohs(icmp_header->icmp_cksum), ntohs(icmp_header->icmp_id),
		ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int icmp_validate_packet(const struct ip *ip_hdr, uint32_t len,
				uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	// check if buffer is large enough to contain expected icmp header
	if (((uint32_t)4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
		return 0;
	}

	struct icmp *icmp_h =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t icmp_idnum = icmp_h->icmp_id;
	uint16_t icmp_seqnum = icmp_h->icmp_seq;
	
	// validate icmp id and seqnum
	if (icmp_idnum != (validation[1] & 0xFFFF)) {
		return 0;
	}
	if (icmp_seqnum != (validation[2] & 0xFFFF)) {
		return 0;
	}
	return 1;
}

static void nmap_icmp_reply_process_packet(const u_char *packet,
				     __attribute__((unused)) uint32_t len,
				     fieldset_t *fs,
				     __attribute__((unused))
				     uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	uint32_t packet_size = htons(ip_hdr->ip_len) + sizeof(struct ether_header);
	fs_add_binary(fs, "bitstring", packet_size, (void *) packet, 0);
    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = "bitstring", .type = "binary", .desc = "bitstring of packet"},
	{.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp-id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "bool",
     .desc = "did probe module classify response as success"}};

probe_module_t module_nmap_icmp_reply = {.name = "nmap_icmp_reply",
				   .packet_length = 46,
				   .pcap_filter = "icmp",
				   .pcap_snaplen = 100,
				   .port_args = 0,
				   .thread_initialize =
				       &nmap_icmp_reply_init_perthread,
				   .make_packet = &nmap_icmp_reply_make_packet,
				   .print_packet = &nmap_icmp_reply_print_packet,
				   .process_packet = &nmap_icmp_reply_process_packet,
				   .validate_packet = &icmp_validate_packet,
				   .close = NULL,
				   .output_type = OUTPUT_TYPE_STATIC,
				   .fields = fields,
				   .numfields = 7};
