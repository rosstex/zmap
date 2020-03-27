/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for NMAP TCP nmap_tcp probe

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

probe_module_t module_nmap_tcp;

static char* packet_type = NULL;
static uint32_t num_ports;

void nmap_tcp_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct tcphdr *tcph = (struct tcphdr *)&iph[1];
	fprintf(fp,
		"source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
		ntohs(tcph->th_win), ntohs(tcph->th_dport),
		ntohl(tcph->th_seq), ntohs(tcph->th_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int nmap_tcp_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;

    if(state->probe_args)
    {
        char *probe_args = state->probe_args;
        if(strcmp(probe_args, "t5") == 0)
        {
            packet_type = strdup(probe_args);
        }
        else if(strcmp(probe_args, "t6") == 0)
        {
            packet_type = strdup(probe_args);
        }
        else if(strcmp(probe_args, "t7") == 0)
        {
            packet_type = strdup(probe_args);
        }
        else
        {
            printf("Invalid probe argument: options are: {t5 t6 t7}\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        packet_type = strdup("t5");
    }

	return EXIT_SUCCESS;
}

static int nmap_tcp_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				  port_h_t dst_port,
				  __attribute__((unused)) void **arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t ip_len = htons(60);
	make_ip_header(ip_header, IPPROTO_TCP, ip_len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

static int nmap_tcp_make_packet(void *buf, UNUSED size_t *buf_len,
			       ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
			       uint32_t *validation, int probe_num,
			       UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    void *tcp_options = (void *)(&tcp_header[1]);
	uint32_t tcp_seq = validation[0];
    uint8_t *tcp_opts;

    ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = 100;
	tcp_header->th_sum = 0;
    tcp_header->th_off = 10;

    if(strcmp(packet_type, "t5") == 0)
    {
        tcp_opts = (uint8_t *) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x04\x02";
        tcp_header->th_win = htons(31337);
        tcp_header->th_flags = TH_SYN;
    }
    else if(strcmp(packet_type, "t6") == 0)
    {
        tcp_opts = (uint8_t *) "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x04\x02";
        tcp_header->th_win = htons(32768);
        ip_header->ip_off = htons(IP_DF);
        tcp_header->th_flags = TH_ACK;
    }
    else
    {
        tcp_opts = (uint8_t *) "\x03\x03\x0F\x01\x02\x04\x01\x09\x08\x0A\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x04\x02";
        tcp_header->th_win = htons(65535);
        tcp_header->th_flags = (TH_FIN | TH_PUSH | TH_URG);
    }

    // set tcp options
    memcpy(tcp_options, tcp_opts, 20);

	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr) + sizeof(uint8_t) * 20, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int nmap_tcp_validate_packet(const struct ip *ip_hdr, UNUSED uint32_t len,
				   __attribute__((unused)) uint32_t *src_ip,
				   uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return 0;
	}
    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
		// buffer not large enough to contain expected tcp header
		return 0;
	}
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t sport = tcp->th_sport;
	uint16_t dport = tcp->th_dport;

    // validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}

	return 1;
}

static void nmap_tcp_process_packet(const u_char *packet,
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

probe_module_t module_nmap_tcp = {
    .name = "nmap_tcp",
    .packet_length = 74,
    .pcap_filter = "tcp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &nmap_tcp_global_initialize,
    .thread_initialize = &nmap_tcp_init_perthread,
    .make_packet = &nmap_tcp_make_packet,
    .print_packet = &nmap_tcp_print_packet,
    .process_packet = &nmap_tcp_process_packet,
    .validate_packet = &nmap_tcp_validate_packet,
    .close = NULL,
    .helptext = "Probe module that implements nmap closed port probes",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = 6};
