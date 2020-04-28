#!/bin/bash

sudo tshark -V -f "icmp6" -P -o "ip.check_checksum:TRUE" -o "udp.check_checksum:TRUE" -o "tcp.check_checksum:TRUE" -w "/tmp/stuff.pcap" -F pcap
