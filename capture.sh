#!/bin/bash

sudo tshark -V -f "udp && (ip dst 8.8.8.8 || ip src 8.8.8.8) " -P -o "ip.check_checksum:TRUE" -o "udp.check_checksum:TRUE" -o "tcp.check_checksum:TRUE" -w "/tmp/stuff.pcap" -F pcap
