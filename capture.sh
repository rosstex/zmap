#!/bin/bash

sudo tshark -V -f "(src host fe80::1e69:7aff:fe60:7aa5) || (src host 1.1.1.1)" -P -o "ip.check_checksum:TRUE" -o "udp.check_checksum:TRUE" -o "tcp.check_checksum:TRUE"