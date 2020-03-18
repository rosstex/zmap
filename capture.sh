#!/bin/bash

sudo tshark -V -f "src host fe80::1e69:7aff:fe60:7aa5" -P -o udp.check_checksum:TRUE -o tcp.check_checksum:TRUE