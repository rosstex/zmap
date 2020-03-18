#!/bin/bash
./compile.sh
wait
sudo zmap -p 20023 -M $1 --ipv6-target-file=ipv6.txt --ipv6-source-ip=fe80::1e69:7aff:fe60:7aa5 --probe-args=$2