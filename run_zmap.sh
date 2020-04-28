#!/bin/bash
./compile.sh
wait

case $1 in
  4) sudo zmap -O csv -p 20023 -M $2 --whitelist-file=ipv4.txt -f saddr,bitstring -r 50000 --probe-args=$3;;
  6) sudo zmap -p 20023 -M $2 --ipv6-target-file=ipv6.txt --ipv6-source-ip=fe80::1e69:7aff:fe60:7aa5 --probe-args=$3;;
  *) echo "Please begin your command with '4' or '6'" && exit;;
esac
