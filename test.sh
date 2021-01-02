#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

ip_addr=10.0.0.10
port=4433

# nc -vz $ip_addr $port
printf "GET / HTTP/1.0\r\n\r\n" | nc -vN $ip_addr $port

printf "\n"

netstat -tanpo 2>/dev/null | grep "$ip_addr:$port"
