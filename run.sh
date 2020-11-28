#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

iface_prefix="tun_tit"

cargo b --release

target=${CARGO_TARGET_DIR:="target"}

sudo setcap cap_net_admin=eip "$target"/release/tit
"$target"/release/tit &
pid=$!

trap 'kill $pid' INT TERM ERR

iface_name=""
until [ -n "$iface_name" ]
do
  iface_name=$(ip tuntap list 2>/dev/null | { grep ${iface_prefix} || true; } | cut -d: -f1)
  sleep 1
done

sudo ip addr add 10.0.0.0/24 dev "$iface_name"
sudo ip link set up dev "$iface_name"
wait $pid
