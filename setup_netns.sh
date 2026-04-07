#!/bin/sh
# This script injects "routing rules" into the Docker netns (not exactly the gVisor env !)
# to route DNS request to the Docker DNS
set -e

GATEWAY_IP="$1"
CONTAINER_IP="$2"
CONTAINER_MAC="$3"

if [ -z "$GATEWAY_IP" ] || [ -z "$CONTAINER_IP" ] || [ -z "$CONTAINER_MAC" ]; then
  echo "Usage: $0 <gateway_ip> <container_ip> <container_mac>" >&2
  exit 1
fi

IFACE="$(ip -j link show | jq -r --arg mac "$CONTAINER_MAC" '.[] | select((.address | ascii_downcase) == ($mac | ascii_downcase)) | .ifname' | head -n1)"
if [ -z "$IFACE" ] || [ "$IFACE" = "null" ]; then
  echo "Could not find interface for container MAC $CONTAINER_MAC" >&2
  exit 1
fi

tc qdisc add dev "$IFACE" clsact || true
tc qdisc add dev lo clsact || true

DOCKER_DNS_PORT=$(ss -lun | awk 'NR>1 {split($4, a, ":"); print a[2]}')

# Setup route to Docker DNS:
# - Only match DNS packets going to the host
# - Write src and dst IPs (src is a special IP that we can match on the way back, dst is the loopback IP)
# - "ptype host pipe" seems needed when multiple networks are attached to the container
# edit - NOPE
# - Docker OUTPUT table will not be used, so rewrite the port ourselves
# Simulate packets coming from lo
tc filter del dev "$IFACE" ingress
tc filter del dev "$IFACE" egress
tc filter replace dev "$IFACE" egress protocol ip pref 49152 flower \
  dst_ip "$GATEWAY_IP" \
  ip_proto udp \
  dst_port 53 \
  action pedit ex munge ip src set 127.0.0.12 pipe \
  action pedit ex munge ip dst set 127.0.0.11 pipe \
  action pedit ex munge udp dport set $DOCKER_DNS_PORT pipe \
  action csum ip and udp pipe \
  action mirred ingress redirect dev lo

# Get mac of ns interface (same as mac of gVisor)
NS_MAC="$(ip -j link show "$IFACE" | jq -r '.[].address')"

# Setup route from Docker DNS back to gVisor
# We only match responses by matching our dummy 127.0.0.12 address
# We also setup container L3 addresses (normal) and L2 dst address (since this ns doesnt get hit by ARP responses)
# L2 src address doesnt seem to be needed, and is difficult to query (need host ns help), so unset
tc filter del dev lo ingress
tc filter del dev lo egress
tc filter replace dev lo egress protocol ip pref 49152 flower \
  dst_ip 127.0.0.12 \
  ip_proto udp \
  src_port $DOCKER_DNS_PORT \
  action pedit ex munge ip src set "$GATEWAY_IP" pipe \
  action pedit ex munge ip dst set "$CONTAINER_IP" pipe \
  action pedit ex munge eth dst set $NS_MAC pipe \
  action pedit ex munge udp sport set 53 pipe \
  action csum ip and udp pipe \
  action mirred ingress redirect dev "$IFACE"

# Allow 127.0.0.11 in this netns to be routed from TC mirred packets (they don't count as locally generated)
sysctl -w net.ipv4.conf.all.route_localnet=1

# Remove source interface checks since tc is spoofing the packets source
echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
