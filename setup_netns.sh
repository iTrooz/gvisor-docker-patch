#!/bin/sh
# This script injects "routing rules" into the Docker netns (not exactly the gVisor env !)
# to route DNS request to the Docker DNS
set -e

GATEWAY_IP="$1"
CONTAINER_IP="$2"

if [ -z "$GATEWAY_IP" ] || [ -z "$CONTAINER_IP" ]; then
  echo "Usage: $0 <gateway_ip> <container_ip>" >&2
  exit 1
fi

tc qdisc add dev eth0 clsact || true
tc qdisc add dev lo clsact || true

DOCKER_DNS_PORT=$(ss -lun | awk 'NR>1 {split($4, a, ":"); print a[2]}')

# Setup route to Docker DNS:
# - Only match DNS packets going to the host
# - Write src and dst IPs (src is a special IP that we can match on the way back, dst is the loopback IP)
# - Docker OUTPUT table will not be used, so rewrite the port ourselves
# Simulate packets coming from lo
tc filter del dev eth0 ingress
tc filter del dev eth0 egress
tc filter replace dev eth0 egress protocol ip pref 49152 flower \
  dst_ip "$GATEWAY_IP" \
  ip_proto udp \
  dst_port 53 \
  action pedit ex munge ip src set 127.0.0.12 pipe \
  action pedit ex munge ip dst set 127.0.0.11 pipe \
  action pedit ex munge udp dport set $DOCKER_DNS_PORT pipe \
  action csum ip and udp pipe \
  action skbedit ptype host pipe \
  action mirred ingress redirect dev lo

# Get mac of ns interface (same as mac of gVisor)
NS_MAC="$(ip -j link show eth0 | jq -r '.[].address')"

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
  action mirred ingress redirect dev eth0

# Allow 127.0.0.11 in this netns to be routed from TC mirred packets (they don't count as locally generated)
sysctl -w net.ipv4.conf.all.route_localnet=1

echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
