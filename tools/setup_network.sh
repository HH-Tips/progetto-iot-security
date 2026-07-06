#!/bin/bash
NET_INTERFACE=$(ip -br link show | grep -E '(en|eth)' | awk '{print $1}' | head -n1)
sudo ip addr add 192.168.1.100/24 dev $NET_INTERFACE
sudo ip link set $NET_INTERFACE up