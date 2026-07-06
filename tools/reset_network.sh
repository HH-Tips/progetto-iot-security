#!/bin/bash
NET_INTERFACE=$(ip -br link show | grep -E '(en|eth)' | awk '{print $1}' | head -n1)
ip addr del 192.168.1.100/24 dev $NET_INTERFACE