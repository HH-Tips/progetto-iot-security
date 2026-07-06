#!/bin/bash
NET_INTERFACE=$(ip -br link show | grep -E '(en|eth)' | awk '{print $1}' | head -n1)
sudo nmcli dev disconnect enp3s0 && sudo nmcli dev connect enp3s0