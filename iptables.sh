#!/usr/bin/env bash

# NetFilterQueue Rules
sudo iptables -A INPUT -m conntrack --ctstate NEW,RELATED,INVALID -j NFQUEUE --queue-num=0
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

sudo iptables -A OUTPUT -m conntrack --ctstate NEW,RELATED,INVALID -j NFQUEUE --queue-num=0
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

sudo iptables -A FORWARD -m conntrack --ctstate NEW,RELATED,INVALID -j NFQUEUE --queue-num=0
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED -j ACCEPT
