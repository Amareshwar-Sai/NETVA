#!/bin/bash
# default.sh — Realistic enterprise firewall ruleset
#
# Default DROP between zones with one specific allow rule.
# Represents a properly-segmented network where DMZ→Internal traffic
# is restricted to a single trusted application path.

set -e

echo "[firewall] Loading strict zone-segmentation rules..."

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X 2>/dev/null || true

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Allow established/related connections back through
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Intra-zone traffic — same subnet hosts can communicate freely
iptables -A FORWARD -s 10.10.0.0/24 -d 10.10.0.0/24 -j ACCEPT
iptables -A FORWARD -s 10.20.0.0/24 -d 10.20.0.0/24 -j ACCEPT

# CRITICAL CROSS-ZONE RULE: appserver → database on MySQL port only.
# This is the one legitimate business path between DMZ and internal.
# It's also the path an attacker on appserver could abuse.
iptables -A FORWARD -s 10.10.0.20 -d 10.20.0.20 -p tcp --dport 3306 -j ACCEPT

# NAT for outbound traffic (so containers can reach internet via host)
iptables -t nat -A POSTROUTING -j MASQUERADE

# Log dropped FORWARD attempts (visible via docker logs lab_firewall)
iptables -A FORWARD -j LOG --log-prefix "[FW-DROP] " --log-level 4

# Final default DROP (redundant with policy but explicit)
iptables -A FORWARD -j DROP

echo "[firewall] Strict zone segmentation active"
echo "[firewall] Allowed cross-zone path: 10.10.0.20 (appserver) -> 10.20.0.20:3306 (database)"
echo "[firewall] All other DMZ <-> Internal traffic: DROPPED"