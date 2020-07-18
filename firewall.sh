
INTERFACE="`route | grep '^default' | grep -o '[^ ]*$'`"

ipset destroy tor

ipset -N tor iphash # create a new set named "tor"

# get the list, don't forget to put your service's IP in the query string
curl -s https://check.torproject.org/torbulkexitlist | sed '/^#/d' | while read IP
do
  # add each IP address to the set, silencing the warnings for IPs that have already been added
  ipset -q -A tor $IP
done
echo "Built IP-Set of all known TOR exit nodes. In future can block all of TOR or severely rate limit it so discourage TOR abuse/TOR attacks"
INTERFACE="`route | grep '^default' | grep -o '[^ ]*$'`"

sudo iptables --flush
sudo iptables -X RATE-LIMIT-IRC
sudo iptables -X RATE-LIMIT-WEB
sudo iptables -X RATE-LIMIT-TOR


sudo iptables --new-chain RATE-LIMIT-IRC
sudo iptables --append RATE-LIMIT-IRC \
  --match hashlimit \
  --hashlimit-mode srcip \
  --hashlimit-upto 12/min \
  --hashlimit-burst 10 \
  --hashlimit-name conn_rate_limit_irc \
  --jump ACCEPT

sudo iptables --append RATE-LIMIT-IRC --jump DROP

sudo iptables --append INPUT -p tcp -m multiport --dports 6665:6669,6697,7000,9998,9999 -i ${INTERFACE} --match conntrack --ctstate NEW --jump RATE-LIMIT-IRC


sudo iptables --new-chain RATE-LIMIT-WEB
sudo iptables --append  RATE-LIMIT-WEB \
  --match hashlimit \
  --hashlimit-mode srcip \
  --hashlimit-upto 50/min \
  --hashlimit-burst 20 \
  --hashlimit-name conn_rate_limit_web \
  --jump ACCEPT

sudo iptables --append RATE-LIMIT-WEB --jump DROP

sudo iptables --append INPUT -p tcp -m multiport --dports 80,443 -i ${INTERFACE} --match conntrack --ctstate NEW --jump RATE-LIMIT-WEB

echo "Added rate limiting to IRC and WEB ports for interface: ${INTERFACE} on `hostname`"



sudo iptables --new-chain RATE-LIMIT-TOR
sudo iptables --append RATE-LIMIT-TOR \
  --match hashlimit \
  --hashlimit-upto 2/hour \
  --hashlimit-burst 1 \
  --hashlimit-name conn_rate_limit_tor \
  --jump ACCEPT

sudo iptables --append RATE-LIMIT-TOR --jump DROP

#sudo iptables -I INPUT -m set --match-set tor src -i ${INTERFACE} --match conntrack --ctstate NEW --jump RATE-LIMIT-TOR
sudo iptables -I INPUT -p tcp -m multiport --dports 6665:6669,6697,7000,9998,9999 -m set --match-set tor src -i ${INTERFACE} --match conntrack --ctstate NEW --jump RATE-LIMIT-TOR

echo "Added rate limiting for TOR exit nodes for interface: ${INTERFACE} on `hostname`"



sudo iptables -A INPUT -p icmp -i ${INTERFACE} \
  --match hashlimit \
  --hashlimit-name rate_limit_icmp \
  --hashlimit-mode srcip \
  --hashlimit-srcmask 32 \
  --hashlimit-above 10/hour \
  --hashlimit-burst 1 \
  --hashlimit-htable-expire 30000 \
  --jump DROP

echo "Added rate limiting for ICMP packets for interface: ${INTERFACE} on `hostname`"
### Drop invalid packets ###
sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

### Drop TCP packets that are new and are not SYN ###
sudo iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

### Drop SYN packets with suspicious MSS value ###
sudo iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

### Block packets with bogus TCP flags ###
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

### 5: Block spoofed packets ###
sudo iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
sudo iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
sudo iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
sudo iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
sudo iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
sudo iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
sudo iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
sudo iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
sudo iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP


### Drop fragments in all chains ###
sudo iptables -t mangle -A PREROUTING -f -j DROP

### Limit connections per source IP ###
sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset

### Limit RST packets ###
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

### Limit new TCP connections per second per source IP ###
sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP


### SSH brute-force protection ###
sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

### Protection against port scanning ###
sudo iptables -N port-scanning
sudo iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
sudo iptables -A port-scanning -j DROP

