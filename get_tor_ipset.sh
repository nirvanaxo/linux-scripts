#!/usr/bin/env bash

ipset destroy tor

ipset -N tor iphash # create a new set named "tor"

# get the list, don't forget to put your service's IP in the query string
curl -s https://check.torproject.org/torbulkexitlist | sed '/^#/d' | while read IP
do
  # add each IP address to the set, silencing the warnings for IPs that have already been added
  ipset -q -A tor $IP
done
