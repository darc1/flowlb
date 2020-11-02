#!/bin/bash
IFACE=ens5
sudo ip link set dev $IFACE mtu 3818
sudo ethtool -L $IFACE combined 1
~/go/bin/go-bindata assets/ && sudo -E env "PATH=$PATH" go run .
