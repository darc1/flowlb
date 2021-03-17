#!/bin/bash

DIR=$(dirname $0)
IFACE=$(cat $DIR/conf.yaml | yq -r ".interface")
sudo ip link set dev $IFACE mtu 3818
sudo ethtool -L $IFACE combined 1
sudo -E env "PATH=$PATH" go run $DIR $DIR/conf.yaml $DIR/mappings.yaml
