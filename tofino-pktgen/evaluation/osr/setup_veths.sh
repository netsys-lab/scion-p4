#! /bin/bash

sudo ip netns add source
sudo ip netns add dest
sudo ip link add veth0 type veth peer name veth1 netns source
sudo ip link add veth2 type veth peer name veth3 netns dest

sudo ip addr add 10.1.4.1/24 dev veth0
sudo ip netns exec source ip addr add 10.1.4.2/24 dev veth1

sudo ip addr add 10.1.5.1/24 dev veth2
sudo ip netns exec dest ip addr add 10.1.5.2/24 dev veth3

sudo ip link set veth0 up
sudo ip netns exec source ip link set veth1 up
sudo ip link set veth2 up
sudo ip netns exec dest ip link set veth3 up
sudo ip netns exec source ip link set lo up
sudo ip netns exec dest ip link set lo up
