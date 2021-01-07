sudo ip link del veNet1Br
sudo ip link del veNet2Br
sudo ip link del veNet3Br
sudo ip link del veNet4Br
sudo ip link del brNET
sudo ip netns del net1
sudo ip netns del net2
sudo ip netns del net3
sudo ip netns del net4


sudo ip link add brNET type bridge
sudo ip link add veNet1 type veth peer name veNet1Br
sudo ip link add veNet2 type veth peer name veNet2Br
sudo ip link add veNet3 type veth peer name veNet3Br
sudo ip link add veNet4 type veth peer name veNet4Br
sudo ip link set veNet1Br master brNET
sudo ip link set veNet2Br master brNET
sudo ip link set veNet3Br master brNET
sudo ip link set veNet4Br master brNET

sudo ip netns add net1
sudo ip netns add net2
sudo ip netns add net3
sudo ip netns add net4

sudo ip link set veNet1 netns net1
sudo ip link set veNet2 netns net2
sudo ip link set veNet3 netns net3
sudo ip link set veNet4 netns net4

sudo ip netns exec net1 ip link set veNet1 address 32:32:32:32:01:01
sudo ip netns exec net1 ip addr add 192.168.4.1/24 dev veNet1
sudo ip netns exec net1 ip link set veNet1 up
sudo ip netns exec net1 ip link set lo up
sudo ip netns exec net1 ip route add 192.168.4.0/24 dev veNet1
sudo ip netns exec net1 ip route add default via 192.168.4.254

sudo ip netns exec net2 ip link set veNet2 address 32:32:32:32:02:02
sudo ip netns exec net2 ip addr add 192.168.4.2/24 dev veNet2
sudo ip netns exec net2 ip link set veNet2 up
sudo ip netns exec net2 ip link set lo up
sudo ip netns exec net2 ip route add 192.168.4.0/24 dev veNet2
sudo ip netns exec net2 ip route add default via 192.168.4.254

sudo ip netns exec net3 ip link set veNet3 address 32:32:32:32:03:03
sudo ip netns exec net3 ip addr add 192.168.4.3/24 dev veNet3
sudo ip netns exec net3 ip link set veNet3 up
sudo ip netns exec net3 ip link set lo up
sudo ip netns exec net3 ip route add 192.168.4.0/24 dev veNet3
sudo ip netns exec net3 ip route add default via 192.168.4.254

sudo ip netns exec net4 ip link set veNet4 address 32:32:32:32:04:04
sudo ip netns exec net4 ip addr add 192.168.4.4/24 dev veNet4
sudo ip netns exec net4 ip link set veNet4 up
sudo ip netns exec net4 ip link set lo up
sudo ip netns exec net4 ip route add 192.168.4.0/24 dev veNet4
sudo ip netns exec net4 ip route add default via 192.168.4.254

sudo ip link set veNet1Br up
sudo ip link set veNet2Br up
sudo ip link set veNet3Br up
sudo ip link set veNet4Br up
sudo ip addr add 192.168.4.254/24 brd + dev brNET
sudo ip link set brNET up


# sudo iptables -t nat -A POSTROUTING -s 192.168.44.254/24 -j MASQUERADE 
# sudo sysctl -w net.ipv4.ip_forward=1

