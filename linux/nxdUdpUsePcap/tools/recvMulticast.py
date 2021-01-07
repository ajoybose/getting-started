#!/usr/bin/env python3

import socket
import struct
import sys

multicast_group = '235.2.3.5'
server_address = ('', 56789)

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the server address
sock.bind(server_address)

# Tell the operating system to add the socket to the multicast group
# on all interfaces.
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

respNum = 0
# Receive/respond loop
while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(2048)
    
    print('received %s bytes from %s' % (len(data), address))
    print(data.decode())

    print('sending acknowledgement to', address)
    sock.sendto(str.encode('Acknowledgement {}\n\0'.format(respNum)), address)
    respNum += 1

    
