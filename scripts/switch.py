#!/usr/bin/python
'''
Author: Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Software switch used for comparison to P4 equivalent.
'''
from scapy.all import sniff as scasniff, Ether, ARP, TCP, sendp, IP, ICMP

import argparse
import binascii
import socket
import struct
import sys
import threading

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Run decoy switch')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
parser.add_argument('-proxy-ip', action='store', type=str, required=True,
                    help='Decoy proxy IP address')
parser.add_argument('-proxy-port', action='store', type=str, required=True,
                    help='Decoy proxy TCP port')
args = parser.parse_args()
glock = threading.Lock()

# Global variables
ip_to_mac = {
    '10.0.0.1': '00:00:00:00:00:01',
    '10.0.0.2': '00:00:00:00:00:02',
    '10.0.0.3': '00:00:00:00:00:03',
    '10.0.0.4': '00:00:00:00:00:04',
}
mac_to_intf = {
    '00:00:00:00:00:01': 's1-eth0',
    '00:00:00:00:00:02': 's1-eth1',
    '00:00:00:00:00:03': 's1-eth2',
    '00:00:00:00:00:04': 's1-eth3',
}

PROXY_IP = '10.0.0.2'
PROXY_PORT = 8888

SYN_FLAGS = 0x2
ETHER_HEADER_LEN = 14

# Dictionary used to determine whether a flow is using decoy switching. The
# keys for this dict are tuples containing srcIp, srcPort, dstIp, and dstPort,
# and it is used to map from client to proxy and from proxy to client.
flows_l = threading.Lock()
outbound_flows = {}
inbound_flows = {}


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if args.verbose:
        glock.acquire()
        sys.stdout.write(s)
        sys.stdout.flush()
        glock.release()


def calculate_tag(pkt):
    '''
    Given a packet, calculate what its tag should be and return it.
    '''
    saddr = struct.unpack('!L', socket.inet_aton(pkt[IP].src))[0]
    daddr = struct.unpack('!L', socket.inet_aton(pkt[IP].dst))[0]
    vals = (
        ('!I', saddr),
        ('!I', daddr),
        ('!B', pkt[IP].proto),
        ('!H', pkt[TCP].sport),
        ('!H', pkt[TCP].dport),
        ('!H', pkt[TCP].window),
    )
    crc = 0
    for i in range(len(vals)):
        bval = struct.pack(vals[i][0], vals[i][1])
        crc = binascii.crc32(bval, crc) & 0xffffffff

    return crc


def handle_tcp(pkt):
    '''
    Handle packet containing TCP headers.
    '''
    if pkt[TCP].flags == SYN_FLAGS:
        # SYN packet. Check for tagging
        seq = pkt[TCP].seq
        tag = calculate_tag(pkt)

        if tag == seq:
            vprint('FOUND A TAGGED PACKET')
            flows_l.acquire()

            # Mark the flow for decoy routing
            k = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            outbound_flows[k] = (PROXY_IP, PROXY_PORT)

            k = (PROXY_IP, PROXY_PORT, pkt[IP].src, pkt[TCP].sport)
            inbound_flows[k] = (pkt[IP].dst, pkt[TCP].dport)
            flows_l.release()

    # Determine whether packet should be rerouted
    flows_l.acquire()
    k = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
    if k in outbound_flows:
        dstIp, dstPort = outbound_flows[k]
        pkt[IP].dst = dstIp
        pkt[TCP].dport = dstPort
        del pkt[TCP].chksum
    elif k in inbound_flows:
        decoyIp, decoyPort = inbound_flows[k]
        pkt[IP].src = decoyIp
        pkt[TCP].sport = decoyPort
        del pkt[TCP].chksum
    flows_l.release()

    handle_ipv4(pkt)


def handle_ipv4(pkt):
    '''
    Handle packet containing IPv4 headers.
    '''
    ip_header = pkt[IP]
    if ip_header.dst not in ip_to_mac:
        # Drop the packet
        vprint("Dropping something else")
        return

    dst_mac = ip_to_mac[ip_header.dst]
    out_intf = mac_to_intf[dst_mac]

    pkt_str = str(pkt)
    pkt_minus_ether = IP(pkt_str[ETHER_HEADER_LEN:])

    spkt = Ether(src=pkt[Ether].src, dst=dst_mac)/pkt_minus_ether
    spkt[IP].ttl -= 1
    del spkt[IP].chksum
    sendp(spkt, iface=out_intf, verbose=0)


def handle_arp(pkt):
    '''
    Handle packet containing ARP headers.
    '''
    glock.acquire()
    print 'in handle_arp'
    arp_header = pkt[ARP]

    # Only respond to ARP requests
    if arp_header.op != 1:
        print 'arp header had wrong opcode'
        glock.release()
        return

    # Convert the ARP request into in ARP reply
    arp_header.op = 2
    arp_header.hwdst = arp_header.hwsrc
    pdst = arp_header.pdst
    arp_header.hwsrc = ip_to_mac[pdst]
    arp_header.pdst = arp_header.psrc
    arp_header.psrc = pdst

    # Send the response
    print 'about to send arp response'
    pkt = Ether(src=arp_header.hwsrc, dst=pkt[Ether].src)/arp_header
    print 'sending arp response on interface %s:' % mac_to_intf[pkt[Ether].dst]
    pkt.show()
    glock.release()
    sendp(pkt, iface=mac_to_intf[pkt[Ether].dst], verbose=0)


def handle_packet(pkt):
    '''
    Process the given packet and send it out the proper interface.
    '''
    glock.acquire()
    sys.stdout.write('packet received')
    sys.stdout.flush()
    if TCP in pkt:
        sys.stdout.write(' tcp:\n')
        pkt.show()
        sys.stdout.flush()
        glock.release()
        handle_tcp(pkt)
    elif ARP in pkt:
        sys.stdout.write(' arp:\n')
        sys.stdout.flush()
        glock.release()
        handle_arp(pkt)
    elif IP in pkt:
        sys.stdout.write(' IP: \n')
        sys.stdout.flush()
        glock.release()
        handle_ipv4(pkt)
    else:
        sys.stdout.write(' unidentified protocol\n')
        pkt.show()
        glock.release()
        # Drop the packet
        return


def incoming_filter(pkt, intf):
    '''
    Given a packet and the interface that detected the packet, return True if
    the packet is incoming. Return False otherwise.
    '''
    glock.acquire()
    print 'packet in filter for intf %s' % intf
    print 'smac: %s\tdmac: %s' % (pkt[Ether].src, pkt[Ether].dst)
    if ARP in pkt:
        print 'ARP looking for %s\tFrom %s' % (pkt[ARP].pdst, pkt[ARP].psrc)
    if TCP in pkt:
        print 'We got a TCP packet!'
    sys.stdout.flush()
    glock.release()
    if pkt[Ether].src in mac_to_intf:
        return mac_to_intf[pkt[Ether].src] == intf
    print 'We\'re dropping something'
    return False


def sniff(intf):
    '''
    Sniff for incoming packets on the given interface.
    '''
    vprint('About to sniff on interface ' + intf)
    scasniff(iface=intf,
             prn=lambda x: handle_packet(x),
             lfilter=lambda x: incoming_filter(x, intf))


def main():
    for intf in mac_to_intf.itervalues():
        t = threading.Thread(target=sniff, args=(intf,))
        t.start()

if __name__ == '__main__':
    main()
