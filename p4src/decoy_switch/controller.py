'''
Author: Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Controller for decoy switch. Updates match-action tables as packets go through
switch.

The structure of this program is based on nat_app.py in the P4 NAT example:
https://github.com/p4lang/tutorials/blob/master/examples/simple_nat/nat_app.py
'''
from scapy.all import Ether, sniff, sendp, TCP
from subprocess import Popen, PIPE
from urlparse import urlparse

import argparse
import socket
import sys

# Set up parser for command line arguments
parser = argparse.ArgumentParser(description='Decoy Switch Controller')
parser.add_argument('--cli', action='store', type=str, required=True,
                    help='Path to behavioral executable')
parser.add_argument('--json', action='store', type=str, required=True,
                    help='Path to JSON configuration for the switch')
parser.add_argument('--thrift-port', action='store', type=str, required=True,
                    help='Thrift port used to send communicate with switch')
# parser.add_argument('--proxy-addr', action='store', type=str, required=True,
#                     help='Decoy proxy IP address.')
# parser.add_argument('--proxy-port', action='store', type=str, required=True,
#                     help='Decoy proxy port.')
parser.add_argument('--switch-addr', action='store', type=str, required=True,
                    help='Decoy Switch IP address.')
parser.add_argument('--interface', action='store', type=str, required=True,
                    help='Interface to send and receive packets.')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
args = parser.parse_args()


# Store decoy routing requests seen so far. Maps client ip/port to deocy
# ip/port.
decoy_pairs = {}

# Default port to be used if not included in covert destination address.
DEFAULT_PORT = 8080


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if args.verbose:
        sys.stdout.write(s)
        sys.stdout.flush()


def send_to_CLI(cmd):
    '''
    Run the cmd string on the decoy switch using the P4 CLI.
    '''
    p = Popen([args.cli, args.json, args.thrift_port], stdout=PIPE, stdin=PIPE)
    output = p.communicate(input=cmd)[0]
    vprint(output)


def add_to_table(client_ip, client_port, decoy_ip, decoy_port,
                 covert_ip, covert_port=DEFAULT_PORT):
    '''
    Add the given client/decoy pair to the switch's routing tables.

    TODO: Figure out what is going on
    '''
    # Add the packet to the decoy switch routing table
    outbound_cmd = 'table_add check_mappings out_from_client %s %s %s %s ' + \
                   '=> %s %s %s %s'
    inbound_cmd = 'table_add check_mappings in_to_client %s %s %s %s ' + \
                  '=> %s %s %s %s'

    # In outbound case, key is the client-decoy pair and val is switch-covert
    # pair.
    params = (
        client_ip,          # IP src
        client_port,        # TCP sport
        decoy_ip,           # IP dst
        decoy_port,         # TCP dport
        args.switch_addr,   # new IP src

        # reuse client port to simulate random port selection by switch.
        client_port,        # new TCP sport
        covert_ip,          # new IP dst
        covert_port,        # new TCP dport
    )
    send_to_CLI(outbound_cmd % params)

    # In inbound case, key is the switch-covert pair pair and the val is the
    # client-decoy pair
    params = (
        covert_ip,          # IP src
        covert_port,        # TCP sport
        args.switch_addr,   # IP dst
        client_port,        # TCP dport
        decoy_ip,           # New IP src
        decoy_port,         # New TCP sport
        client_ip,          # New IP dst
        client_port,        # New TCP dport
    )
    send_to_CLI(inbound_cmd % params)


def process_cpu_packet(packet):
    '''
    Given packet from decoy switch, perform processing specified by the
    packet's CPU headers.
    '''
    # Validate packet
    p_str = str(packet)
    # 0-7 : preamble
    # 8   : reason
    # 9-  : data packet (TCP)
    if p_str[:8] != '\x00' * 8 or p_str[8] != '\xab':
        return

    ip_hdr = None
    tcp_hdr = None
    try:
        p = Ether(p_str[9:])
        ip_hdr = p['IP']
        tcp_hdr = p['TCP']
    except Exception as e:
        vprint(e)

    # Don't reprocess packet
    if (ip_hdr.src, tcp_hdr.sport) in decoy_pairs:
        return
    decoy_pairs[(ip_hdr.src, tcp_hdr.sport)] = (ip_hdr.dst, tcp_hdr.dport)

    vprint('Packet received')
    vprint(p.summary())

    # Look up the covert destination's IP address
    payload = p[TCP].payload
    abs_addr = ''
    try:
        # Request line should be of the form
        # "GET http://www.example.com/ HTTP/1.1"
        abs_addr = str(payload).strip().split()[1]
    except Exception as e:
        vprint(e)
        return
    url = urlparse(abs_addr)
    covert_ip = ''
    try:
        covert_ip = socket.gethostbyname(url.hostname)
    except Exception as e:
        vprintf('Failed to lookup host %s:\n%s\n' % (url.hostname, e))
        return

    covert_port = url.port if url.port is not None else DEFAULT_PORT

    vprint('Decoded covert %s:%d' % (covert_ip, covert_port))

    add_to_table(ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport,
                 covert_ip, covert_port)

    # Send packet back to switch. Use hachy solution to avoid reprocessing
    # this packet.
    new_p = p_str[:8] + '\xac' + p_str[9:]
    sendp(new_p, iface=args.interface, verbose=args.verbose)


def main():
    '''
    Get packets from the switch.
    '''
    sniff(iface=args.interface, prn=lambda x: process_cpu_packet(x))


if __name__ == '__main__':
    main()
