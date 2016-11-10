'''
Author: Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Controller for decoy switch. Updates match-action tables as packets go through
switch.

The structure of this program is based on nat_app.py in the P4 NAT example:
https://github.com/p4lang/tutorials/blob/master/examples/simple_nat/nat_app.py
'''
from scapy.all import Ether, sniff, sendp
from subprocess import Popen, PIPE

import argparse
import sys

# Set up parser for command line arguments
parser = argparse.ArgumentParser(description='Decoy Switch Controller')
parser.add_argument('--cli', action='store', type=str, required=True,
                    help='Path to behavioral executable')
parser.add_argument('--json', action='store', type=str, required=True,
                    help='Path to JSON configuration for the switch')
parser.add_argument('--thrift-port', action='store', type=str, required=True,
                    help='Thrift port used to send communicate with switch')
parser.add_argument('--proxy-addr', action='store', type=str, required=True,
                    help='Decoy proxy IP address.')
parser.add_argument('--proxy-port', action='store', type=str, required=True,
                    help='Decoy proxy port.')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
args = parser.parse_args()


# Store decoy routing requests seen so far. Maps client ip/port to deocy
# ip/port.
decoy_pairs = {}


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if args.verbose:
        sys.stdout.write(s)


def send_to_CLI(cmd):
    '''
    Run the cmd string on the decoy switch using the P4 CLI.
    '''
    p = Popen([args.cli, args.json, args.thrift_port], stdout=PIPE, stdin=PIPE)
    output = p.communicate(input=cmd)[0]
    vprint(output)


def add_to_table(client_ip, client_port, decoy_ip, decoy_port):
    '''
    Add the given client/decoy pair to the switch's routing tables.
    '''
    # Add the packet to the decoy switch routing table
    outbound_cmd = 'table_add check_tag send_to_proxy %s %s %s %s => %s %s'
    inbound_cmd = 'table_add check_tag hide_dst %s %s %s %s => %s %s'

    # In outbound case, key is the client-decoy pair and val is the proxy info
    params = (
        client_ip,
        client_port,
        decoy_ip,
        decoy_port,
        args.proxy_addr,
        args.proxy_port,
    )
    send_to_CLI(outbound_cmd % params)

    # In inbound case, key is the proxy-client pair and the val is the decoy
    params = (
        args.proxy_addr,
        args.proxy_port,
        client_ip,
        client_port,
        decoy_ip,
        decoy_port,
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
    # 8   : device
    # 9   : reason
    # 10  : iface
    # 11- : data packet (TCP)
    if p_str[:8] != '\x00' * 8 or p_str[8] != '\x00' or p_str[9] != '\xab':
        return

    ip_hdr = None
    tcp_hdr = None
    try:
        p = Ether(p_str[11:])
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

    add_to_table(ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport)

    # Send packet back to switch. Use hachy solution to avoid reprocessing
    # this packet.
    new_p = p_str[:9] + '\xac' + p_str[10:]
    sendp(new_p, iface='cpu-veth-0', verbose=args.verbose)


def main():
    '''
    Get packets from the switch.
    '''
    sniff(iface='cpu-veth-0', prn=lambda x: process_cpu_packet(x))


if __name__ == '__main__':
    main()
