'''
Author: Blake Lawson
Adviser: Jennifer Rexford

Controller for client switch. Keeps track of mapping between original sequence
numbers and new sequence numbers after tagging.
'''
from scapy.all import Ether, sniff
from subprocess import Popen, PIPE

import argparse
import struct
import sys

# Set up parser for command line arguments
parser = argparse.ArgumentParser(description='Decoy Switch Controller')
parser.add_argument('--cli', action='store', type=str, required=True,
                    help='Path to behavioral executable')
parser.add_argument('--json', action='store', type=str, required=True,
                    help='Path to JSON configuration for the switch')
parser.add_argument('--thrift-port', action='store', type=str, required=True,
                    help='Thrift port used to send communicate with switch')
parser.add_argument('--interface', action='store', type=str, required=True,
                    help='Interface to send and receive packets.')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
args = parser.parse_args()


# Store client/dst pairs seen so far.
seen = {}


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


def add_to_table(saddr, sport, daddr, dport, seq_diff):
    '''
    Given information about the packet, add it to the switch table.
    '''
    vprintf('Adding %d as table offset value\n' % seq_diff)
    sign = ''
    if seq_diff > 0:
        sign = 'pos'
    else:
        sign = 'neg'
        seq_diff *= -1

    outbound_cmd = 'table_add tag_offset %s_outbound %s %s %s %s => %d'
    inbound_cmd = 'table_add tag_offset %s_inbound %s %s %s %s => %d'

    # In outbound case, src and dst are the same as the current packet
    params = (sign, saddr, sport, daddr, dport, seq_diff)
    send_to_CLI(outbound_cmd % params)

    # In inbound case, src and dst are reversed
    params = (sign, daddr, dport, saddr, sport, seq_diff)
    send_to_CLI(inbound_cmd % params)


def process_cpu_packet(packet):
    '''
    Given packet from client switch, update table with sequence number offset.
    '''
    # Validate packet
    p_str = str(packet)
    # 0-7   : preamble1
    # 8     : reason
    # 9-16  : preamble2
    # 17-20 : tag_value
    # 21-   : data packet (TCP)
    if p_str[:8] != '\x00'*8 or p_str[8] != '\xab' or p_str[9:17] != '\x00'*8:
        vprint('Packet discarded')
        return

    ip_hdr = None
    tcp_hdr = None
    tag = 0
    try:
        tag = struct.unpack('!I', p_str[17:21])[0]
        p = Ether(p_str[21:])
        ip_hdr = p['IP']
        tcp_hdr = p['TCP']
    except Exception as e:
        vprint(e)
        return

    # Don't reprocess packet
    if (ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport) in seen:
        vprint('already saw packet')
        return

    vprintf('initial seqNo: %d\ttag: %d\n' % (tcp_hdr.seq, tag))

    diff = tag - tcp_hdr.seq

    seen[(ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport)] = diff

    vprint('Packet received')
    vprint(p.summary())

    add_to_table(ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport, diff)


def main():
    '''
    Get packets from the switch.
    '''
    sniff(iface=args.interface, prn=lambda x: process_cpu_packet(x))


if __name__ == '__main__':
    main()
