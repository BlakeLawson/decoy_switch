'''
Author: Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Controller for decoy switch. Updates match-action tables as packets go through
switch.

The structure of this program is based on nat_app.py in the P4 NAT example:
https://github.com/p4lang/tutorials/blob/master/examples/simple_nat/nat_app.py
'''
from scapy.all import Ether, sniff, sendp, TCP, IP
from subprocess import Popen, PIPE
from urlparse import urlparse

import argparse
import socket
import sys
import threading

# Set up parser for command line arguments
parser = argparse.ArgumentParser(description='Decoy Switch Controller')
parser.add_argument('--cli', action='store', type=str, required=True,
                    help='Path to behavioral executable')
parser.add_argument('--json', action='store', type=str, required=True,
                    help='Path to JSON configuration for the switch')
parser.add_argument('--thrift-port', action='store', type=str, required=True,
                    help='Thrift port used to send communicate with switch')
parser.add_argument('--switch-addr', action='store', type=str, required=True,
                    help='Decoy Switch IP address.')
parser.add_argument('--switch-mac', action='store', type=str, required=True,
                    help='Decoy switch MAC address.')
parser.add_argument('--interface', action='store', type=str, required=True,
                    help='Interface to send and receive packets.')
parser.add_argument('-v', '--verbose', action='store_true', required=False)
args = parser.parse_args()

# Default port to be used if not included in covert destination address.
DEFAULT_PORT = 8080

# TCP flag
SYN_FLAGS = 0x2

# Store decoy routing requests seen so far. Maps 4-tuple to tuple of (seq
# number, ack number). Used to calculate seq/ack offsets later on.
seqack_base_lock = threading.Lock()
seqack_base = {}

# Store TCP options associated with a given connection. Maps tuple of (IP.src,
# TCP.sport, IP.dst, TCP.dport) to TCP options.
tcp_options_lock = threading.Lock()
tcp_options = {}

# Mark whether handle_offsets has seen the given packet already
offsets_seen_lock = threading.Lock()
offsets_seen = {}

# Reason number to function mappings
controller_functions = {
    '\xab': lambda x: handle_parse_covert(x),
    '\xac': lambda x: handle_get_options(x),
    '\xad': lambda x: handle_offsets(x),
}


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


def update_decoy_mapping_table(client_ip, client_port, decoy_ip, decoy_port,
                               covert_ip, covert_port=DEFAULT_PORT):
    '''
    Add the given client/decoy pair to the switch's routing tables.
    '''
    # Add the packet to the decoy switch routing table
    outbound_cmd = 'table_add check_mappings out_from_client %s %s %s %s ' + \
                   '=> %s %s %s %s'
    inbound_cmd = 'table_add check_mappings in_to_client %s %s %s %s ' + \
                  '=> %s %s %s %s'
    close_decoy_cmd = 'table_add check_mappings decoy_drop %s %s %s %s =>'

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

    # Add command that drops all future packets from the decoy. Not a great
    # solution but will end FIN, ACK that comes after RST for now.
    params = (
        decoy_ip,
        decoy_port,
        client_ip,
        client_port,
    )
    send_to_CLI(close_decoy_cmd % params)


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
    if p_str[:8] != '\x00' * 8 or p_str[8] not in controller_functions:
        return
    controller_functions[p_str[8]](p_str)


def handle_parse_covert(p_str):
    '''
    Given string packet, read the covert destination and send it back to
    the switch.
    '''
    ip_hdr = None
    tcp_hdr = None
    try:
        p = Ether(p_str[9:])
        ip_hdr = p[IP]
        tcp_hdr = p[TCP]
    except Exception as e:
        vprint(e)

    # Don't reprocess packet
    params = (ip_hdr.src, tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport)
    if params not in tcp_options:
        return

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

    # Update dict with info
    k = (covert_ip, covert_port, args.switch_addr, tcp_hdr.sport)
    seqack_base_lock.acquire()
    if k in seqack_base:
        seqack_base_lock.release()
        return
    seqack_base[k] = (tcp_hdr.seq, tcp_hdr.ack, ip_hdr.src,
                      tcp_hdr.sport, ip_hdr.dst, tcp_hdr.dport)
    seqack_base_lock.release()
    vprint('Decoded covert %s:%d' % (covert_ip, covert_port))

    update_decoy_mapping_table(ip_hdr.src, tcp_hdr.sport, ip_hdr.dst,
                               tcp_hdr.dport, covert_ip, covert_port)

    # Send packet back to switch. Use hacky solution to avoid reprocessing
    # this packet.
    new_p = p_str[:8] + '\x00' + p_str[9:]
    sendp(new_p, iface=args.interface, verbose=args.verbose)

    # Create the initial SYN packet for the connection to the covert
    # destination and send it back to the switch.
    covert_syn = Ether(src=args.switch_mac)
    covert_syn = covert_syn/IP(src=args.switch_addr, dst=covert_ip)
    covert_syn = covert_syn/TCP(sport=tcp_hdr.sport, dport=covert_port,
                                flags=SYN_FLAGS, options=tcp_options[params],
                                seq=tcp_hdr.seq)
    sendp(covert_syn, iface=args.interface, verbose=args.verbose)


def handle_get_options(p_str):
    '''
    Given string packet, record the TCP options.
    '''
    try:
        p = Ether(p_str[9:])
    except Exception as e:
        vprint(e)

    if TCP not in p or IP not in p:
        return

    k = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
    tcp_options_lock.acquire()
    if k in tcp_options:
        tcp_options_lock.release()
        return
    tcp_options[k] = p[TCP].options
    tcp_options_lock.release()

    vprint('saving options %s for %s' % (str(tcp_options[k]), str(k)))


def update_seqack_table(seq_diff, ack_diff, client_ip, client_port, decoy_ip,
                        decoy_port, switch_ip, switch_port, covert_ip,
                        covert_port):
    '''
    Given information about the packet, add seq and ack differences to the
    switch table.
    '''
    vprintf('Adding %d as table offset value\n' % seq_diff)
    seq_sign = ''
    if seq_diff >= 0:
        seq_sign = 'pos'
    else:
        seq_sign = 'neg'
        seq_diff *= -1

    ack_sign = ''
    if ack_diff >= 0:
        ack_sign = 'pos'
    else:
        ack_sign = 'neg'
        ack_diff *= -1

    vprintf('updated seq_diff:%d ack_diff:%d\n' % (seq_diff, ack_diff))

    # Handle sequence numbers
    seq_outbound_cmd = 'table_add seq_offset %s_seq_outbound %s %s %s %s => %d'
    seq_inbound_cmd = 'table_add seq_offset %s_seq_inbound %s %s %s %s => %d'
    ack_outbound_cmd = 'table_add ack_offset %s_ack_outbound %s %s %s %s => %d'
    ack_inbound_cmd = 'table_add ack_offset %s_ack_inbound %s %s %s %s => %d'

    # In outbound case, src and dst are the same as the current packet
    params = (
        seq_sign,
        switch_ip,
        switch_port,
        covert_ip,
        covert_port,
        seq_diff,
    )
    vprint('Sending command %s' % (seq_outbound_cmd % params))
    send_to_CLI(seq_outbound_cmd % params)

    params = (
        ack_sign,
        switch_ip,
        switch_port,
        covert_ip,
        covert_port,
        ack_diff,
    )
    vprint('Sending command %s' % (ack_outbound_cmd % params))
    send_to_CLI(ack_outbound_cmd % params)

    # In inbound case, src and dst are reversed
    params = (
        seq_sign,
        decoy_ip,
        decoy_port,
        client_ip,
        client_port,
        seq_diff,
    )
    vprint('Sending command %s' % (seq_outbound_cmd % params))
    send_to_CLI(seq_inbound_cmd % params)

    params = (
        ack_sign,
        decoy_ip,
        decoy_port,
        client_ip,
        client_port,
        ack_diff,
    )
    vprint('Sending command %s' % (ack_outbound_cmd % params))
    send_to_CLI(ack_inbound_cmd % params)


def handle_offsets(p_str):
    '''
    Given packet from covert destination, record the difference between the
    seq and ack numbers for the two connections.
    '''
    try:
        p = Ether(p_str[9:])
    except Exception as e:
        vprint(e)

    if TCP not in p or IP not in p:
        return

    k = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
    offsets_seen_lock.acquire()
    if k not in seqack_base or k in offsets_seen:
        offsets_seen_lock.release()
        return
    offsets_seen[k] = ''
    offsets_seen_lock.release()

    vprint('got a packet to compute offsets')

    old_seq, old_ack, c_addr, c_port, d_addr, d_port = seqack_base[k]

    covert_seq = p[TCP].seq
    covert_ack = p[TCP].ack

    seq_diff = covert_ack - old_seq
    ack_diff = covert_seq - old_ack

    vprintf('covert_seq:%d covert_ack:%d old_seq:%d old_ack:%d seq_diff:%d ack_diff:%d\n' % (covert_seq, covert_ack, old_seq, old_ack, seq_diff, ack_diff))

    # Switch src and dst because inbound and outbound are maintained with
    # respect to the client.
    update_seqack_table(seq_diff, ack_diff, c_addr, c_port, d_addr, d_port,
                        p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport)

    # Send packet back to switch
    new_p = p_str[:8] + '\x00' + p_str[9:]
    sendp(new_p, iface=args.interface, verbose=args.verbose)


def main():
    '''
    Get packets from the switch.
    '''
    sniff(iface=args.interface, prn=lambda x: process_cpu_packet(x))


if __name__ == '__main__':
    main()
