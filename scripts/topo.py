#!/usr/bin/python
'''
Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Configure mininet topology and run test code on client.
'''

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import Intf

from p4_mininet import P4Host, P4Switch

from time import sleep

import argparse
import os
import subprocess
import sys

_verbose = False
_THIS_DIR = os.path.dirname(os.path.realpath(__file__))
_THRIFT_BASE_PORT = 22222


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if _verbose:
        sys.stdout.write(s)
        sys.stdout.flush()


class TestTopo(Topo):

    '''
    Single switch. Three hosts.

    sw_path: string path to P4 behavioral exe
    json_path: string path to P4 configuration
    '''
    def __init__(self, sw_path, switch_json_path, client_json_path):
        super(TestTopo, self).__init__()
        self.addHost('client', ip='10.0.0.1', mac='00:00:00:00:00:01')
        self.addHost('proxy', ip='10.0.0.2', mac='00:00:00:00:00:02')
        self.addHost('decoy_dst', ip='10.0.0.3', mac='00:00:00:00:00:03')
        self.addHost('covert_dst', ip='10.0.0.4', mac='00:00:00:00:00:04')

        if _verbose:
            sw_path += ' --log-console'

        # Decoy switch
        self.addSwitch(
                's1',
                sw_path=sw_path,
                json_path=switch_json_path,
                thrift_port=_THRIFT_BASE_PORT,
                pcap_dump=True,
                verbose=True)

        # Client-side switch
        self.addSwitch(
                's2',
                sw_path=sw_path,
                json_path=client_json_path,
                thrift_port=_THRIFT_BASE_PORT + 1,
                pcap_dump=True,
                verbose=True)

        self.addLink('s2', 'client')
        self.addLink('s1', 's2')
        self.addLink('s1', 'proxy')
        self.addLink('s1', 'decoy_dst')
        self.addLink('s1', 'covert_dst')


def init_hosts(net):
    for h in net.hosts:
        h.cmd('export GOPATH="/home/blake/Documents/code/"')


def init_switches(switches, p4_cli_path, p4_json_paths, commands_paths):
    '''
    Iterate through switches in the mininet topology and initialize them with
    the commands in p4src/tag_commands.txt.

    switches: List of switches in the Mininet topology.
    p4_cli_path: String path to the p4 cli executable.
    p4_json_paths: List of string paths to the p4 json configuration files for
        each of the switches in switches.
    commands_paths: List of string paths to commands.txt files for each of the
        switches in switches. Used to initialize the p4 switch.
    '''
    assert len(switches) == len(p4_json_paths)
    assert len(p4_json_paths) == len(commands_paths)
    for i in range(len(switches)):
        # cmd = [p4_cli_path, '--json', p4_json_paths[i], '--thrift-port',
        cmd = [p4_cli_path, p4_json_paths[i], str(_THRIFT_BASE_PORT + i)]
        with open(commands_paths[i], 'r') as f:
            vprintf('Running %s on switch %s\n' %
                    (' '.join(cmd), switches[i].name))
            try:
                output = subprocess.check_output(cmd, stdin=f)
                vprintf(output)
            except subprocess.CalledProcessError as e:
                vprintf('Failed to initialize switch %s\n' % switches[i].name)
                print(e)
                print(e.output)


def make_argparse():
    parser = argparse.ArgumentParser(description='Create mininet topology ' +
                                     'and run test.')
    parser.add_argument('-v', '--verbose', action='store_true', required=False)
    parser.add_argument('--mininet-cli',  action='store_true',
                        help='Run mininet CLI after test', required=False)
    parser.add_argument('--behavioral-exe', action='store', type=str,
                        help='Path to P4 behavioral executable', required=True)
    parser.add_argument('--switch-json', action='store', type=str,
                        help='Path to P4 JSON config file', required=True)
    parser.add_argument('--p4-cli', action='store', type=str,
                        help='Path to BM CLI', required=True)
    parser.add_argument('--switch-commands', action='store', type=str,
                        help='Path to P4 commands.txt init file',
                        required=True)
    parser.add_argument('--client-commands', action='store', type=str,
                        help='Path to init file for P4 client', required=True)
    parser.add_argument('--client-json', action='store', type=str,
                        help='Path to P4 JSON config file for the ' +
                        'client switch',
                        required=True)
    return parser


def main(args):
    if _verbose:
        setLogLevel('info')

    vprint('Starting test')
    topo = TestTopo(sw_path=args.behavioral_exe,
                    switch_json_path=args.switch_json,
                    client_json_path=args.client_json)
    vprint('Initialized topo')
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, controller=None)

    # Configure CPU offloading
    Intf('cpu-veth-1', net.get('s1'), 11)
    Intf('cpu-veth-3', net.get('s2'), 12)

    vprint('Starting mininet')
    net.start()
    init_hosts(net)
    init_switches(net.switches,
                  p4_cli_path=args.p4_cli,
                  p4_json_paths=[args.switch_json, args.client_json],
                  commands_paths=[args.switch_commands, args.client_commands])
    sleep(1)
    vprint('mininet started')

    proxy = net.getNodeByName('proxy')
    proxy.cmd('sudo tcpdump -v -i any -s 0 -w log/proxy_tcp.pcap ' +
              '&> /dev/null &')
    proxy.cmd('go run src/main/proxy.go &> log/proxy.log &')

    decoy = net.getNodeByName('decoy_dst')
    decoy.cmd('sudo tcpdump -v -s 0 -i any -w log/decoy_tcp.pcap ' +
              '&> /dev/null &')
    decoy.cmd('go run src/main/server.go &> log/decoy.log &')

    covert = net.getNodeByName('covert_dst')
    covert.cmd('sudo tcpdump -v -s 0 -i any -w log/covert_tcp.pcap ' +
               '&> /dev/null &')
    covert.cmd('go run src/main/server.go &> log/covert.log &')

    client = net.getNodeByName('client')
    client.cmd('sudo tcpdump -v -s 0 -i any -w log/client_tcp.pcap ' +
               '&> /dev/null &')
    client.cmd('go run src/main/client.go &> log/client.log &')

    sleep(2)
    if args.mininet_cli:
        CLI(net)

    vprint('Shutting down')

    # Suppress mininet exception message
    try:
        net.stop()
    except:
        vprint('')


if __name__ == '__main__':
    args = make_argparse().parse_args()
    _verbose = args.verbose

    main(args)
