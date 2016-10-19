#!/usr/bin/python

# Blake Lawson (blawson@princeton.edu)
# Adviser: Jennifer Rexford

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.node import OVSController
from mininet.topo import Topo

from p4_mininet import P4Host
from p4_mininet import P4Switch

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
    def __init__(self, sw_path, json_path):
        super(TestTopo, self).__init__()
        self.addHost('client', ip='10.0.0.1', mac='00:00:00:00:00:01')
        self.addHost('proxy', ip='10.0.0.2', mac='00:00:00:00:00:02')
        self.addHost('decoy_dst', ip='10.0.0.3', mac='00:00:00:00:00:03')
        self.addHost('covert_dst', ip='10.0.0.4', mac='00:00:00:00:00:04')

        self.addSwitch('s1', sw_path=sw_path, json_path=json_path, 
                       thrift_port=_THRIFT_BASE_PORT, pcap_dump=True)

        self.addLink('s1', 'client')
        self.addLink('s1', 'proxy')
        self.addLink('s1', 'decoy_dst')
        self.addLink('s1', 'covert_dst')


def init_hosts(net):
    for h in net.hosts:
        h.cmd('export GOPATH="/home/blake/Documents/code/"')


def init_switches(net, p4_cli_path, p4_json_path, commands_path):
    '''
    Iterate through switches in the mininet topology and initialize them with
    the commands in p4src/commands.txt.

    net: Mininet object
    p4_cli_path: string path to the p4 cli executable
    p4_json_path: string path to the p4 json configuration file
    commands_path: string path to commands.txt file used to initialize the
        p4 switch
    '''
    for i in range(len(net.switches)):
        cmd = [p4_cli_path, '--json', p4_json_path, '--thrift-port',
               str(_THRIFT_BASE_PORT + i)]
        with open(commands_path, 'r') as f:
            vprintf('Running %s on switch %s\n' %  (' '.join(cmd), net.switches[i].name))
            try:
                output = subprocess.check_output(cmd, stdin=f)
                vprintf(output)
            except subprocess.CalledProcessError as e:
                vprintf('Failed to initialize switch %s\n' % net.switches[i].name)
                print e
                print e.output


def make_argparse():
    parser = argparse.ArgumentParser(description='Create mininet topology and ' +
            'run test.')
    parser.add_argument('-v', '--verbose', action='store_true', required=False)
    parser.add_argument('--mininet-cli',  action='store_true', 
                        help='Run mininet CLI after test', required=False)
    parser.add_argument('--behavioral-exe', action='store', type=str,
                        help='Path to P4 behavioral executable', required=True)
    parser.add_argument('--json', action='store', type=str,
                        help='Path to P4 JSON config file', required=True)
    parser.add_argument('--p4-cli', action='store', type=str,
                        help='Path to BM CLI', required=True)
    parser.add_argument('--p4-commands', action='store', type=str,
                        help='Path to P4 commands.txt init file', required=True)
    return parser


def main(args):
    if _verbose:
        setLogLevel('info')

    vprint('Starting test')
    topo = TestTopo(sw_path=args.behavioral_exe, json_path=args.json)
    vprint('Initialized topo')
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, controller=None)

    vprint('Starting mininet')
    net.start()
    init_hosts(net)
    init_switches(net, p4_cli_path=args.p4_cli, p4_json_path=args.json, 
                 commands_path=args.p4_commands)
    vprint('mininet started')

    proxy = net.getNodeByName('proxy')
    proxy.cmd('sudo tcpdump -v -i any -s 0 -w log/proxy_tcp.cap &> /dev/null &')
    proxy.cmd('go run src/main/proxy.go &> log/proxy.txt &')

    decoy = net.getNodeByName('decoy_dst')
    decoy.cmd('go run src/main/server.go &> log/decoy.txt &')

    covert = net.getNodeByName('covert_dst')
    covert.cmd('go run src/main/server.go &> log/covert.txt &')

    client = net.getNodeByName('client')
    client.cmd('sudo tcpdump -v -s 0 -i any -w log/client_tcp.cap &> /dev/null &')
    client.cmd('go run src/main/client.go &> log/client.txt &')

    sleep(2)
    if args.mininet_cli:
        CLI(net)

    vprint('Shutting down')
    net.stop()


if __name__ == '__main__':
    args = make_argparse().parse_args()
    _verbose = args.verbose

    main(args)
