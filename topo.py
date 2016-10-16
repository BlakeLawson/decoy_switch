#!/usr/bin/python
# Blake Lawson (blawson@princeton.edu)
# Adviser: Jennifer Rexford
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.node import OVSController
from mininet.topo import Topo

from time import sleep

import argparse
import sys

verbose = False


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if verbose:
        sys.stdout.write(s)
        sys.stdout.flush()


class TestTopo(Topo):

    '''
    Single switch. Three hosts.
    '''
    def __init__(self):
        super(TestTopo, self).__init__()
        self.addHost('client', ip='10.0.0.1', mac='00:00:00:00:00:01')
        self.addHost('proxy', ip='10.0.0.2', mac='00:00:00:00:00:02')
        self.addHost('decoy_dst', ip='10.0.0.4', mac='00:00:00:00:00:03')
        self.addHost('covert_dst', ip='10.0.0.5', mac='00:00:00:00:00:04')

        self.addSwitch('s1')

        self.addLink('s1', 'client')
        self.addLink('s1', 'proxy')
        self.addLink('s1', 'decoy_dst')
        self.addLink('s1', 'covert_dst')


def init_hosts(net):
    for h in net.hosts:
        h.cmd('export GOPATH="/home/blake/Documents/code/"')


def make_argparse():
    parser = argparse.ArgumentParser(description='Create mininet topology and ' +
            'run test.')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-c', '--cli',  action='store_true')
    return parser


def main(args):
    vprint('Starting test')
    topo = TestTopo()
    vprint('Initialized topo')
    net = Mininet(topo)

    vprint('Starting mininet')
    net.start()
    init_hosts(net)
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
    if args.cli:
        CLI(net)

    vprint('Shutting down')
    net.stop()


if __name__ == '__main__':
    args = make_argparse().parse_args()
    verbose = args.verbose

    main(args)
