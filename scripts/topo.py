#!/usr/bin/python
'''
Blake Lawson (blawson@princeton.edu)
Adviser: Jennifer Rexford

Configure mininet topology and run test code on client.
'''
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.topo import Topo
from mininet.link import Intf, TCLink

from p4_mininet import P4Switch

from time import sleep

import argparse
import os
import subprocess
import sys

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))
_THRIFT_BASE_PORT = 22222
_PROXY_ADDR = '10.0.0.2'
_PROXY_PORT = '8888'

# Process command line arguments
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
parser.add_argument('--sw-switch', action='store', type=str, required=False,
                    help='Path to a software switch to use instead of the P4' +
                    ' switch.')
args = parser.parse_args()


def vprint(s):
    vprintf('%s\n' % s)


def vprintf(s):
    if args.verbose:
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
        self.addHost('proxy', ip=_PROXY_ADDR, mac='00:00:00:00:00:02')
        self.addHost('decoy', ip='10.0.0.3', mac='00:00:00:00:00:03')
        self.addHost('covert', ip='10.0.0.4', mac='00:00:00:00:00:04')

        if args.verbose:
            sw_path += ' --log-console'

        # Decoy switch
        if args.sw_switch is None:
            self.addSwitch(
                    's1',
                    sw_path=sw_path,
                    json_path=switch_json_path,
                    thrift_port=_THRIFT_BASE_PORT,
                    pcap_dump=True,
                    verbose=True)
        else:
            self.addHost('s1', inNamespace=True)

        # Client-side switch
        self.addSwitch(
                's2',
                sw_path=sw_path,
                json_path=client_json_path,
                thrift_port=_THRIFT_BASE_PORT + 1,
                pcap_dump=True,
                verbose=True)

        self.addLink('s2', 'client', bw=1, delay='1ms')
        self.addLink('s1', 's2', bw=1, delay='1ms')
        self.addLink('s1', 'proxy', bw=1, delay='1ms')
        self.addLink('s1', 'decoy', bw=1, delay='1ms')
        self.addLink('s1', 'covert', bw=1, delay='1ms')


def init_hosts(net):
    for h in net.hosts:
        h.cmd('export GOPATH="/home/blake/Documents/code/"')
        h.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        h.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        h.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')


def init_switches(net):
    '''
    Initialize the switches in the topology. For P4 switches, this means
    running all initial commands. For the software switch, this means running
    the program.
    '''
    # Initialize the decoy switch
    if args.sw_switch is not None:
        s1 = net.get('s1')
        s1.cmd('sudo tcpdump -v -i s1-eth0 -s 0 -w log/s1-eth0.pcap ' +
               '&> /dev/null &')
        s1.cmd('sudo tcpdump -v -i s1-eth1 -s 0 -w log/s1-eth1.pcap ' +
               '&> /dev/null &')
        s1.cmd('sudo tcpdump -v -i s1-eth2 -s 0 -w log/s1-eth2.pcap ' +
               '&> /dev/null &')
        s1.cmd('sudo tcpdump -v -i s1-eth3 -s 0 -w log/s1-eth3.pcap ' +
               '&> /dev/null &')
        cmd = 'python %s %s -proxy-ip %s -proxy-port %s &> log/sw_switch.log &'
        params = (
            args.sw_switch,
            '-v' if args.verbose else '',
            _PROXY_ADDR,
            _PROXY_PORT,
        )
        s1.cmd(cmd % params)
    else:
        cmd = [args.p4_cli, args.switch_json, str(_THRIFT_BASE_PORT)]
        with open(args.switch_commands, 'r') as f:
            vprint('Running %s on switch s1' % ' '.join(cmd))
            try:
                output = subprocess.check_output(cmd, stdin=f)
                vprint(output)
            except subprocess.CalledProcessError as e:
                vprint('Failed to initialize switch s1')
                print(e)
                print(e.output)

    # Initialize client switch
    cmd = [args.p4_cli, args.client_json, str(_THRIFT_BASE_PORT + 1)]
    with open(args.client_commands, 'r') as f:
        vprint('Running %s on switch s2' % ' '.join(cmd))
        try:
            output = subprocess.check_output(cmd, stdin=f)
            vprint(output)
        except subprocess.CalledProcessError as e:
            vprint('Failed to initialize switch s2')
            print(e)
            print(e.output)


def main():
    if args.verbose:
        setLogLevel('info')

    vprint('Starting test')
    topo = TestTopo(sw_path=args.behavioral_exe,
                    switch_json_path=args.switch_json,
                    client_json_path=args.client_json)
    vprint('Initialized topo')
    net = Mininet(topo=topo,
                  host=CPULimitedHost,
                  switch=P4Switch,
                  link=TCLink,
                  controller=None)
    if args.sw_switch is None:
        Intf('cpu-veth-1', net.get('s1'), 11)
    Intf('cpu-veth-3', net.get('s2'), 12)

    vprint('Starting mininet')
    net.start()
    init_hosts(net)
    init_switches(net)

    sleep(1)
    vprint('mininet started')

    proxy = net.getNodeByName('proxy')
    proxy.cmd('sudo tcpdump -v -i any -s 0 -w log/proxy.pcap ' +
              '&> /dev/null &')
    proxy.cmd('go run src/main/proxy.go -port 8888 -file /dev/null ' +
              '&> log/proxy.log &')

    decoy = net.getNodeByName('decoy')
    decoy.cmd('sudo tcpdump -v -s 0 -i any -w log/decoy.pcap ' +
              '&> /dev/null &')
    decoy.cmd('go run src/main/server.go -f src/server/decoy.html ' +
              '&> log/decoy.log &')

    covert = net.getNodeByName('covert')
    covert.cmd('sudo tcpdump -v -s 0 -i any -w log/covert.pcap ' +
               '&> /dev/null &')
    covert.cmd('go run src/main/server.go -f src/server/covert.html ' +
               '&> log/covert.log &')

    client = net.getNodeByName('client')
    client.cmd('sudo tcpdump -v -s 0 -i any -w log/client.pcap ' +
               '&> /dev/null &')
    client.cmd('go run src/main/client.go -decoy "10.0.0.3:8080" ' +
               '-covert "10.0.0.4:8080" &> log/client.log &')

    sleep(2)
    if args.mininet_cli:
        CLI(net)
    else:
        # Make sure that the test has time to finish
        sleep(10)

    vprint('Shutting down')

    # Suppress mininet exception message
    try:
        net.stop()
    except:
        vprint('')


if __name__ == '__main__':
    main()
