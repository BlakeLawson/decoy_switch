#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet

class TestTopo(Topo):

    '''
    Single switch. Three hosts.
    '''
    def __init__(self):
        super(TestTopo, self).__init__()
        self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
        self.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
        self.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')

        self.addSwitch('s1')

        self.addLink('s1', 'h1')
        self.addLink('s1', 'h2')
        self.addLink('s1', 'h3')


def main():
    topo = TestTopo()


if __name__ == '__main__':
    main()
