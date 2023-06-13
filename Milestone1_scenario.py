#!/usr/bin/env python3
"""
vlanhost.py: Host subclass that uses a VLAN tag for the default interface.

Dependencies:
    This class depends on the "vlan" package
    $ sudo apt-get install vlan

Usage (example uses VLAN ID=1000):
    From the command line:
        sudo mn --custom vlanhost.py --host vlan,vlan=1000

    From a script (see exampleUsage function below):
        from functools import partial
        from vlanhost import VLANHost

        ....

        host = partial( VLANHost, vlan=1000 )
        net = Mininet( host=host, ... )

    Directly running this script:
        sudo python vlanhost.py 1000

"""

from sys import exit  # pylint: disable=redefined-builtin

from mininet.node import Host
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.log import error


class VLANHost( Host ):
    "Host connected to VLAN interface"

    # pylint: disable=arguments-differ
    def config( self, **params ):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""

        vlan = params.pop('vlan',None)
        assert vlan is not None, 'VLANHost without vlan in instantiation'
        r = super( VLANHost, self ).config( **params )

        intf = self.defaultIntf()
        ip_info = params['ip']
        new_intf = f'{intf}.{vlan}'
        # remove IP from default, "physical" interface
        self.cmd( f'ip address del {ip_info} dev {intf}')
        # create VLAN interface
        self.cmd(f'ip link add link {intf} name {new_intf} type vlan id {vlan}')
        # assign the host's IP to the VLAN interface
        self.cmd( f'ip address add {ip_info} dev {new_intf}')
        self.cmd( f'ip link set up dev {new_intf}')
        # update the (Mininet) interface to refer to VLAN interface name
        intf.name = new_intf
        # add VLAN interface to host's name to intf map
        self.nameToIntf[ new_intf ] = intf

        return r


hosts = { 'vlan': VLANHost }


class VLANStarTopo( Topo ):
    """Example topology that uses host in multiple VLANs

       The topology has a single switch. There are k VLANs with
       n hosts in each, all connected to the single switch. There
       are also n hosts that are not in any VLAN, also connected to
       the switch."""

    def build( self, k=2, n=2, vlanBase=100 ):
        s1 = self.addSwitch( 's1', protocols=["OpenFlow13"])
        s2 = self.addSwitch('s2', protocols=["OpenFlow13"])
        self.addLink(s1, s2)
        h = self.addHost("mport", ip = "10.0.4.2/24")
        self.addLink(h, s1)
        h = self.addHost('juju1', cls=VLANHost, vlan=100, ip = "172.28.1.2/24", mac='12:00:00:00:00:02')
        self.addLink(h, s1)
        h = self.addHost('vm1', cls=VLANHost, vlan=200, ip = "192.168.40.10/24", mac='12:00:00:00:00:10')
        self.addLink(h, s1)
        h = self.addHost('vm2', cls=VLANHost, vlan=201, ip = "192.168.40.10/24", mac='12:00:00:00:00:10')
        self.addLink(h, s1)
        h = self.addHost('vm3', cls=VLANHost, vlan=202, ip = "192.168.40.10/24", mac='12:00:00:00:00:10')
        self.addLink(h, s1)
        h = self.addHost('vm4', cls=VLANHost, vlan=203, ip = "192.168.40.10/24", mac='12:00:00:00:00:10')
        self.addLink(h, s1)

        h = self.addHost("laptop", ip = "10.0.4.3/24")
        self.addLink(h, s2)
        h = self.addHost("client", ip = "192.168.40.2/24")
        self.addLink(h, s2)
        h = self.addHost('juju2', cls=VLANHost, vlan=100, ip = "172.28.1.3/24", mac='12:00:00:00:00:03')
        self.addLink(h, s2)


def exampleCustomTags():
    """Simple example that exercises VLANStarTopo"""

    net = Mininet(topo=VLANStarTopo(), waitConnected=True, controller = partial(RemoteController, ip='127.0.0.1', port=6633))
    net.start()
    CLI( net )
    net.stop()


if __name__ == '__main__':
    import sys
    from functools import partial

    from mininet.net import Mininet
    from mininet.cli import CLI
    from mininet.topo import SingleSwitchTopo
    from mininet.log import setLogLevel
    from mininet.node import Controller
    from mininet.node import RemoteController

    setLogLevel( 'info' )

    # Using the 'ip' command everywhere, there is no need for extra packages
    exampleCustomTags()
