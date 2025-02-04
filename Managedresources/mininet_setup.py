#!/usr/bin/python

import argparse
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class CustomTreeTopo(Topo):
    """
    Creates a tree topology with a specified depth and fanout.
    """

    def build(self, depth=4, fanout=2):
        """
        Recursively builds a tree topology.
        """
        self.create_tree(depth, fanout)

    def create_tree(self, depth, fanout, parent=None):
        """
        Recursive function to add switches and hosts to create a tree.
        """
        if depth == 0:
            return

        # Create a switch
        switch_id = len(self.switches()) + 1
        switch = self.addSwitch('s{}'.format(switch_id))

        if parent:
            self.addLink(parent, switch)  # Connect switch to its parent

        for _ in range(fanout):
            if depth == 1:
                # Create and link host
                host_id = len(self.hosts()) + 1
                host = self.addHost('h{}'.format(host_id))
                self.addLink(switch, host)
            else:
                self.create_tree(depth - 1, fanout, switch)


def configure_switches(net):
    """
    Applies additional configurations to Open vSwitch (OVS) for smooth operation.
    """
    info("*** Configuring OVS switches...\n")

    for switch in net.switches:
        switch.cmd("ovs-vsctl set bridge {} protocols=OpenFlow13".format(switch))
        switch.cmd("ovs-vsctl set-fail-mode {} secure".format(switch))
        info("Configured {}\n".format(switch))


def generate_traffic(net):
    """
    Simulates a DDoS attack by generating continuous traffic.
    """
    info("*** Generating DDoS traffic\n")

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    # Start a simple HTTP server on h3
    h3.cmd("python3 -m http.server 80 &")

    # Start a flood ping from h1 to h3
    h1.cmd("ping 10.0.0.3 -f &")

    # Start a flood ping from h2 to h3
    h2.cmd("ping 10.0.0.3 -f &")

    # Start a SYN flood attack from h2 to h3 on port 80
    h2.cmd("hping3 --flood --syn -p 80 10.0.0.3 &")

    info("*** Traffic generation started!\n")


def run_network(controller_ip):
    """
    Initializes Mininet, creates topology, and applies configurations.
    """
    setLogLevel('info')

    # Create the network
    info("*** Creating network\n")
    topo = CustomTreeTopo(depth=2, fanout=2)
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,  # We use an external Ryu controller
        autoSetMacs=True,
        cleanup=True
    )

    # Add the remote Ryu controller
    info("*** Adding Remote Controller: {} ***\n".format(controller_ip))
    ryu_controller = net.addController(
        'c0', controller=RemoteController, ip=controller_ip, port=6653
    )

    # Start the network
    info("*** Starting network\n")
    net.start()

    # Apply additional switch configurations
    configure_switches(net)

    # Generate DDoS-like traffic
    generate_traffic(net)

    # Open Mininet CLI for interactive debugging
    info("*** Running CLI\n")
    CLI(net)

    # Stop the network when CLI exits
    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Mininet DDoS Simulation with Remote Controller")
    parser.add_argument('--controller-ip', type=str, required=True, help="IP address of the remote SDN controller")
    
    args = parser.parse_args()

    # Run the network with the provided controller IP
    run_network(args.controller_ip)
