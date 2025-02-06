#!/usr/bin/python

"""Mininet Network Setup Script

This script creates a tree topology in Mininet and configures it for DDoS attack simulation.
It sets up switches, hosts, and connects to a remote SDN controller for network management.

The topology consists of multiple layers of switches in a tree structure, with hosts at the leaf nodes.
Traffic generation simulates both normal network activity and potential DDoS attacks.

Usage:
    python3 mininet_setup.py --controller-ip=<controller_ip>
"""

import argparse
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class CustomTreeTopo(Topo):
    """Custom tree topology class for Mininet.
    
    Creates a hierarchical tree network topology with configurable depth and fanout.
    Each level consists of switches, with hosts connected to the leaf switches.
    This topology is suitable for simulating various network scenarios including DDoS attacks.
    """

    def build(self, depth=4, fanout=2):
        """Build the tree topology with specified depth and fanout.
        
        Args:
            depth (int): Number of levels in the tree (default: 4)
            fanout (int): Number of child switches per parent (default: 2)
        """
        # Start the recursive tree creation from the root
        self.create_tree(depth, fanout)

    def create_tree(self, depth, fanout, parent=None):
        """Recursively create tree topology by adding switches and hosts.
        
        Args:
            depth (int): Current depth level in the tree
            fanout (int): Number of children per node
            parent (str): Parent switch name (None for root)
            
        The function creates switches at each level and connects hosts
        to the leaf switches when depth reaches 0.
        """
        # Base case: reached leaf level
        if depth == 0:
            return

        # Create a new switch with an incrementing ID
        # The ID is based on the current number of switches + 1
        switch_id = len(self.switches()) + 1
        switch = self.addSwitch('s{}'.format(switch_id))  # Format: s1, s2, s3, etc.

        # If this switch has a parent (not the root), create a link to it
        # This builds the hierarchical structure of the tree
        if parent:
            self.addLink(parent, switch)  # Creates a bidirectional link

        for _ in range(fanout):
            if depth == 1:
                # Create and link host
                host_id = len(self.hosts()) + 1
                host = self.addHost('h{}'.format(host_id))
                self.addLink(switch, host)
            else:
                self.create_tree(depth - 1, fanout, switch)


def configure_switches(net):
    """Configure OpenFlow switches in the network.
    
    Args:
        net (Mininet): The Mininet network instance.
        
    Applies specific configurations to the OpenFlow switches:
    - Sets OpenFlow protocol versions
    - Configures flow table sizes
    - Enables necessary OpenFlow features
    """
    info("*** Configuring OVS switches...\n")

    for switch in net.switches:
        switch.cmd("ovs-vsctl set bridge {} protocols=OpenFlow13".format(switch))
        switch.cmd("ovs-vsctl set-fail-mode {} secure".format(switch))
        info("Configured {}\n".format(switch))


def generate_traffic(net):
    """Generate network traffic to simulate normal and attack scenarios.
    
    Args:
        net (Mininet): The Mininet network instance.
        
    Simulates:
    - Normal background traffic between hosts
    - Potential DDoS attack traffic patterns
    - Various network conditions for testing
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
    """Initialize and run the Mininet network.
    
    Args:
        controller_ip (str): IP address of the SDN controller.
        
    This function:
    1. Creates the network topology
    2. Connects to the SDN controller
    3. Configures switches and hosts
    4. Starts traffic generation
    5. Provides CLI access for network management
    """
    # Enable Mininet's info logging for better visibility
    setLogLevel('info')

    # Create the network with custom topology and remote controller
    info("*** Creating network\n")
    topo = CustomTreeTopo(depth=3, fanout=2)
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
