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
    This topology is suitable for simulating DDoS attacks.
    """

    def build(self, depth=3, fanout=4):
        """Build the tree topology with specified depth and fanout.
        
        Args:
            depth (int): Number of levels in the tree (default: 3)
            fanout (int): Number of child switches per parent (default: 4)
        """
        # Start the recursive tree creation from the root
        self.create_tree(depth, fanout)

    def create_tree(self, depth, fanout, parent=None):
        """Recursively create tree topology by adding switches and hosts.
        
        Args:
            depth (int): Current depth level in the tree
            fanout (int): Number of children per node
            parent (str): Parent switch name (None for root)
        """
        # Base case: reached leaf level
        if depth == 0:
            return

        # Create a new switch
        switch_id = len(self.switches()) + 1
        switch = self.addSwitch(f's{switch_id}')

        # Connect to parent if not root
        if parent:
            self.addLink(parent, switch)

        # Add child nodes
        for _ in range(fanout):
            if depth == 1:
                # Create and link host at leaf level
                host_id = len(self.hosts()) + 1
                host = self.addHost(f'h{host_id}')
                self.addLink(switch, host)
            else:
                # Create subtree
                self.create_tree(depth - 1, fanout, switch)


def configure_switches(net):
    """Configure OpenFlow switches for the simulation."""
    info("*** Configuring switches...\n")
    for switch in net.switches:
        # Set OpenFlow 1.3
        switch.cmd(f"ovs-vsctl set bridge {switch} protocols=OpenFlow13")


def generate_traffic(net):
    """Generate DDoS attack traffic in the tree topology.
    
    The last host will be the target, and all other hosts will be attackers.
    Each attacker will generate multiple types of attack traffic.
    """
    info("*** Starting DDoS attack simulation\n")
    
    # Get all hosts
    hosts = net.hosts
    target = hosts[-1]  # Last host is the target
    attackers = hosts[:-1]  # All other hosts are attackers
    
    # Start HTTP server on target
    target.cmd("python3 -m http.server 80 &")
    info(f"*** Started HTTP server on target {target.name}\n")
    
    # Start attacks from all attackers
    info(f"*** Starting attacks from {len(attackers)} hosts\n")
    for attacker in attackers:
        # Launch multiple attack types from each attacker
        attacker.cmd(f"hping3 --flood --syn -p 80 {target.IP()} &")  # SYN flood
        attacker.cmd(f"ping {target.IP()} -f &")  # ICMP flood
        attacker.cmd(f"while true; do wget http://{target.IP()}:80 -O /dev/null; done &")  # HTTP flood
        info(f"*** Started attacks from {attacker.name}\n")
    
    info(f"*** DDoS attack traffic started from {len(attackers)} hosts to {target.name}\n")


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
