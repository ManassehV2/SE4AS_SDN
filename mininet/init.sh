#!/bin/bash

# OpenVSwitch Initialization Script
# This script initializes and starts OpenVSwitch services required for Mininet

# Create necessary directories for OpenVSwitch operation
mkdir -p /var/run/openvswitch
mkdir -p /etc/openvswitch

# Create and initialize the OpenVSwitch database if it doesn't exist
# This database stores switch configurations and flow rules
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start the OpenVSwitch database server
# This manages the switch configurations
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
             --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
             --pidfile --detach

# Initialize OpenVSwitch and wait for the database to be ready
ovs-vsctl --no-wait init

# Start the OpenVSwitch daemon
# This is the main switch process that handles packet forwarding
ovs-vswitchd --pidfile --detach

# Wait for the switch daemon to fully initialize
sleep 3

# Create the default bridge for OpenVSwitch
# This bridge will be used by Mininet for the virtual network
ovs-vsctl --may-exist add-br br0

# Execute the command passed to docker run
# This will typically be the Mininet setup script
exec "$@"
wait_for_service "ovsdb" 30 "ovs-vsctl show >/dev/null 2>&1"

# Initialize OpenVSwitch
echo "Initializing OpenVSwitch..."
ovs-vsctl --no-wait init

# Start the OpenVSwitch daemon
echo "Starting OpenVSwitch daemon..."
ovs-vswitchd --pidfile --detach

# Wait for the switch daemon to be ready
wait_for_service "ovs-vswitchd" 30 "ovs-vsctl show | grep -q ovs_version"

# Configure networking for WSL2
echo "Configuring WSL2 networking..."
service openvswitch-switch start || true

# Create the default bridge for OpenVSwitch
echo "Creating default bridge..."
ovs-vsctl --may-exist add-br br0

# Set bridge protocols for better compatibility
ovs-vsctl set bridge br0 protocols=OpenFlow13

# Execute the command passed to docker run
exec "$@"
