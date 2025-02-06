#!/bin/bash

# Start Open vSwitch
mkdir -p /var/run/openvswitch
mkdir -p /etc/openvswitch

# Initialize the database if it doesn't exist
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start ovsdb-server
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
             --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
             --pidfile --detach

# Wait for ovsdb to start
ovs-vsctl --no-wait init

# Start ovs-vswitchd
ovs-vswitchd --pidfile --detach

# Wait for vswitchd to start
sleep 3

# Create the default bridge
ovs-vsctl --may-exist add-br br0

# Execute the command passed to docker run
exec "$@"
