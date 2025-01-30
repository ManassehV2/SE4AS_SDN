FROM osrg/ryu:latest

WORKDIR /app

# Install dependencies, including Mininet
RUN apt-get update && apt-get install -y \
    iputils-ping \
    git \
    openvswitch-switch \
    iproute2 \
    net-tools \
    python-pip \
    python-dev \
    mininet \
    hping3 && \
    apt-get clean

# Clone Ryu repo to restore missing GUI files
RUN git clone https://github.com/faucetsdn/ryu.git && \
    cp -r ryu/ryu/app/gui_topology/html /usr/local/lib/python2.7/dist-packages/ryu/app/gui_topology/ && \
    rm -rf ryu

# Copy custom monitor app
COPY . /app

# Install additional Python dependencies
RUN pip install requests scapy==2.5.0

# Set PYTHONPATH to include /app
ENV PYTHONPATH="/app:$PYTHONPATH"

# Expose necessary ports
EXPOSE 8080 6653

# Start Open vSwitch services and Ryu controller
CMD service openvswitch-switch start && \
    ryu-manager \
    ryu.app.ofctl_rest \
    ryu.app.gui_topology.gui_topology \
    ryu.app.rest_topology \
    ryu.app.ws_topology \
    ryu.topology.switches \
    monitor_topology