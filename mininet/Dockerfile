# Use Debian Bookworm slim as base image for smaller size
FROM debian:bookworm-slim

# Install required packages for Mininet and OpenVSwitch
# - mininet: Network emulator
# - net-tools: Basic networking tools
# - iputils-ping: For network connectivity testing
# - python3: Required for running Mininet scripts
# - openvswitch: Software-defined networking switch
# - kmod: For kernel module management
# - iproute2: Modern networking utilities
RUN apt update && \
    apt install -y \
    mininet \
    net-tools \
    iputils-ping \
    python3 \
    python3-pip \
    openvswitch-switch \
    openvswitch-common \
    kmod \
    iproute2 \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory for the application
WORKDIR /app

# Copy the Mininet network topology setup script
# This script creates and configures the virtual network
COPY mininet_setup.py /app/

# Copy and configure Open vSwitch initialization script
# This script starts OpenVSwitch services and creates initial bridge
COPY init.sh /init.sh
RUN chmod +x /init.sh && \
    sed -i 's/\r$//' /init.sh


# Use init.sh as entrypoint to ensure OpenVSwitch is properly initialized
ENTRYPOINT ["/init.sh"]

# Default command creates the Mininet network topology
# Uses the 'monitor' service as the SDN controller
CMD ["python3", "/app/mininet_setup.py", "--controller-ip=monitor"]
