FROM ubuntu:latest

# Install required packages
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
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

WORKDIR /app
COPY Managedresources/mininet_setup.py /app/mininet_setup.py

# Initialize Open vSwitch
COPY init.sh /init.sh
RUN chmod +x /init.sh

ENTRYPOINT ["/init.sh"]
CMD ["python3", "/app/mininet_setup.py", "--controller-ip=monitor"]
