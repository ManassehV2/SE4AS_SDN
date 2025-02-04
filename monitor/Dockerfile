FROM osrg/ryu:latest

WORKDIR /app

# Install necessary packages
RUN apt-get update && apt-get install -y \
    iputils-ping \
    git \
    iproute2 \
    net-tools \
    python3-pip \
    hping3 && \
    apt-get clean

# Install Python dependencies
RUN pip3 install requests

# Copy the custom controller
COPY . /app

# Set PYTHONPATH
ENV PYTHONPATH="/app:$PYTHONPATH"

# Expose necessary ports
EXPOSE 6653 8080 5001

# Start the Ryu controller with REST API and Monitor Controller
CMD ["ryu-manager", "ryu.app.ofctl_rest", "/app/monitor_topology.py"]
