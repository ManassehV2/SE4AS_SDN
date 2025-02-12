# Use the official Python 3.8 slim image as the base
FROM python:3.8-slim

# Set the working directory
WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    git \
    iproute2 \
    net-tools \
    hping3 && \
    apt-get clean

# Install Ryu and dependencies with specific versions
RUN pip install \
    ryu==4.34 \
    eventlet==0.30.2 \
    requests==2.27.1 \
    urllib3==1.26.15 \
    websocket-client==1.2.3

# Clone the Ryu repository to get the missing static files
RUN git clone https://github.com/faucetsdn/ryu.git && \
    cp -r ryu/ryu/app/gui_topology/html /usr/local/lib/python3.8/site-packages/ryu/app/gui_topology/ && \
    rm -rf ryu

# Copy your custom controller code into the container
COPY . /app

# Set the PYTHONPATH environment variable
ENV PYTHONPATH="/app:$PYTHONPATH"

# Expose the necessary ports
EXPOSE 6653 8080

# Command to start the Ryu controller with all required apps
CMD ["ryu-manager", "--verbose", "--observe-links", \
     "ryu.app.simple_switch_13", \
     "ryu.app.ofctl_rest", \
     "ryu.app.rest_topology", \
     "ryu.app.ws_topology", \
     "ryu.app.gui_topology.gui_topology", \
     "/app/flow_monitor.py"]
