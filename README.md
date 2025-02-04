# SE4AS SDN Project

This project implements a Self-Adaptive Software-Defined Network (SDN) controller using the MAPE-K (Monitor, Analyze, Plan, Execute) feedback loop architecture. The system is designed to automatically adapt network configurations based on real-time monitoring and analysis.

## Architecture

The project follows a microservices architecture with the following components:

### MAPE-K Components

1. **Monitor**
   - Collects network statistics and metrics
   - Exposes ports 6653 (OpenFlow) and 8080 (HTTP)
   - Interfaces with SDN switches

2. **Analyze**
   - Processes collected network data
   - Identifies patterns and potential issues

3. **Plan**
   - Determines appropriate actions based on analysis
   - Generates adaptation strategies

4. **Execute**
   - Implements network changes
   - Exposes port 5002
   - Includes health monitoring

### Supporting Infrastructure

- **InfluxDB**
  - Time-series database for storing network metrics
  - Runs on port 8086
  - Configured with initial setup for 'network_stats' bucket

## Prerequisites

- Docker
- Docker Compose

## Setup and Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd SE4AS_SDN
   ```

2. Start the services:
   ```bash
   docker-compose up -d
   ```

## Configuration

### InfluxDB
- Username: admin
- Organization: my-org
- Default bucket: network_stats
- Port: 8086

## Project Structure

```
├── Managedresources/    # Managed network resources
├── analyze/             # Analysis component
├── docker-compose.yml   # Docker composition file
├── execute/             # Execution component
├── influxdb-config/     # InfluxDB configuration
├── monitor/             # Monitoring component
└── plan/                # Planning component
```

## Networks

All services are connected through the `se4as_network` Docker network for internal communication.

## Resource Management

The services include resource management configurations for optimal performance and reliability.

## Contributing

Please read the contribution guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.