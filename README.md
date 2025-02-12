# SE4AS SDN Project - DDoS Mitigation System

This project implements a Self-Adaptive Software-Defined Network (SDN) controller using the MAPE-K (Monitor, Analyze, Plan, Execute) feedback loop architecture. The system provides automated DDoS attack detection and mitigation through real-time network monitoring and adaptive control.

## System Overview

### System Architecture

![System Architecture](images/System_Architecture.png)

The system implements a complete MAPE-K feedback loop for network management with the following components:

1. **Mininet**: Network emulation environment
2. **RYU SDN Controller**: OpenFlow controller for network management
3. **Analyzer**: Flow classification using machine learning
4. **Planner**: Determines mitigation strategies
5. **Executor**: Implements network changes
6. **InfluxDB**: Knowledge base for metrics storage
7. **Grafana**: Visualization and monitoring

### System Workflow

![Sequence Diagram](images/Sequence_Diagram.png)

The sequence diagram shows the detailed workflow of the system:

1. **Monitoring Phase**
   - Network traffic flows are collected
   - Flow Monitor sends data for classification

2. **Analysis Phase**
   - Analyzer classifies flows (Benign/Suspicious/DDoS)
   - Classifications are sent to Planner

3. **Planning Phase**
   - Planner determines appropriate actions
   - Actions are sent to Executor

4. **Execution Phase**
   - Flow modifications are applied
   - Metrics are calculated and logged
   - Execution status is returned

5. **Visualization**
   - Metrics are queried and displayed in Grafana
   - Shows traffic distribution and effectiveness

### Dashboard Visualization

![Dashboard](images/Dashboard.png)

The Grafana dashboard provides real-time monitoring of:

1. **Mitigation Effectiveness Overview**:
   - Mitigation Ratio: 78.6% of flows being mitigated
   - Traffic Reduction: 14.6% reduction in malicious traffic

2. **Network Traffic Distribution**:
   - Real-time comparison of normal vs mitigated traffic
   - Line graph showing traffic patterns over time

3. **Bandwidth Savings Over Time**:
   - Tracks network resources preserved through mitigation
   - Historical view of mitigation effectiveness

4. **Flow Count by Type**:
   - Bar chart comparing normal vs mitigated flows
   - Quick visualization of traffic composition

5. **Packet Rate Comparison**:
   - Detailed view of packet rates for both traffic types
   - Helps identify attack patterns and normal behavior

### Key Features

- Real-time network flow monitoring
- Automatic DDoS attack detection
- Adaptive traffic classification (Benign/Suspicious/DDoS)
- Automated mitigation strategies
- Comprehensive metrics and visualization
- Docker-based microservices architecture

## Prerequisites

- Docker Engine (20.10.0 or higher)
- Docker Compose (2.0.0 or higher)
- 4GB RAM minimum
- 10GB free disk space

## Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/ManassehV2/SE4AS_SDN.git
   cd SE4AS_SDN
   ```

2. **Start the System**
   ```bash
   # Build and start all services
   docker-compose up -d

   # Verify all services are running
   docker-compose ps
   ```

3. **Access System Interfaces**

   a. **Grafana Dashboard**
   - URL: http://localhost:3000
   - Default credentials:
     - Username: admin
     - Password: admin
   - Features:
     - Real-time traffic monitoring
     - Mitigation effectiveness metrics
     - Network flow analysis

   b. **Network Topology**
   - URL: http://localhost:8080
   - Visualize the complete SDN network topology
   - Monitor real-time network connections

## Component Details

### 1. Monitor (Ports: 6653, 8080)
- Collects network flow statistics
- Interfaces with SDN switches via OpenFlow
- Exposes REST API for flow data

### 2. Analyzer (Port: 5004)
- Classifies network flows
- Detection criteria:
  - Flow rate analysis
  - Packet pattern matching
  - Traffic distribution analysis

### 3. Planner (Port: 5001)
- Determines mitigation actions
- Action types:
  - set-priority: Normal traffic
  - apply-rate-limit: Suspicious flows
  - drop: Confirmed DDoS flows

### 4. Executor (Port: 5002)
- Implements mitigation actions
- Logs effectiveness metrics
- Provides feedback for adaptation

### 5. InfluxDB (Port: 8086)
- Stores network metrics
- Configuration:
  - Organization: my-org
  - Bucket: network_stats
  - Retention: 7 days

## Monitoring and Visualization

### Grafana Dashboards

1. **Traffic Overview Panel**
   - Real-time traffic distribution
   - Normal vs. Mitigated flows
   - Query:
     ```flux
     from(bucket: "network_stats")
       |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
       |> filter(fn: (r) => r["_measurement"] == "network_usage")
       |> filter(fn: (r) => r["_field"] == "byte_rate")
     ```

2. **Mitigation Effectiveness**
   - Traffic reduction ratio
   - Bandwidth savings
   - Mitigation success rate

3. **Flow Analysis**
   - Packet rate comparison
   - Flow count by type
   - Bandwidth utilization

### Key Metrics

- **Traffic Reduction**: Percentage of mitigated traffic
- **Mitigation Ratio**: Proportion of flows requiring mitigation
- **Bandwidth Savings**: Network resources preserved

## Troubleshooting

1. **Service Health Check**
   ```bash
   docker-compose ps
   docker logs se4as_monitor
   ```

2. **Common Issues**
   - InfluxDB connection: Check credentials and ports
   - Monitor not receiving flows: Verify SDN switch connectivity
   - High CPU usage: Check resource allocation in docker-compose.yml

3. **Metric Collection Issues**
   ```bash
   # Check InfluxDB status
   curl -I http://localhost:8086
   
   # Verify metrics writing
   docker logs se4as_execute | grep "Logged network stats"
   ```

## Configuration

### Environment Variables
```env
INFLUXDB_HOST=influxdb
INFLUXDB_PORT=8086
INFLUXDB_BUCKET=network_stats
DOCKER_INFLUXDB_INIT_ORG=my-org
DOCKER_INFLUXDB_INIT_USERNAME=admin
DOCKER_INFLUXDB_INIT_PASSWORD=admin123
```

### Resource Limits
```yaml
services:
  monitor:
    mem_limit: 512M
  analyze:
    mem_limit: 256M
  plan:
    mem_limit: 256M
  execute:
    mem_limit: 256M
```

## Project Structure
```
SE4AS_SDN/
├── monitor/
│   ├── app/
│   │   ├── flow_monitor.py    # Flow statistics collection
│   │   └── simple_controller.py
│   └── Dockerfile
├── analyze/
│   ├── app/
│   │   └── analyze.py         # Traffic classification
│   └── Dockerfile
├── plan/
│   ├── app/
│   │   └── plan.py           # Mitigation planning
│   └── Dockerfile
├── execute/
│   ├── app/
│   │   └── execute.py        # Action implementation
│   └── Dockerfile
├── influxdb-config/          # InfluxDB configuration
├── docker-compose.yml        # Service orchestration
└── README.md
```

## Networks
All services communicate through the `se4as_network` Docker network:
```yaml
networks:
  se4as_network:
    driver: bridge
```

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Submit pull request

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Support
For issues and feature requests, please use the GitHub issue tracker.