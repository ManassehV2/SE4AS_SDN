from datetime import datetime
from flask import Flask, request, jsonify
import logging
import requests
import time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
from collections import defaultdict

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# InfluxDB Configuration
INFLUXDB_URL = f"http://{os.getenv('INFLUXDB_HOST', 'influxdb')}:{os.getenv('INFLUXDB_PORT', '8086')}"
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_stats")
INFLUXDB_ORG = os.getenv("DOCKER_INFLUXDB_INIT_ORG", "my-org")
INFLUXDB_USERNAME = os.getenv("DOCKER_INFLUXDB_INIT_USERNAME", "admin")
INFLUXDB_PASSWORD = os.getenv("DOCKER_INFLUXDB_INIT_PASSWORD", "admin123")


client = InfluxDBClient(
    url=INFLUXDB_URL,
    username=INFLUXDB_USERNAME,  
    password=INFLUXDB_PASSWORD,  
    org=INFLUXDB_ORG
)
write_api = client.write_api(write_options=SYNCHRONOUS) 

def fetch_ryu_stats():
    """
    Fetches flow statistics from the Ryu controller REST API.
    Returns key aggregated network metrics.
    """
    try:
        # Get active switches
        switches_response = requests.get("http://monitor:8080/stats/switches")
        switches_response.raise_for_status()
        switches = switches_response.json()  # Example: [1, 2, 3]

        all_flow_stats = []
        switch_total_bytes = defaultdict(int)  # Track bytes per switch
        switch_total_packets = defaultdict(int)  # Track packets per switch

        for switch in switches:
            flow_response = requests.get(f"http://monitor:8080/stats/flow/{switch}")
            flow_response.raise_for_status()
            flow_stats = flow_response.json().get(str(switch), [])

            for flow in flow_stats:
                all_flow_stats.append(flow)
                switch_total_bytes[switch] += flow.get("byte_count", 0)
                switch_total_packets[switch] += flow.get("packet_count", 0)

        return all_flow_stats, switches, switch_total_bytes, switch_total_packets

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch Ryu stats: {e}")
        return [], [], {}, {}

def log_network_usage(phase):
    """
    Logs the most important network statistics before and after mitigation.
    """
    flow_stats, active_switches, switch_total_bytes, switch_total_packets = fetch_ryu_stats()

    if not flow_stats:
        logger.error("No flow stats available for logging!")
        return

    # Aggregate important statistics
    total_packet_count = sum(flow.get("packet_count", 0) for flow in flow_stats)
    total_byte_count = sum(flow.get("byte_count", 0) for flow in flow_stats)
    total_flows = len(flow_stats)
    avg_packet_rate = sum(flow.get("packet_count", 0) / max(flow.get("duration_sec", 1), 1e-6) for flow in flow_stats) / max(total_flows, 1)
    max_flow_duration = max(flow.get("duration_sec", 0) for flow in flow_stats) if flow_stats else 0

    # Identify the "Top Talker" switch (highest byte_count)
    top_switch = max(switch_total_bytes, key=switch_total_bytes.get, default=None)
    top_switch_bytes = switch_total_bytes.get(top_switch, 0)

    timestamp = datetime.utcnow().isoformat()

    # Create InfluxDB data point
    point = Point("network_usage") \
        .tag("phase", phase) \
        .field("total_packet_count", total_packet_count) \
        .field("total_byte_count", total_byte_count) \
        .field("total_flows", total_flows) \
        .field("avg_packet_rate", avg_packet_rate) \
        .field("max_flow_duration", max_flow_duration) \
        .field("num_active_switches", len(active_switches)) \
        .field("top_switch_id", top_switch if top_switch else -1) \
        .field("top_switch_bytes", top_switch_bytes)

    try:
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
        logger.info(f"Logged network-wide usage ({phase}) from Ryu stats to InfluxDB.")
    except Exception as e:
        logger.error(f"Failed to log network-wide stats: {e}")



@app.route('/plan', methods=['POST'])
def plan():
    try:
        classifications = request.json.get("classifications", [])
        actions = []

        logger.info(f"Received {len(classifications)} classifications for planning.")

        # Log optimized network usage BEFORE mitigation
        log_network_usage("before_mitigation")

        for classification in classifications:
            flow = classification["flow"]
            category = classification["category"]
            datapath_id = classification["datapath_id"]

            if category == "Benign":
                actions.append({
                    "datapath_id": datapath_id,
                    "flow": flow,
                    "action": "set-priority",
                    "priority": 100  
                })
            elif category == "Suspicious":
                actions.append({
                    "datapath_id": datapath_id,
                    "flow": flow,
                    "action": "apply-rate-limit",
                    "rate_limit": 1000  
                })
            elif category == "DDoS":
                actions.append({
                    "datapath_id": datapath_id,
                    "flow": flow,
                    "action": "drop"
                })

        response = requests.post("http://execute:5002/execute", json={"actions": actions})

        if response.status_code == 200:
            logger.info("Actions sent to Executor successfully.")
        else:
            logger.error(f"Failed to send actions to Executor: {response.text}")

        time.sleep(30)
        return jsonify(actions), 200

    except Exception as e:
        logger.error(f"Error during planning: {e}")
        return jsonify({"error": "Failed to process classifications"}), 500
    


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
