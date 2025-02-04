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

def fetch_ryu_stats(classifications):
    """
    Uses received classifications instead of fetching data from `/stats/flow`.
    Retrieves active switches from `/stats/switches`.
    """
    try:
        if not classifications:
            logger.warning("No classifications available for logging!")
            return [], 0, {}, {}, {}, 0  # Add 0 for byte_rate

        all_flow_stats = classifications  # Use received classifications
        switch_total_bytes = defaultdict(int)
        switch_total_packets = defaultdict(int)
        switch_durations = defaultdict(list)
        total_byte_rate = 0  # Initialize total byte rate

        # Retrieve active switches from `/stats/switches`
        try:
            response = requests.get("http://monitor:8080/stats/switches")
            response.raise_for_status()
            active_switches = len(response.json())  # Get the count of active switches
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch active switches: {e}")
            active_switches = 0

        # Aggregate statistics per switch
        for classification in all_flow_stats:
            flow = classification.get("flow", {})
            datapath_id = classification.get("datapath_id")

            switch_total_bytes[datapath_id] += flow.get("byte_count", 0)
            switch_total_packets[datapath_id] += flow.get("packet_count", 0)
            total_byte_rate += flow.get("byte_rate", 0)  # Aggregate byte rate

            duration = flow.get("duration_sec", 0) + flow.get("duration_nsec", 0) / 1e9
            switch_durations[datapath_id].append(duration)

        return all_flow_stats, active_switches, switch_total_bytes, switch_total_packets, switch_durations, total_byte_rate

    except Exception as e:
        logger.error(f"Failed to process received classifications: {e}")
        return [], 0, {}, {}, {}, 0


def log_network_usage(phase, classifications):
    """
    Logs network statistics from the received classifications instead of fetching from Ryu.
    Now includes byte_rate.
    """
    flow_stats, active_switches, switch_total_bytes, switch_total_packets, switch_durations, total_byte_rate = fetch_ryu_stats(classifications)

    if not flow_stats:
        logger.error("No flow stats available for logging!")
        return

    # Compute other metrics
    total_packet_count = sum(flow["flow"].get("packet_count", 0) for flow in flow_stats)
    total_byte_count = sum(flow["flow"].get("byte_count", 0) for flow in flow_stats)
    total_flows = len(flow_stats)

    avg_packet_rate = sum(
        flow["flow"].get("packet_count", 0) / max(flow["flow"].get("duration_sec", 1) + flow["flow"].get("duration_nsec", 0) / 1e9, 1e-6)
        for flow in flow_stats
    ) / max(total_flows, 1)

    max_flow_duration = max(
        (flow["flow"].get("duration_sec", 0) + flow["flow"].get("duration_nsec", 0) / 1e9) for flow in flow_stats
    ) if flow_stats else 0

    top_switch = max(switch_total_bytes, key=switch_total_bytes.get, default=None)
    top_switch_bytes = switch_total_bytes.get(top_switch, 0)

    timestamp = datetime.utcnow().isoformat()

    # Store metrics to InfluxDB  
    point = Point("network_usage") \
        .tag("phase", phase) \
        .field("total_packet_count", total_packet_count) \
        .field("total_byte_count", total_byte_count) \
        .field("total_flows", total_flows) \
        .field("avg_packet_rate", avg_packet_rate) \
        .field("max_flow_duration", max_flow_duration) \
        .field("num_active_switches", active_switches) \
        .field("top_switch_id", top_switch if top_switch else -1) \
        .field("top_switch_bytes", top_switch_bytes) \
        .field("total_byte_rate", total_byte_rate)  # Add byte_rate field

    try:
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
        logger.info(f"Logged network-wide usage ({phase}) with total_byte_rate: {total_byte_rate}")
    except Exception as e:
        logger.error(f"Failed to log network-wide stats: {e}")


@app.route('/plan', methods=['POST'])
def plan():
    try:
        classifications = request.json.get("classifications", [])
        actions = []

        logger.info(f"Received {len(classifications)} classifications for planning.")

        # Log optimized network usage BEFORE mitigation
        log_network_usage("before_mitigation", classifications)

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
