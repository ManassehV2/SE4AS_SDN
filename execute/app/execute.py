from flask import Flask, request, jsonify
import requests
import logging
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# InfluxDB Configuration (same as Planner)
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

# Ryu REST API URL
RYU_REST_API_URL = "http://monitor:8080/stats/flowentry/add"

def send_flow_modification(flow, action):
    """
    Send flow modification to the Ryu controller.
    """
    try:
        datapath_id = flow.get("datapath_id")
        priority = flow.get("priority", 1)

        if not datapath_id:
            raise ValueError("Missing 'datapath_id'")

        match = flow.get("match", {})

        # Define instructions based on action
        if action == "set-priority":
            instructions = [{"type": "APPLY_ACTIONS", "actions": [{"type": "OUTPUT", "port": "NORMAL"}]}]
        elif action == "apply-rate-limit":
            instructions = [{"type": "APPLY_ACTIONS", "actions": [{"type": "METER", "meter_id": 1}]}]
        elif action == "drop":
            instructions = [{"type": "APPLY_ACTIONS", "actions": []}]  # Drop packets
        else:
            raise ValueError(f"Unknown action: {action}")

        flow_mod = {
            "dpid": int(datapath_id),
            "cookie": 0,
            "cookie_mask": 0,
            "table_id": 0,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "priority": priority,
            "match": match,
            "instructions": instructions,
        }

        logger.info(f"Sending flow modification: {flow_mod}")
        response = requests.post(RYU_REST_API_URL, json=flow_mod)
        response.raise_for_status()
        logger.info(f"Successfully applied action '{action}' to flow: {flow}")

        return True

    except requests.exceptions.RequestException as e:
        logger.error(f"Ryu controller communication error: {e}")
        return False
    except Exception as e:
        logger.error(f"Error in send_flow_modification: {e}")
        return False

def fetch_ryu_stats(actions):
    """
    Uses received actions from `plan` instead of fetching data from Ryu `/stats/flow`.
    Excludes DDoS flows from the statistics.
    Returns key aggregated network metrics, including byte_rate.
    """
    try:
        if not actions:
            logger.warning("No actions available for logging!")
            return 0, 0, 0, 0  # Add 0 for byte_rate

        total_packet_count = 0
        total_byte_count = 0
        total_flows = 0
        total_byte_rate = 0  # Initialize total byte rate

        # Aggregate statistics, excluding DDoS flows
        for action_item in actions:
            flow = action_item.get("flow", {})
            category = action_item.get("action")  # This contains "drop" for DDoS

            if category == "drop" or category == "apply-rate-limit":
                continue  # Skip logging this flow

            total_flows += 1
            total_packet_count += flow.get("packet_count", 0)
            total_byte_count += flow.get("byte_count", 0)
            total_byte_rate += flow.get("byte_rate", 0)  # Aggregate byte_rate

        return total_flows, total_packet_count, total_byte_count, total_byte_rate

    except Exception as e:
        logger.error(f"Failed to process received actions: {e}")
        return 0, 0, 0, 0  # Return default values


def log_network_usage_after_mitigation(actions):
    """
    Logs network statistics after mitigation to InfluxDB.
    Excludes DDoS flows from the statistics.
    """
    total_flows, total_packet_count, total_byte_count, total_byte_rate = fetch_ryu_stats(actions)
    timestamp = datetime.utcnow().isoformat()

    point = Point("network_usage") \
        .tag("phase", "after_mitigation") \
        .field("total_flows", total_flows) \
        .field("total_packet_count", total_packet_count) \
        .field("total_byte_count", total_byte_count) \
        .field("total_byte_rate", total_byte_rate) \
        .time(timestamp, WritePrecision.NS)

    try:
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
        logger.info(f"Logged 'after_mitigation' network stats (excluding DDoS) to InfluxDB, with byte_rate: {total_byte_rate}")
    except Exception as e:
        logger.error(f"Failed to log 'after_mitigation' network stats: {e}")


@app.route('/execute', methods=['POST'])
def execute():
    """
    Receive actions from the Planner and execute them
    by sending flow modifications to the Ryu controller.
    """
    try:
        actions = request.json.get("actions", [])
        if not actions:
            return jsonify({"error": "No actions received"}), 400

        logger.info(f"Received {len(actions)} actions for execution.")

        results = []
        for action_item in actions:
            flow = action_item.get("flow")
            action = action_item.get("action")
            datapath_id = action_item.get("datapath_id")

            if not flow or not datapath_id:
                results.append({"flow": flow, "action": action, "success": False, "error": "Missing data"})
                continue

            success = send_flow_modification(flow, action)
            results.append({"flow": flow, "action": action, "success": success})

        # Wait for some time to let mitigation take effect
        time.sleep(30)

        # Log network stats AFTER mitigation
        log_network_usage_after_mitigation(actions)

        return jsonify({"results": results}), 200

    except Exception as e:
        logger.error(f"Error in execute endpoint: {e}")
        return jsonify({"error": "Failed to execute actions"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
