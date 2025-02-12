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
    Uses received actions from `plan` to calculate network statistics.
    Separates normal and mitigated flows for better analysis.
    Returns metrics for both normal and mitigated flows.
    """
    try:
        if not actions:
            logger.warning("No actions available for logging!")
            return {
                'normal': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0},
                'mitigated': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0}
            }

        stats = {
            'normal': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0},
            'mitigated': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0}
        }

        for action_item in actions:
            flow = action_item.get("flow", {})
            action = action_item.get("action")
            
            # Categorize flow based on action
            category = 'mitigated' if action in ["drop", "apply-rate-limit"] else 'normal'
            
            stats[category]['flows'] += 1
            stats[category]['packets'] += flow.get("packet_count", 0)
            stats[category]['bytes'] += flow.get("byte_count", 0)
            stats[category]['byte_rate'] += flow.get("byte_rate", 0)

        return stats

    except Exception as e:
        logger.error(f"Failed to process received actions: {e}")
        return {
            'normal': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0},
            'mitigated': {'flows': 0, 'packets': 0, 'bytes': 0, 'byte_rate': 0}
        }


def calculate_mitigation_metrics(stats):
    """
    Calculate additional metrics to measure mitigation effectiveness.
    """
    total_flows = stats['normal']['flows'] + stats['mitigated']['flows']
    if total_flows == 0:
        return {
            'mitigation_ratio': 0,
            'traffic_reduction': 0,
            'bandwidth_savings': 0
        }

    metrics = {
        'mitigation_ratio': stats['mitigated']['flows'] / total_flows,
        'traffic_reduction': (
            1 - (stats['normal']['byte_rate'] / (stats['normal']['byte_rate'] + stats['mitigated']['byte_rate']))
            if (stats['normal']['byte_rate'] + stats['mitigated']['byte_rate']) > 0 else 0
        ),
        'bandwidth_savings': stats['mitigated']['byte_rate']  # Bytes/sec prevented from flowing
    }
    return metrics

def log_network_usage_after_mitigation(actions):
    """
    Logs detailed network statistics after mitigation to InfluxDB.
    Tracks both normal and mitigated flows separately.
    """
    stats = fetch_ryu_stats(actions)
    timestamp = datetime.now().isoformat()
    
    # Calculate mitigation effectiveness metrics
    effectiveness = calculate_mitigation_metrics(stats)
    
    # Log normal traffic stats
    normal_point = Point("network_usage") \
        .tag("phase", "after_mitigation") \
        .tag("traffic_type", "normal") \
        .field("flows", stats['normal']['flows']) \
        .field("packet_count", stats['normal']['packets']) \
        .field("byte_count", stats['normal']['bytes']) \
        .field("byte_rate", stats['normal']['byte_rate']) \
        .time(timestamp, WritePrecision.NS)

    # Log mitigated traffic stats
    mitigated_point = Point("network_usage") \
        .tag("phase", "after_mitigation") \
        .tag("traffic_type", "mitigated") \
        .field("flows", stats['mitigated']['flows']) \
        .field("packet_count", stats['mitigated']['packets']) \
        .field("byte_count", stats['mitigated']['bytes']) \
        .field("byte_rate", stats['mitigated']['byte_rate']) \
        .time(timestamp, WritePrecision.NS)

    # Log mitigation effectiveness metrics
    effectiveness_point = Point("mitigation_effectiveness") \
        .field("mitigation_ratio", effectiveness['mitigation_ratio']) \
        .field("traffic_reduction", effectiveness['traffic_reduction']) \
        .field("bandwidth_savings", effectiveness['bandwidth_savings']) \
        .time(timestamp, WritePrecision.NS)

    try:
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=[normal_point, mitigated_point, effectiveness_point])
        logger.info(f"Logged detailed network stats to InfluxDB with mitigation effectiveness metrics")
        logger.info(f"Mitigation effectiveness: {effectiveness}")
    except Exception as e:
        logger.error(f"Failed to log network stats: {e}")


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
