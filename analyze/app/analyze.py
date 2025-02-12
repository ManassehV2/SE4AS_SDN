from flask import Flask, request, jsonify
import logging
import pandas as pd
import joblib
import requests
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
from datetime import datetime

app = Flask(__name__)

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

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load the trained model and feature columns
MODEL_PATH = "flow_classifier_with_features.joblib"
try:
    # Load the model and feature list
    model_and_features = joblib.load(MODEL_PATH)
    model = model_and_features['model']
    feature_columns = model_and_features['features']
    logger.info("{}".format(feature_columns))
    logger.info("Model and feature columns loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None
    feature_columns = []

def calculate_adaptive_thresholds(probabilities):
    """
    Calculate adaptive thresholds for classification.
    """
    mean_prob = probabilities.mean()
    std_prob = probabilities.std()
    T1 = max(0, mean_prob - 0.5 * std_prob)  # Lower threshold for Benign
    T2 = min(1, mean_prob + 0.5 * std_prob)  # Upper threshold for DDoS
    return T1, T2

def classify_flow(prob, T1, T2):
    """
    Classify a flow based on its probability and adaptive thresholds.
    """
    if prob < T1:
        return "Benign"
    elif prob > T2:
        return "DDoS"
    else:
        return "Suspicious"

@app.route('/classify', methods=['POST'])
def classify():
    """
    Endpoint to classify flows sent by the Ryu controller.
    """
    try:
        flows = request.json.get("flows", [])
        logger.info(f"Received {len(flows)} flows for classification.")

        # Ensure the model is loaded
        if model is None:
            raise ValueError("Model is not loaded.")

        # Convert flows to DataFrame
        flow_df = pd.DataFrame(flows)

        # Add missing columns and fill with default values (0)
        for col in feature_columns:
            if col not in flow_df.columns:
                flow_df[col] = 0  # Default missing feature values to 0

        # Ensure correct feature ordering
        flow_df = flow_df[feature_columns]

        # Predict probabilities
        probabilities = model.predict_proba(flow_df)[:, 1]  # Assuming class 1 is DDoS
        logger.info(f"Predicted probabilities: {probabilities}")

        # Calculate adaptive thresholds
        T1, T2 = calculate_adaptive_thresholds(probabilities)
        logger.info(f"Adaptive thresholds calculated: T1={T1}, T2={T2}")

        # Classify based on adaptive thresholds
        categories = [classify_flow(prob, T1, T2) for prob in probabilities]

        # Prepare results
        results = [
            {
                "datapath_id": flow.get("datapath_id"),
                "flow": flow,
                "probability": prob,
                "category": category,
            }
            for flow, prob, category in zip(flows, probabilities, categories)
        ]

        # Log category distribution
        benign_count = categories.count('Benign')
        suspicious_count = categories.count('Suspicious')
        ddos_count = categories.count('DDoS')
        
        logger.info(f"Category distribution: "
                    f"Benign={benign_count}, "
                    f"Suspicious={suspicious_count}, "
                    f"DDoS={ddos_count}")
        
        # Send category distribution to InfluxDB
        point = Point("flow_categories")\
            .field("benign_flows", benign_count)\
            .field("suspicious_flows", suspicious_count)\
            .field("ddos_flows", ddos_count)\
            .time(datetime.now().isoformat(), WritePrecision.NS)
        
        try:
            write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
            logger.info("Successfully sent category distribution to InfluxDB")
        except Exception as e:
            logger.error(f"Failed to send data to InfluxDB: {str(e)}")

        
        # Send to Planner
        try:
            response = requests.post(
                "http://plan:5001/plan", json={"classifications": results})
            response.raise_for_status()
            logger.info("Classifications sent to Planner successfully.")
        except Exception as e:
            logger.error(f"Failed to send classifications to Planner: {e}")

        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Error during classification: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004)
