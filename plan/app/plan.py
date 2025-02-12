from flask import Flask, request, jsonify
import logging
import requests
import time

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)




@app.route('/plan', methods=['POST'])
def plan():
    try:
        classifications = request.json.get("classifications", [])
        actions = []

        logger.info(f"Received {len(classifications)} classifications for planning.")

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
