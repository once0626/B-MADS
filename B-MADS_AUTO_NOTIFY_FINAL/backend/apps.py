
from flask import Flask, request, jsonify
from flask_cors import CORS
import os, shutil, time
from static_analysis import analyze_file

app = Flask(__name__)
CORS(app)

SAFE_SCAN_DIR = "safe_scan"
os.makedirs(SAFE_SCAN_DIR, exist_ok=True)

last_result = {}

@app.route("/scan", methods=["POST"])
def scan():
    global last_result
    data = request.get_json(force=True)
    original_path = data.get("filepath")

    if not original_path or not os.path.exists(original_path):
        return jsonify({"verdict":"Error","reason":"file not found"}), 400

    filename = os.path.basename(original_path)
    safe_path = os.path.join(SAFE_SCAN_DIR, filename)

    for _ in range(3):
        try:
            time.sleep(1)
            shutil.copy2(original_path, safe_path)
            break
        except PermissionError:
            time.sleep(1)
    else:
        last_result = {"verdict":"Error","reason":"File locked by system, retry scan"}
        return jsonify(last_result), 423

    result = analyze_file(safe_path)
    last_result = result
    return jsonify(result)

@app.route("/last-result")
def last():
    return jsonify(last_result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
