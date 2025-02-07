# AI-Cyber-Security
import os
import bcrypt
import requests
import yt_search
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from openai import OpenAI
import joblib
import boto3
from google.cloud import storage

app = Flask(__name__)

# Load environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GCP_BUCKET_NAME = os.getenv("GCP_BUCKET_NAME")
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET")

if not OPENAI_API_KEY or not GCP_BUCKET_NAME or not AWS_S3_BUCKET:
    raise ValueError("Missing environment variables. Set them before running the app.")

client = OpenAI(api_key=OPENAI_API_KEY)

# Admin Credentials (Hashed Password)
ADMIN_USERNAME = "Priyanshu Raj Kushwaha"
ADMIN_PASSWORD_HASH = bcrypt.hashpw("YourSecurePassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password):
    return bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8'))

# Fetch Cybersecurity Threat Intelligence
def fetch_cyber_threats():
    sources = [
        "https://attack.mitre.org/",
        "https://www.virustotal.com/latest-threats",
        "https://www.shodan.io/"
    ]
    threats = []
    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            threats.append(soup.get_text())
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {source}: {e}")
    return " ".join(threats)

# YouTube Search
def fetch_video_links(query):
    return yt_search.YoutubeSearch(query, max_results=5).to_dict()

# AI Summarization
def summarize_text(text):
    try:
        response = client.completions.create(
            model="gpt-4",
            prompt=f"Summarize the following text:\n\n{text}",
            max_tokens=100
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Error: {e}"

# Load AI Security Model (Cloud)
def load_model():
    try:
        s3 = boto3.client("s3")
        s3.download_file(AWS_S3_BUCKET, "intrusion_model.pkl", "/tmp/intrusion_model.pkl")
        return joblib.load("/tmp/intrusion_model.pkl")
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

def detect_intrusion(features):
    model = load_model()
    if model is None:
        return "Model could not be loaded"
    prediction = model.predict([features])
    return "Cyber Attack Detected!" if prediction[0] == 1 else "No Threat"

# API Endpoints
@app.route('/admin', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    if username == ADMIN_USERNAME and check_password(password):
        return jsonify({"message": "Admin access granted", "status": "success"})
    else:
        return jsonify({"message": "Unauthorized", "status": "error"}), 401

@app.route('/search', methods=['POST'])
def search():
    data = request.json
    query = data.get("query", "")

    google_results = fetch_cyber_threats()
    video_results = fetch_video_links(query)

    return jsonify({"google_links": google_results, "video_links": video_results})

@app.route('/summarize', methods=['POST'])
def summarize():
    data = request.json
    text = data.get("text", "")

    summary = summarize_text(text)
    return jsonify({"summary": summary})

@app.route('/cyber_threats', methods=['GET'])
def get_cyber_threats():
    threats = fetch_cyber_threats()
    return jsonify({"cyber_threats": threats})

@app.route('/detect_intrusion', methods=['POST'])
def intrusion():
    data = request.json
    features = data.get("features", [])

    result = detect_intrusion(features)
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
