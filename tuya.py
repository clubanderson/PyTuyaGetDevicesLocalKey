from flask import Flask, request, jsonify
import os
import hashlib
import hmac
import requests
import time
import json
# import random
# import string
import sys
from typing import Any, Dict, List

app = Flask(__name__)

from urllib.parse import urlparse, parse_qsl, urlencode
import yaml  # To read Home Assistant secrets

# Load Home Assistant secrets.yaml
SECRETS_FILE = os.getenv("HOME_ASSISTANT_CONFIG", "config/secrets.yaml")

with open(SECRETS_FILE, "r") as secrets_file:
    secrets = yaml.safe_load(secrets_file)

# Set debug value to True or False to (de)activate output
DEBUG = True
EMPTYBODYENCODED = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TUYATIME = str(int(time.time()) * 1000)

# Read Tuya API Credentials from secrets.yaml
TUYA_API_BASE_URL = "https://openapi.tuyaus.com"  
CLIENT_ID = secrets["tuya_client_id"]
CLIENT_SECRET = secrets["tuya_client_secret"]
BASE_URL = secrets["tuya_base_url"]

# ✅ Global Token Storage
ACCESS_TOKEN = None
TOKEN_EXPIRATION = 0

# Load and parse the device list from secrets.yaml (stored as JSON string)
DEVICE_LIST = json.loads(secrets["tuya_device_list"])

# def get_access_token1(ClientID, ClientSecret, BaseUrl, EMPTYBODYENCODED, TUYATIME, DEBUG):
#     # Get Access Token
#     URL = "/v1.0/token?grant_type=1"

#     StringToSign = f"{ClientID}{TUYATIME}GET\n{EMPTYBODYENCODED}\n\n{URL}"
#     if DEBUG:
#         print("StringToSign is now", StringToSign)

#     AccessTokenSign = hmac.new(ClientSecret.encode(), StringToSign.encode(), hashlib.sha256).hexdigest().upper()
#     if DEBUG:
#         print("AccessTokenSign is now", AccessTokenSign)

#     headers = {
#         "sign_method": "HMAC-SHA256",
#         "client_id": ClientID,
#         "t": TUYATIME,
#         "mode": "cors",
#         "Content-Type": "application/json",
#         "sign": AccessTokenSign
#     }

#     AccessTokenResponse = requests.get(BaseUrl + URL, headers=headers).json()
#     if DEBUG:
#         print("AccessTokenResponse is now", AccessTokenResponse)

#     AccessToken = AccessTokenResponse.get("result", {}).get("access_token")
#     if DEBUG:
#         print("Access token is now", AccessToken)

#     return AccessToken

# def get_device_info():
#     access_token = get_access_token1(CLIENT_ID, CLIENT_SECRET, BASE_URL, EMPTYBODYENCODED, TUYATIME, DEBUG)

#     device_ids = ",".join(DEVICE_LIST.keys())

#     # Send Device status request
#     URL = f"/v2.0/cloud/thing/batch?device_ids={device_ids}"

#     StringToSign = f"{CLIENT_ID}{access_token}{TUYATIME}GET\n{EMPTYBODYENCODED}\n\n{URL}"
#     if DEBUG:
#         print("StringToSign is now", StringToSign)

#     RequestSign = hmac.new(CLIENT_SECRET.encode(), StringToSign.encode(), hashlib.sha256).hexdigest().upper()
#     if DEBUG:
#         print("RequestSign is now", RequestSign)

#     headers = {
#         "sign_method": "HMAC-SHA256",
#         "client_id": CLIENT_ID,
#         "t": TUYATIME,
#         "mode": "cors",
#         "Content-Type": "application/json",
#         "sign": RequestSign,
#         "access_token": access_token
#     }

#     RequestResponse = requests.get(BASE_URL + URL, headers=headers).json()
#     if DEBUG:
#         print("RequestResponse is now", RequestResponse)

#     devices_info = RequestResponse.get("result", [])
#     for device_info in devices_info:
#         id = device_info.get("id")
#         localKey = device_info.get("local_key")
#         customName = device_info.get("custom_name")

#         print(f"{id}\t{localKey}\t{customName}")


# ✅ Generate SHA256 Hash of the Request Body
def sha256_hash(data):
    if not data:
        return hashlib.sha256(b"").hexdigest()  # Empty body case
    body = json.dumps(data, separators=(',', ':'))  # Minified JSON for accurate hashing
    return hashlib.sha256(body.encode()).hexdigest()


# # ✅ Generate Tuya Sign
def calculate_sign1(method, path, params=None, body=None, access_token=""):
    timestamp = str(int(time.time() * 1000))

    # 🔹 Hash the request body
    content_sha256 = sha256_hash(body)

    # 🔹 Sort query parameters alphabetically
    query_string = ""
    if params:
        sorted_params = sorted(params.items())
        query_string = urlencode(sorted_params)

    # 🔹 Build the final URL path
    url_str = path + ("?" + query_string if query_string else "")

    # 🔹 Create `StringToSign`
    string_to_sign = f"{method}\n{content_sha256}\n\n{url_str}"

    # 🔹 Build message for HMAC-SHA256
    sign_string = CLIENT_ID + access_token + timestamp + string_to_sign

    # 🔹 Generate HMAC-SHA256 signature
    sign = hmac.new(CLIENT_SECRET.encode(), sign_string.encode(), hashlib.sha256).hexdigest().upper()

    return sign, timestamp

def calculate_sign(method: str, path: str, access_token: str = "", body: Dict[str, Any] = None) -> tuple[str, str]:
    """
    Calculate the signature for Tuya API requests.

    Args:
        method (str): HTTP method (GET, POST, etc.)
        path (str): API path
        body (Dict[str, Any], optional): Request body. Defaults to None.

    Returns:
        tuple[str, int]: Generated signature and timestamp.
    """
    print (f"calculate_sign: {method} {path} {body}")

    str_to_sign = method + "\n"
    content_to_sha256 = json.dumps(body) if body else ""
    str_to_sign += hashlib.sha256(content_to_sha256.encode("utf8")).hexdigest().lower() + "\n\n" + path
    
    t = int(time.time() * 1000)
    message = CLIENT_ID + access_token + str(t) + str_to_sign
    sign = hmac.new(
        CLIENT_SECRET.encode("utf8"),
        msg=message.encode("utf8"),
        digestmod=hashlib.sha256,
    ).hexdigest().upper()
    return sign, str(t)

# ✅ Fetch New Access Token (No Circular Dependency)
def fetch_access_token():
    global ACCESS_TOKEN, TOKEN_EXPIRATION

    url = f"{TUYA_API_BASE_URL}/v1.0/token?grant_type=1"

    # 🔹 Generate Signature

    sign, timestamp = calculate_sign1("GET", "/v1.0/token?grant_type=1")

    headers = {
        "client_id": CLIENT_ID,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "sign": sign,
        "Content-Type": "application/json"
    }

    # 🔹 Send API Request
    response = requests.get(url, headers=headers)

    if response.status_code == 200 and response.json().get("success"):
        result = response.json().get("result", {})
        ACCESS_TOKEN = result.get("access_token")
        TOKEN_EXPIRATION = int(time.time() * 1000) + (result.get("expire_time", 0) * 1000)
        print(f"✅ Access token: {ACCESS_TOKEN}")
        return ACCESS_TOKEN
    else:
        print("❌ Failed to retrieve access token")
        return None


# ✅ Get Cached Access Token (Calls Fetch Only If Expired)
def get_access_token():
    global ACCESS_TOKEN, TOKEN_EXPIRATION

    if ACCESS_TOKEN and int(time.time() * 1000) < TOKEN_EXPIRATION - 60000:
        return ACCESS_TOKEN

    return fetch_access_token()  # 🔹 Fetch only when necessary


def tuya_request(method, path, params=None, body=None):
    """Send a signed request to the Tuya Cloud API."""

    # 🔹 Ensure we have a valid access token
    access_token = get_access_token()
    if not access_token:
        print("❌ No valid access token")
        return None

    # 🔹 Generate Signature
    sign, timestamp = calculate_sign(method, path, access_token, body)

    # 🔹 Create Headers
    headers = {
        "client_id": CLIENT_ID,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "sign": sign,
        "access_token": access_token,
        "Content-Type": "application/json"
    }

    # 🔹 Full API URL
    full_url = TUYA_API_BASE_URL + path

    # 🔹 Debugging: Print Request Data
    print("\n🔹 Sending Request:")
    print(f"📌 URL: {full_url}")
    print(f"📌 Headers: {json.dumps(headers, indent=2)}")
    print(f"📌 Payload: {json.dumps(body, indent=2) if body else 'None'}")

    # 🔹 Make Request
    response = requests.request(method, full_url, headers=headers, params=params, json=body)

    # 🔹 Debugging: Print Response
    print("\n🔹 Response Received:")
    print(f"📌 Status Code: {response.status_code}")
    try:
        response_json = response.json()
        print(f"📌 Response JSON: {json.dumps(response_json, indent=2)}")
    except:
        print(f"📌 Raw Response: {response.text}")

    if response.status_code != 200:
        print(f"❌ Tuya API Error: {response.status_code}")
        return None

    return response_json

def control_rotation(device_id, rotation):
    url = f"/v1.0/devices/{device_id}/commands"
    print (f"Control Rotation: {rotation}")
    print (f"Device ID: {device_id}")
    print (f"URL: {url}")
    # 🔹 Define Payload
    payload = {
        "commands": [
            {
                "code": "percent_control",
                "value": rotation
            }
        ]
    }

    # 🔹 Send Request
    return tuya_request("POST", url, body=payload)

# ✅ Send Command to Control Curtain
def control_curtain(device_id, action):
    url = f"/v1.0/devices/{device_id}/commands"
    # url = f"/v2.0/cloud/thing/{device_id}/commands"
    print (f"Control Curtain: {action}")
    print (f"Device ID: {device_id}")
    print (f"URL: {url}")
    # 🔹 Define Payload
    payload = {
        "commands": [
            {
                "code": "control",
                "value": action
            }
        ]
    }

    # 🔹 Send Request
    return tuya_request("POST", url, body=payload)

# Home Assistant Functions
# @service
def open_curtain():
    """Home Assistant Service: Open Curtain"""
    device_id = list(DEVICE_LIST.keys())[0]
    control_rotation(device_id, 50)
    control_curtain(device_id, "open")

# def open_curtain():
#     device_id = list(DEVICE_LIST.keys())[0]  # Assume first device is the curtain motor
#     return control_curtain(device_id, "open")

# @service
def close_curtain():
    """Home Assistant Service: Close Curtain"""
    device_id = list(DEVICE_LIST.keys())[0]
    control_curtain(device_id, "close")
    time.sleep(16)
    control_rotation(device_id, 10)

# def close_curtain():
#     device_id = list(DEVICE_LIST.keys())[0]  # Assume first device is the curtain motor
#     return control_curtain(device_id, "close")

# def rotate_open():
#     device_id = list(DEVICE_LIST.keys())[0]  # Assume first device is the curtain motor
#     return control_rotation(device_id, 50)

# def rotate_close():
#     device_id = list(DEVICE_LIST.keys())[0]  # Assume first device is the curtain motor
#     return control_rotation(device_id, 10)

# if __name__ == "__main__":
#     if len(sys.argv) > 1:
#         action = sys.argv[1]
#         if action == "open":
#             # rotate_open()
#             open_curtain()
#         elif action == "close":
#             close_curtain()
#             # close_curtain()
#             # time.sleep(16)
#             # rotate_close()

@app.route("/control", methods=["GET"])
def ack():
    response = {
        "status": "ok",
        "message": "Server is running"
    }
    return jsonify(response)

@app.route("/control", methods=["POST"])
def control():
    data = request.get_json()
    action = data.get("action")
    device_id = list(DEVICE_LIST.keys())[0]
    
    if action == "open":
        control_rotation(device_id, 50)
        response = control_curtain(device_id, "open")
    elif action == "close":
        response = control_curtain(device_id, "close")
        time.sleep(16)
        control_rotation(device_id, 10)
    else:
        return jsonify({"error": "Invalid action"}), 400
    
    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)