import json
import hmac
import hashlib
import requests
import asyncio
import time
import os
import yaml
import sys
from typing import Any, Dict
from urllib.parse import urlencode

# Load Home Assistant secrets.yaml
SECRETS_FILE = os.getenv("HOME_ASSISTANT_CONFIG", "config/secrets.yaml")

with open(SECRETS_FILE, "r") as secrets_file:
    secrets = yaml.safe_load(secrets_file)

# # Load Tuya API credentials from Home Assistant's PyScript configuration
# config = pyscript.config["apps"]["tuya_control"][0]  # Get first dictionary in the list

# CLIENT_ID = config["tuya_client_id"]
# CLIENT_SECRET = config["tuya_client_secret"]
# TUYA_BASE_URL = config["tuya_base_url"]
# DEVICE_LIST = json.loads(config["tuya_device_list"])  # Convert JSON string to dictionary

# Read Tuya API Credentials from secrets.yaml
TUYA_BASE_URL = "https://openapi.tuyaus.com"  
CLIENT_ID = secrets["tuya_client_id"]
CLIENT_SECRET = secrets["tuya_client_secret"]
BASE_URL = secrets["tuya_base_url"]
DEVICE_LIST = json.loads(secrets["tuya_device_list"])

ACCESS_TOKEN = None
TOKEN_EXPIRATION = 0

print(f"✅ Tuya PyScript Initialized - Client ID: {CLIENT_ID}")


async def get_access_token():
    """Fetch Tuya API access token asynchronously."""
    global ACCESS_TOKEN, TOKEN_EXPIRATION

    # Return cached token if still valid
    if ACCESS_TOKEN and int(time.time() * 1000) < TOKEN_EXPIRATION - 60000:
        return ACCESS_TOKEN

    timestamp = str(int(time.time() * 1000))

    content_sha256 = hashlib.sha256(b"").hexdigest()  # Empty body case
    
    # 🔹 Sort query parameters alphabetically
    query_string = ""

    # 🔹 Build the final URL path
    url_str = f"{TUYA_BASE_URL}/v1.0/token?grant_type=1"

    # 🔹 Create `StringToSign`
    string_to_sign = f"GET\n{content_sha256}\n\n{url_str}"

    # 🔹 Build message for HMAC-SHA256
    sign_string = CLIENT_ID + timestamp + string_to_sign

    # 🔹 Generate HMAC-SHA256 signature
    sign = hmac.new(CLIENT_SECRET.encode(), sign_string.encode(), hashlib.sha256).hexdigest().upper()

    headers = {
        "client_id": CLIENT_ID,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "sign": sign,
        "Content-Type": "application/json",
    }

    # Make the request asynchronously
    response = requests.get(url_str, headers)
    data = response.json()

    if response.status_code == 200 and data.get("success"):
        result = data["result"]
        ACCESS_TOKEN = result["access_token"]
        TOKEN_EXPIRATION = int(time.time() * 1000) + (result["expire_time"] * 1000)
        print("✅ Tuya Access Token Obtained")
        return ACCESS_TOKEN

    print("❌ Failed to retrieve Tuya access token")
    return None


async def tuya_request(method: str, path: str, body: Dict[str, Any] = None):
    """Send a signed request to the Tuya Cloud API asynchronously."""
    access_token = await get_access_token()
    if not access_token:
        print("❌ No valid Tuya access token")
        return None

    timestamp = str(int(time.time() * 1000))
    content_sha256 = hashlib.sha256(json.dumps(body).encode() if body else b"").hexdigest()
    string_to_sign = f"{method}\n{content_sha256}\n\n{path}"
    sign = hmac.new(
        CLIENT_SECRET.encode(),
        (CLIENT_ID + access_token + timestamp + string_to_sign).encode(),
        hashlib.sha256,
    ).hexdigest().upper()

    headers = {
        "client_id": CLIENT_ID,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "sign": sign,
        "access_token": access_token,
        "Content-Type": "application/json",
    }

    full_url = TUYA_BASE_URL + path
    print(f"📌 Sending {method} request to {full_url}")

    # Make the request asynchronously
    response = await hass.async_add_executor_job(
        requests.request, method, full_url, headers=headers, json=body
    )

    if response.status_code != 200:
        print(f"❌ Tuya API Error: {response.status_code}")
        return None

    return response.json()


async def control_device(device_id: str, command: str, value: Any):
    """Send a command to a Tuya device asynchronously."""
    url = f"/v1.0/devices/{device_id}/commands"
    payload = {"commands": [{"code": command, "value": value}]}

    return await tuya_request("POST", url, body=payload)


# @service
async def open_curtain():
    """Home Assistant Service: Open Curtain"""
    device_id = list(DEVICE_LIST.keys())[0]
    print(f"🟢 Opening curtain: {device_id}")
    await control_device(device_id, "percent_control", 50)  # Adjust rotation
    await control_device(device_id, "control", "open")  # Open curtain


# @service
async def close_curtain():
    """Home Assistant Service: Close Curtain"""
    device_id = list(DEVICE_LIST.keys())[0]
    print(f"🔴 Closing curtain: {device_id}")
    await control_device(device_id, "control", "close")  # Close curtain
    await asyncio.sleep(16)  # Wait for curtain to close
    await control_device(device_id, "percent_control", 10)  # Adjust rotation after closing

if __name__ == "__main__":
    if len(sys.argv) > 1:
        action = sys.argv[1]
        loop = asyncio.get_event_loop()
        if action == "open":
            # rotate_open()
            loop.run_until_complete(open_curtain())
        elif action == "close":
            loop.run_until_complete(close_curtain())
            # close_curtain()
            # time.sleep(16)
            # rotate_close()