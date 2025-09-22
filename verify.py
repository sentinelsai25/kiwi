import subprocess
import platform
import requests
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# --- Function to get current connected Wi-Fi SSID ---
def get_current_ssid():
    os_name = platform.system()
    try:
        if os_name == "Windows":
            output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")
            for line in output.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[1].strip()
        elif os_name == "Linux":
            output = subprocess.check_output(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], encoding="utf-8")
            for line in output.splitlines():
                active, ssid = line.split(":")
                if active == "yes":
                    return ssid
        elif os_name == "Darwin":  # Mac
            output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                encoding="utf-8"
            )
            for line in output.splitlines():
                if " SSID: " in line:
                    return line.split(":")[1].strip()
        else:
            return None
    except Exception:
        return None

# --- Load authority public key ---
with open("authority_public.pem","rb") as f:
    authority_pub = serialization.load_pem_public_key(f.read())

# --- Load device certificate ---
with open("device_cert.json") as f:
    device_cert = json.load(f)

# --- Get current SSID ---
ssid = get_current_ssid()
if not ssid:
    print("❌ Could not detect current Wi-Fi SSID.")
    exit(1)

# --- Check if certificate exists ---
if device_cert.get("ssid") != ssid:
    print(f"SSID: {ssid} | Certificate: ❌ Not verified (no certificate)")
    exit(1)

# --- Verify authority signature ---
device_info = f"{device_cert['device_id']}-{ssid}-{device_cert['mac']}-{device_cert['device_public_key']}"
sig_bytes = bytes.fromhex(device_cert['authority_signature'])

try:
    authority_pub.verify(sig_bytes, device_info.encode(), padding.PKCS1v15(), hashes.SHA256())
    cert_status = "✅ Verified"
except InvalidSignature:
    cert_status = "❌ Not verified"

print(f"SSID: {ssid} | Certificate: {cert_status}")

if cert_status == "❌ Not verified":
    exit(1)

# --- Request ESP32 to generate new nonce and signature ---
router_ip = "192.168.4.1"  # default IP for ESP32 AP
try:
    resp = requests.get(f"http://{router_ip}/verify", timeout=5)
    resp.raise_for_status()
    data = resp.json()
    nonce = data.get("nonce", "")
    sig_hex = data.get("signature", "")
except Exception as e:
    print(f"SSID: {ssid} | Router: ❌ Not verified (router unreachable) | {e}")
    exit(1)

# --- Verify router signature using device public key ---
device_pub = serialization.load_pem_public_key(device_cert['device_public_key'].encode())

try:
    device_pub.verify(bytes.fromhex(sig_hex), nonce.encode(), padding.PKCS1v15(), hashes.SHA256())
    router_status = "✅ Verified (authentic)"
except InvalidSignature:
    router_status = "❌ Not verified (possible fake)"

print(f"SSID: {ssid} | Router: {router_status}")
print(f"Nonce used for verification: {nonce}")