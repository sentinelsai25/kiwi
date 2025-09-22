# generator.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json

# User inputs
device_id = input("Enter Device ID: ").strip()
ssid = input("Enter Wi-Fi SSID: ").strip()
mac = input("Enter MAC address: ").strip()

# Authority key (in real life, generated once and kept secret)
authority_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authority_public_key = authority_private_key.public_key()

# Save authority public key
with open("authority_public.pem", "wb") as f:
    f.write(authority_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Device public/private keypair
device_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
device_public_key = device_private_key.public_key()

device_public_pem = device_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

device_private_pem = device_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

# Sign device info with authority
device_info = f"{device_id}-{ssid}-{mac}-{device_public_pem}"
authority_signature = authority_private_key.sign(
    device_info.encode(),
    padding.PKCS1v15(),
    hashes.SHA256()
).hex()

# Build device certificate
device_cert = {
    "device_id": device_id,
    "ssid": ssid,
    "mac": mac,
    "device_public_key": device_public_pem,
    "authority_signature": authority_signature
}

# Save certificate JSON
with open("device_cert.json", "w") as f:
    json.dump(device_cert, f, indent=2)

# Save private key for flashing to ESP32
with open("device_private.pem", "w") as f:
    f.write(device_private_pem)

print("Device certificate and private key generated. Authority public key saved.")