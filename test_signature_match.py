"""Test script to compare signing vs verification signature bases."""

import os
os.environ["AAUTH_DEBUG"] = "1"

from core.httpsig import sign_request, verify_signature
from core.crypto_utils import generate_ed25519_keypair

# Generate a key pair
private_key, public_key = generate_ed25519_keypair()

# Sign a request
method = "GET"
url = "http://localhost:8002/data"
headers = {}
body = b""

print("=" * 60)
print("SIGNING")
print("=" * 60)
sig_headers = sign_request(method, url, headers.copy(), body, private_key, sig_scheme="hwk")

print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)

# Now verify with the same parameters
# Note: headers dict now includes Signature-Key (added during signing)
is_valid = verify_signature(
    method=method,
    target_uri=url,
    headers=headers,  # Use the headers dict (includes Signature-Key added during signing)
    body=body,
    signature_input_header=sig_headers["Signature-Input"],
    signature_header=sig_headers["Signature"],
    signature_key_header=sig_headers["Signature-Key"],
    public_key=public_key
)

print(f"\nVerification result: {is_valid}")
print("=" * 60)

