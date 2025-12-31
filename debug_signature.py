"""Debug script to compare signature base construction."""

import asyncio
from participants.agent import Agent
from core.httpsig import sign_request
from core.crypto_utils import generate_ed25519_keypair
import os

# Enable debug output
os.environ["AAUTH_DEBUG"] = "1"

async def test():
    agent = Agent("https://agent.example")
    
    # Sign a request
    method = "GET"
    url = "http://localhost:8002/data"
    headers = {}
    body = b""
    
    print("=" * 60)
    print("SIGNING REQUEST")
    print("=" * 60)
    sig_headers = agent.sign_request(method, url, headers, body)
    
    print("\nSignature headers:")
    for k, v in sig_headers.items():
        print(f"  {k}: {v[:100]}..." if len(v) > 100 else f"  {k}: {v}")
    
    print("\n" + "=" * 60)
    print("Now make the actual request to see verification...")
    print("=" * 60)
    
    response = await agent.request_resource(url, method, headers, body)
    print(f"\nStatus: {response.status_code}")
    if response.status_code != 200:
        print(f"Error: {response.text}")

if __name__ == "__main__":
    asyncio.run(test())

