"""Demo script for Phase 2: Agent Identity via JWKS.

This script demonstrates both sig=hwk and sig=jwks_uri schemes working simultaneously
on separate endpoints.
"""

import asyncio
import uvicorn
import threading
import httpx
from participants.agent import Agent
from participants.resource import Resource


async def main():
    """Run Phase 2 demo."""
    print("=" * 80)
    print("Phase 2 Demo: Agent Identity via JWKS")
    print("Resource challenges for identity use Signature-Requirement (pseudonym/identity).")
    print("Agent tokens use typ aa-agent+jwt (see library create_agent_token / verify).")
    print("=" * 80)
    print()
    
    # Create agent and resource
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("https://resource.example.com", port=8002)
    
    # Start resource server
    print("Starting resource server on port 8002...")
    resource_thread = threading.Thread(
        target=lambda: uvicorn.run(resource.app, host="127.0.0.1", port=8002, log_level="info"),
        daemon=True
    )
    resource_thread.start()
    
    # Start agent server
    print("Starting agent server on port 8001...")
    agent_thread = threading.Thread(
        target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="info"),
        daemon=True
    )
    agent_thread.start()
    
    # Wait for servers to start
    print("Waiting for servers to start...")
    await asyncio.sleep(2)
    
    print()
    print("=" * 80)
    print("Demo 1: sig=hwk on /data-hwk endpoint (Phase 1)")
    print("=" * 80)
    
    try:
        response = await agent.request_resource(
            "http://127.0.0.1:8002/data-hwk",
            sig_scheme="hwk"
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {data}")
            print("✓ sig=hwk works on /data-hwk endpoint")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    input("Press Enter to continue to Demo 2...")
    print()
    print("=" * 80)
    print("Demo 2: sig=jwks_uri on /data-jwks endpoint (Phase 2)")
    print("=" * 80)
    
    try:
        response = await agent.request_resource(
            "http://127.0.0.1:8002/data-jwks",
            sig_scheme="jwks_uri"
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {data}")
            print("✓ sig=jwks_uri works on /data-jwks endpoint")
            print(f"  Agent ID: {data.get('agent_id')}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    input("Press Enter to continue to Demo 3...")
    print()
    print("=" * 80)
    print("Demo 3: Verify metadata endpoint")
    print("=" * 80)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://127.0.0.1:8001/.well-known/aauth-agent")
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"Metadata: {metadata}")
                print("✓ Agent metadata endpoint works")
            else:
                print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    input("Press Enter to continue to Demo 4...")
    print()
    print("=" * 80)
    print("Demo 4: Verify JWKS endpoint")
    print("=" * 80)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://127.0.0.1:8001/jwks.json")
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                jwks = response.json()
                print(f"JWKS: {jwks}")
                print("✓ Agent JWKS endpoint works")
                if jwks.get("keys") and len(jwks["keys"]) > 0:
                    print(f"  Key ID (kid): {jwks['keys'][0].get('kid')}")
            else:
                print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    input("Press Enter to continue to Demo 5...")
    print()
    print("=" * 80)
    print("Demo 5: Wrong scheme rejected")
    print("=" * 80)
    
    try:
        # Try to use sig=hwk on /data-jwks endpoint (should fail)
        response = await agent.request_resource(
            "http://127.0.0.1:8002/data-jwks",
            sig_scheme="hwk"  # Wrong scheme!
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 401:
            print(f"Response: {response.text}")
            print("✓ Wrong scheme correctly rejected")
        else:
            print(f"Unexpected success: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    input("Press Enter to continue to Demo 6...")
    print()
    print("=" * 80)
    print("Demo 6: Both endpoints work independently")
    print("=" * 80)
    
    try:
        # Test both endpoints in sequence
        response_hwk = await agent.request_resource(
            "http://127.0.0.1:8002/data-hwk",
            sig_scheme="hwk"
        )
        response_jwks = await agent.request_resource(
            "http://127.0.0.1:8002/data-jwks",
            sig_scheme="jwks_uri"
        )
        
        print(f"/data-hwk status: {response_hwk.status_code}")
        print(f"/data-jwks status: {response_jwks.status_code}")
        
        if response_hwk.status_code == 200 and response_jwks.status_code == 200:
            print("✓ Both endpoints work independently")
        else:
            print("✗ One or both endpoints failed")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    print("=" * 80)
    print("Phase 2 Demo Complete!")
    print("=" * 80)
    print()
    print("Summary:")
    print("- sig=hwk works on /data-hwk endpoint (Phase 1)")
    print("- sig=jwks_uri works on /data-jwks endpoint (Phase 2)")
    print("- Agent metadata endpoint works")
    print("- Agent JWKS endpoint works")
    print("- Wrong scheme correctly rejected")
    print("- Both endpoints work independently")
    print()
    print("Servers are still running. Press Ctrl+C to stop.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")

