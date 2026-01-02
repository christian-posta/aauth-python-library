# Phase 4: User Delegation

## Status: Complete ✅

Phase 4 implements the user delegation flow where agents obtain authorization through user consent. When an auth server determines that user consent is required, it issues a `request_token` instead of an auth token. The agent redirects the user to the auth server's authorization endpoint, where the user authenticates and grants consent. The auth server then redirects back to the agent with an authorization code, which the agent exchanges for an auth token.

## What Was Implemented

### Core Components

1. **User Simulator** (`participants/user_simulator.py`)
   - `UserSimulator` class for automated browser redirect simulation
   - `complete_flow()` - Completes the full user consent flow automatically
   - `deny_consent()` - Simulates user denying consent
   - Handles login, consent pages, and authorization code extraction
   - Comprehensive debug output

2. **Auth Server Enhancements** (`participants/auth_server.py`)
   - `require_user_consent` parameter - Enables user consent requirement
   - State management:
     - `pending_requests` - Stores request_token → request details mapping
     - `authorization_codes` - Stores code → request details mapping (single-use, 60s expiry)
     - `users` - Simple in-memory user database for demo
   - `_generate_request_token()` - Generates opaque request_token (10min expiry)
   - `_generate_authorization_code()` - Generates authorization code (60s expiry, single-use)
   - `GET /agent/auth` - Authorization endpoint (Section 9.5)
     - Displays login page if not authenticated
     - Displays consent page after authentication
     - HTML pages with modern styling
   - `POST /agent/auth` - Handles login and consent submission
     - Validates user credentials
     - Processes consent grant/deny
     - Redirects to agent callback with code or error
   - `_handle_code_exchange()` - Handles `request_type=code` token requests (Section 9.6)
     - Validates authorization code
     - Verifies agent signature
     - Issues auth token with user identity (`sub` claim)
   - Updated `_evaluate_policy()` - Returns `requires_user_consent` flag
   - Updated `_handle_token_request()` - Returns `request_token` when consent required

3. **Agent Enhancements** (`participants/agent.py`)
   - `_handle_request_token()` - Handles `request_token` responses
     - Fetches auth server metadata
     - Constructs authorization URL
     - Uses user simulator to complete flow (automated)
   - `_exchange_authorization_code()` - Exchanges authorization code for auth token
     - Makes signed request to token endpoint with `request_type=code`
     - Stores received auth token
   - `GET /callback` - OAuth callback endpoint
     - Receives redirect from auth server with authorization code
     - Displays success/error page
   - Updated `_request_auth_token()` - Detects `request_token` in response and handles it

4. **User Delegation Flow** (`flows/user_delegated.py`)
   - `run_user_delegated_flow()` - Automated flow with user simulator
   - `run_user_delegated_flow_manual()` - Placeholder for manual browser testing
   - Orchestrates complete user delegation flow

5. **Demo Script** (`demo_phase4.py`)
   - Interactive demonstration of user delegation flow
   - Supports automated mode (with user simulator) and manual mode (browser-based)
   - `--manual` flag for manual browser testing
   - Comprehensive test output with pass/fail status

6. **Tests** (`tests/test_phase4.py`)
   - Unit tests for request_token generation
   - Unit tests for authorization code generation
   - Unit tests for policy evaluation
   - Integration test for complete flow

## Flow Description

### Automated Flow (with User Simulator)

1. **Agent requests resource** (`GET /data-auth`)
   - Resource returns 401 with `Agent-Auth: httpsig; auth-token; resource_token="..."; auth_server="..."`
   
2. **Agent requests auth token** (`POST /agent/token`)
   - Presents resource token with signed request
   - Auth server evaluates policy → requires user consent
   - Auth server returns `request_token` instead of `auth_token`
   
3. **Agent handles request_token**
   - Constructs authorization URL: `/agent/auth?request_token=...&redirect_uri=...`
   - Uses user simulator to complete flow:
     - GET `/agent/auth` → Login page
     - POST `/agent/auth` (login) → Consent page
     - POST `/agent/auth` (consent) → Redirect with authorization code
   
4. **Agent exchanges code** (`POST /agent/token` with `request_type=code`)
   - Presents authorization code with signed request
   - Auth server validates code and issues auth token with `sub` claim
   
5. **Agent retries resource request**
   - Uses `sig=jwt` with auth token
   - Resource validates auth token and grants access

### Manual Flow (Browser-Based)

Same as automated flow, but:
- Step 3 is performed manually by the user in a browser
- User opens authorization URL, authenticates, and grants consent
- Agent's `/callback` endpoint receives the redirect
- Agent automatically exchanges code for tokens

## Key Features

### Request Token
- Opaque string generated by auth server
- Represents a pending authorization request
- Stored in `pending_requests` with 10-minute expiry
- Contains: agent, resource, scope, redirect_uri, agent_jwk

### Authorization Code
- Opaque string generated by auth server after user consent
- Single-use, 60-second expiry
- Stored in `authorization_codes` with request details
- Exchanged for auth token via `request_type=code`

### User Identity
- Auth tokens issued after user consent include `sub` claim
- `sub` contains the user identifier (username in demo)
- Enables resource to know which user authorized the access

### HTML Pages
- Modern, responsive design
- Login page with demo credentials displayed
- Consent page showing agent, resource, and requested scopes
- Clear grant/deny buttons
- Error pages for invalid tokens or denied consent

## Testing

### Automated Testing
```bash
python demo_phase4.py
```

This runs the complete flow with user simulator automatically.

### Manual Browser Testing

For true manual browser testing, you can interact with the flow step-by-step:

#### Step 1: Start the Servers

In separate terminals, start each server:

```bash
# Terminal 1: Start Agent
python -c "from participants.agent import Agent; Agent('http://127.0.0.1:8001', port=8001).run()"

# Terminal 2: Start Resource  
python -c "from participants.resource import Resource; Resource('http://127.0.0.1:8002', port=8002, auth_server='http://127.0.0.1:8003').run()"

# Terminal 3: Start Auth Server (with user consent required)
python -c "from participants.auth_server import AuthServer; AuthServer('http://127.0.0.1:8003', port=8003, require_user_consent=True).run()"
```

#### Step 2: Make a Request to the Resource

The agent server exposes a `/request` endpoint that allows you to make requests using the agent's keys. This ensures the agent uses its own key pair for signing.

**Using curl:**

```bash
curl -X POST http://127.0.0.1:8001/request \
  -H "Content-Type: application/json" \
  -d '{
    "resource_url": "http://127.0.0.1:8002/data-auth",
    "method": "GET",
    "sig_scheme": "jwks"
  }'
```

The agent will:
1. Make a signed request to the resource
2. Handle the 401 challenge
3. Request auth token (will get `request_token` for user consent)
4. Complete the user consent flow automatically (or you can watch for the URL)

**Watch the debug output** for the authorization URL:
```
DEBUG AGENT:   Redirect URL: http://127.0.0.1:8003/agent/auth?request_token=...
```

Copy that URL and open it in your browser to manually complete the consent flow.

**Using Python:**

```python
import httpx
import json

response = httpx.post(
    "http://127.0.0.1:8001/request",
    json={
        "resource_url": "http://127.0.0.1:8002/data-auth",
        "method": "GET",
        "sig_scheme": "jwks"
    }
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

**Alternative: Use the demo script**

The demo script handles everything automatically:

```bash
python demo_phase4.py --manual
```

**Alternative: Use a single Python script that starts everything**

Create a script that uses the same agent instance for both the server and making requests:

```python
import asyncio
import threading
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer

async def manual_test():
    # Create participants (same instances used for servers and requests)
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    auth_server = AuthServer("http://127.0.0.1:8003", port=8003, require_user_consent=True)
    
    # Start servers in background
    def run_server(server, name):
        print(f"Starting {name}...")
        server.run()
    
    threading.Thread(target=run_server, args=(agent, "Agent"), daemon=True).start()
    threading.Thread(target=run_server, args=(resource, "Resource"), daemon=True).start()
    threading.Thread(target=run_server, args=(auth_server, "Auth Server"), daemon=True).start()
    
    # Wait for servers to start
    await asyncio.sleep(2)
    
    # Make request using the SAME agent instance (same keys!)
    print("\nMaking request to resource...")
    response = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET",
        sig_scheme="jwks"
    )
    
    print(f"\nStatus: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")
    else:
        print("Check debug output above for authorization URL")
        print("The agent will pause waiting for user consent...")

asyncio.run(manual_test())
```

**Note**: The agent's `request_resource()` method will automatically handle the user consent flow using the user simulator. For true manual browser testing, you'd need to modify the agent to pause and display the authorization URL instead of using the simulator.

#### Step 3: Extract Authorization URL

When the agent receives a `request_token` from the auth server, you'll see debug output like:

```
DEBUG AGENT:   Request token received: UdpvvfnRSnzJUU-3n_xRMmXEagtJjroBDvfggIoZ4C4...
DEBUG AGENT:   Auth endpoint: http://127.0.0.1:8003/agent/auth
DEBUG AGENT:   Redirect URL: http://127.0.0.1:8003/agent/auth?request_token=UdpvvfnRSnzJUU-3n_xRMmXEagtJjroBDvfggIoZ4C4&redirect_uri=http://127.0.0.1:8001/callback
```

#### Step 4: Open Authorization URL in Browser

Copy the redirect URL and open it in your browser:

```
http://127.0.0.1:8003/agent/auth?request_token=UdpvvfnRSnzJUU-3n_xRMmXEagtJjroBDvfggIoZ4C4&redirect_uri=http://127.0.0.1:8001/callback
```

#### Step 5: Authenticate and Grant Consent

1. **Login Page**: Enter credentials
   - Username: `testuser`
   - Password: `testpass`
   - Click "Login"

2. **Consent Page**: Review the authorization request
   - Shows Agent, Resource, and requested scopes
   - Click "Grant Access" to approve or "Deny" to reject

#### Step 6: Agent Exchanges Code

After you grant consent, the browser redirects to:
```
http://127.0.0.1:8001/callback?code=Zt29P-RM_VHw00n4qNOHnGtKkhWtQe2-_gcabU2iMWk
```

The agent's `/callback` endpoint receives this and automatically exchanges the code for an auth token. You can then retry the resource request, which should now succeed.

#### Complete Example Script

Here's a complete Python script for manual testing:

```python
import asyncio
import sys
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer

async def manual_test():
    # Note: Servers should be running in separate terminals
    
    agent = Agent("http://127.0.0.1:8001", port=8001)
    
    print("=" * 80)
    print("MANUAL TESTING - Step 1: Request Resource")
    print("=" * 80)
    print("\nMaking request to resource...")
    print("(This will trigger the user consent flow)")
    print()
    
    response = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET",
        sig_scheme="jwks"
    )
    
    if response.status_code == 200:
        print("✓ SUCCESS: Resource access granted!")
        print(f"Response: {response.json()}")
    else:
        print(f"Status: {response.status_code}")
        print("Check the debug output above for the authorization URL.")
        print("Open that URL in your browser to complete the consent flow.")

if __name__ == "__main__":
    print("\nNOTE: Make sure all servers are running before running this script!")
    print("Agent: http://127.0.0.1:8001")
    print("Resource: http://127.0.0.1:8002")
    print("Auth Server: http://127.0.0.1:8003\n")
    asyncio.run(manual_test())
```

### Unit Tests
```bash
pytest tests/test_phase4.py -v
```

## Debug Output

All components include comprehensive debug output:
- Request/response details
- Token generation and validation
- Policy evaluation results
- User consent flow steps
- Authorization code exchange

Enable/disable with `AAUTH_DEBUG` environment variable (defaults to enabled).

## Demo Credentials

For testing the login page:
- **Username:** `testuser`
- **Password:** `testpass`

## Alignment with SPEC.md

Phase 4 implements **Section 3.6: User Delegated Access**:
- Request token generation (Section 9.5)
- Authorization endpoint (Section 9.5)
- Authorization code exchange (Section 9.6)
- User identity in auth tokens (`sub` claim)

## Next Steps

Phase 4 completes the core user delegation flow. Future enhancements could include:
- Token refresh flow
- Scope-specific consent pages
- More sophisticated policy evaluation
- User session management
- Multiple user accounts
- Consent revocation

