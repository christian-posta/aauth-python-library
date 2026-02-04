# Phase 1 Implementation: Pseudonymous Flow

![Phase 1 Demo Screenshot](images/demo1.png)


Phase 1 implements basic proof-of-possession without identity using `sig=hwk` scheme.


## How It Works

1. **Agent generates ephemeral key pair** (Ed25519)
2. **Agent signs request** with `sig=hwk`:
   - Public key included in `Signature-Key` header
   - Signature covers `@method`, `@target-uri`, and `content-digest` (if body exists)
3. **Resource validates signature**:
   - Extracts public key from `Signature-Key` header
   - Reconstructs signature base
   - Verifies signature using Ed25519
4. **Resource grants access** if signature is valid

## Running Phase 1

### Run Tests
```bash
pytest tests/test_phase1.py -v
```

### Run Demo
```bash
python demo_phase1.py
```

### Run Participants Manually

**Terminal 1 - Resource (with debug):**
```bash
# Basic debug (signature verification details)
AAUTH_DEBUG=1 python -m participants.resource

# HTTP-level debug (shows full request/response headers and bodies, curl-like)
AAUTH_DEBUG_HTTP=1 python -m participants.resource

# Both debug levels
AAUTH_DEBUG=1 AAUTH_DEBUG_HTTP=1 python -m participants.resource
```

**Terminal 2 - Agent (interactive):**
```python
import os
# Enable HTTP-level debug to see full request/response (curl-like)
os.environ["AAUTH_DEBUG_HTTP"] = "1"
# Or enable signature verification debug
# os.environ["AAUTH_DEBUG"] = "1"

from participants.agent import Agent
import asyncio

agent = Agent("https://agent.example")
async def test():
    response = await agent.request_resource("http://localhost:8002/data")
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")
    else:
        print(f"Error: {response.text}")

asyncio.run(test())
```

**Note:** When `AAUTH_DEBUG_HTTP=1` is set, you'll see:
- **Agent side**: Full HTTP request headers and body (what the agent sends)
- **Agent side**: Full HTTP response headers and body (what the agent receives)
- **Resource side**: Full HTTP request headers and body (what the resource receives)
- **Resource side**: Full HTTP response headers and body (what the resource sends)

This gives you curl-like visibility into the HTTP traffic between agent and resource.

## Key Features

- ✅ Ed25519 cryptographic signatures
- ✅ RFC 9421 HTTP Message Signing
- ✅ Content-Digest for body integrity
- ✅ GET and POST request support
- ✅ Proper error handling (401 for invalid signatures)
- ✅ Label consistency checking (Signature-Input, Signature, Signature-Key must use same label)
- ✅ Timestamp validation (60-second tolerance)



## Notes

- Phase 1 uses `sig=hwk` (pseudonymous) - no identity, just proof-of-possession
- Keys are ephemeral (generated at startup)
- No tokens yet (that comes in Phase 3)
- Simple in-memory implementation (no persistence)

## What Was Implemented

### Core Components

1. **`core/crypto_utils.py`**
   - Ed25519 key pair generation
   - JWK conversion (private/public key ↔ JWK format)
   - JWKS document generation
   - Key utilities for Phase 2+ preparation

2. **`core/httpsig.py`**
   - HTTP Message Signing (RFC 9421) implementation
   - Signature generation with `sig=hwk` scheme (using label `sig1`)
   - Signature verification with label consistency checking
   - Signature-Key header parsing (supports any label: sig, sig1, etc.)
   - Support for `@method`, `@authority`, `@path`, `@query`, `content-type`, `content-digest`, and `signature-key` components
   - RFC 9530 Content-Digest support
   - Timestamp validation (60-second tolerance)

### Participants

3. **`participants/agent.py`**
   - Agent that signs requests with `sig=hwk`
   - FastAPI server (for future metadata endpoints)
   - `request_resource()` method for making signed requests

4. **`participants/resource.py`**
   - Resource server that validates signatures
   - Protected `/data` endpoint (GET and POST)
   - Signature verification logic
   - Returns 401 for unsigned/invalid requests

### Testing

5. **`tests/test_phase1.py`**
   - Test for successful signed request
   - Test for rejected unsigned request
   - Test for POST request with body

6. **`demo_phase1.py`**
   - Interactive demo script
   - Shows all Phase 1 functionality

## Output

```bash
❯ python demo_phase1.py
============================================================
Phase 1 Demo: Pseudonymous Flow (sig=hwk)
============================================================

1. Starting resource server on port 8002...
   ✓ Resource server running

2. Testing unsigned request (should fail)...

================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data HTTP/1.1
Host: localhost:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: localhost:8002
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig
content-length: 25

[Body (25 bytes)]
Missing signature headers
================================================================================

   Status: 401
   ✓ Correctly rejected unsigned request

3. Testing signed request (should succeed)...

================================================================================
>>> AGENT REQUEST to http://localhost:8002/data
================================================================================
GET http://localhost:8002/data HTTP/1.1
Signature: sig1=:jNE5CtEHHyJcLXYlryN6d-2uDj8mH4VgcLfBPdSrwg1Pai31a614boL1vAfH8v-IFD5ajZh_iLw2r-ZS6vUsDw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785726
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="EBtHEC1k4YT2S9_wmP2GPJoNhMBmWmR0UNRTD5tdW5o")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data HTTP/1.1
Host: localhost:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: localhost:8002
signature: sig1=:jNE5CtEHHyJcLXYlryN6d-2uDj8mH4VgcLfBPdSrwg1Pai31a614boL1vAfH8v-IFD5ajZh_iLw2r-ZS6vUsDw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785726
signature-key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="EBtHEC1k4YT2S9_wmP2GPJoNhMBmWmR0UNRTD5tdW5o")
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 90
content-type: application/json

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================


================================================================================
<<< AGENT RESPONSE from http://localhost:8002/data
================================================================================
HTTP/1.1 200 OK
content-length: 90
content-type: application/json
date: Mon, 19 Jan 2026 01:22:06 GMT
server: uvicorn

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================

   Status: 200
   ✓ Request successful!
   Response: Access granted
   Scheme: hwk

4. Testing POST request with body...

================================================================================
>>> AGENT REQUEST to http://localhost:8002/data
================================================================================
POST http://localhost:8002/data HTTP/1.1
Content-Digest: sha-256=:+07b4YoEZDosbiJrWo+8E65P7cZCm2RjiT1RfbiCBrU=:
Content-Type: application/json
Signature: sig1=:crwTM_y340Swq9ZvPUEZnb2t5xHuoI0HE2IfuQIo5W67UKI0C0QSIf7MQvH1HWMtQwmy20G1l3NW1dyBXLvXDw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="EBtHEC1k4YT2S9_wmP2GPJoNhMBmWmR0UNRTD5tdW5o")

[Body (41 bytes)]
{"action": "create", "data": "test data"}
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
POST /data HTTP/1.1
Host: localhost:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:+07b4YoEZDosbiJrWo+8E65P7cZCm2RjiT1RfbiCBrU=:
content-length: 41
content-type: application/json
host: localhost:8002
signature: sig1=:crwTM_y340Swq9ZvPUEZnb2t5xHuoI0HE2IfuQIo5W67UKI0C0QSIf7MQvH1HWMtQwmy20G1l3NW1dyBXLvXDw:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="EBtHEC1k4YT2S9_wmP2GPJoNhMBmWmR0UNRTD5tdW5o")
user-agent: python-httpx/0.28.1

[Body (41 bytes)]
{"action": "create", "data": "test data"}
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 91
content-type: application/json

[Body (91 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"POST"}
================================================================================


================================================================================
<<< AGENT RESPONSE from http://localhost:8002/data
================================================================================
HTTP/1.1 200 OK
content-length: 91
content-type: application/json
date: Mon, 19 Jan 2026 01:22:06 GMT
server: uvicorn

[Body (91 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"POST"}
================================================================================

   Status: 200
   ✓ POST request successful!
   Method: POST

============================================================
Phase 1 Demo Complete!
============================================================
```