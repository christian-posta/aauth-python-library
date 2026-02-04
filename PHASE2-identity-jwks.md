# Phase 2: Agent Identity via JWKS

![Phase 2 Demo Screenshot](images/demo2.png)


Phase 2 adds agent identity verification using JWKS discovery while maintaining full backward compatibility with Phase 1's `sig=hwk` scheme. The resource exposes **separate endpoints for each signature scheme** (`/data-hwk`, `/data-jwks`) to enable clear demonstration of both capabilities simultaneously.


## How It Works

### Architecture Flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant R as Resource
    
    Note over A,R: Phase 1: sig=hwk endpoint
    A->>R: GET /data-hwk<br/>Signature-Key: sig1=(scheme=hwk kty="OKP" ...)
    R->>R: Verify sig=hwk<br/>(extract key from header)
    R-->>A: 200 OK
    
    Note over A,R: Phase 2: sig=jwks endpoint
    A->>A: Publish metadata at<br/>/.well-known/aauth-agent
    A->>A: Publish JWKS at /jwks.json
    A->>R: GET /data-jwks<br/>Signature-Key: sig1=(scheme=jwks id="..." kid="...")
    R->>R: Extract id and kid
    R->>A: GET /.well-known/aauth-agent
    A-->>R: Metadata JSON
    R->>A: GET /jwks.json
    A-->>R: JWKS document
    R->>R: Match key by kid<br/>Verify signature
    R-->>A: 200 OK
```

### Key Differences: sig=hwk vs sig=jwks

| Aspect | sig=hwk (Phase 1) | sig=jwks (Phase 2) |
|--------|-------------------|-------------------|
| **Identity** | Pseudonymous (key in header) | Identified (agent_id + kid) |
| **Key Source** | Embedded in Signature-Key header | Fetched via JWKS discovery |
| **Discovery** | None (self-contained) | Mode 2: metadata → JWKS |
| **Use Case** | One-off requests, privacy | Persistent identity, auditability |

### Mode 2 Discovery Flow

When a resource receives a request with `sig=jwks`:

1. **Extract identifiers**: Parse `id` and `kid` from `Signature-Key` header
2. **Fetch metadata**: GET `{agent_id}/.well-known/aauth-agent`
3. **Extract JWKS URI**: Read `jwks_uri` from metadata
4. **Fetch JWKS**: GET `{jwks_uri}`
5. **Match key**: Find key with matching `kid`
6. **Verify signature**: Use matched key to verify HTTP signature

## Running Phase 2

### Automated Tests

Run the Phase 2 test suite:

```bash
pytest tests/test_phase2.py -v
```

This includes:
- Metadata generation and fetching tests
- JWKS handling tests
- Signature generation/verification tests
- Scheme validation tests
- Integration tests for both endpoints
- Backward compatibility tests

### Demo Script

Run the Phase 2 demo:

```bash
python demo_phase2.py
```

The demo shows:
- `sig=hwk` flow on `/data-hwk`
- `sig=jwks` flow on `/data-jwks`
- Metadata endpoint verification
- JWKS endpoint verification
- Wrong scheme rejection
- Both endpoints working independently

### Manual Testing

**Important Note for `sig=jwks` Testing:**
For `sig=jwks` to work, the agent instance used for signing requests MUST be the same one serving the JWKS endpoint. Each `Agent()` instance generates its own key pair, so if you create a new instance, it will have a different key than the server, causing verification to fail.

**Option 1: Use the same agent instance (recommended for manual testing)**

**Terminal 1 - Resource Server:**
```bash
python -c "from participants.resource import Resource; Resource('https://resource.example.com', port=8002).run()"
```

**Terminal 2 - Agent Server and Client (same instance):**
```python
# Start server in background, then use same instance for requests
from participants.agent import Agent
import uvicorn
import threading
import asyncio

agent = Agent("http://127.0.0.1:8001", port=8001)

# Start server in background thread
server_thread = threading.Thread(
    target=lambda: uvicorn.run(agent.app, host="127.0.0.1", port=8001, log_level="info"),
    daemon=True
)
server_thread.start()

# Wait for server to start
import time
time.sleep(2)

# Now use the SAME agent instance for requests
async def test():
    response = await agent.request_resource(
        "http://127.0.0.1:8002/data-jwks",
        sig_scheme="jwks"
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")

asyncio.run(test())
```

**Option 2: Run servers separately (for sig=hwk only, or use demo script for sig=jwks)**

**Terminal 1 - Resource Server:**
```bash
python -c "from participants.resource import Resource; Resource('https://resource.example.com', port=8002).run()"
```


**Note:** If you create a new `Agent()` instance in Terminal 3, it will have a different key pair and `sig=jwks` will fail. Use the demo script (`python demo_phase2.py`) for `sig=jwks` testing, or use Option 1 above.

#### 2. Test sig=hwk on /data-hwk

**Terminal 3 - Python REPL:**
```python
import asyncio
from participants.agent import Agent

async def test():
    agent = Agent("http://127.0.0.1:8001", port=8001)
    response = await agent.request_resource(
        "http://127.0.0.1:8002/data-hwk",
        sig_scheme="hwk"
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

asyncio.run(test())
```

Expected output:
```
Status: 200
Response: {'message': 'Access granted', 'data': 'This is protected data', 'scheme': 'hwk', 'method': 'GET'}
```

#### 3. Verify Metadata Endpoint

```bash
curl http://127.0.0.1:8001/.well-known/aauth-agent
```

Expected output:
```json
{
  "agent": "http://127.0.0.1:8001",
  "jwks_uri": "http://127.0.0.1:8001/jwks.json"
}
```

#### 4. Verify JWKS Endpoint

```bash
curl http://127.0.0.1:8001/jwks.json
```

Expected output:
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "...",
      "kid": "key-1"
    }
  ]
}
```

#### 5. Test Wrong Scheme Rejection

**Terminal 3 - Python REPL:**
```python
import asyncio
from participants.agent import Agent

async def test():
    agent = Agent("http://127.0.0.1:8001", port=8001)
    # Try sig=hwk on /data-jwks (should fail)
    response = await agent.request_resource(
        "http://127.0.0.1:8002/data-jwks",
        sig_scheme="hwk"  # Wrong scheme!
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")

asyncio.run(test())
```

Expected output:
```
Status: 401
Response: Invalid signature scheme: expected jwks, got hwk
```

## Debug Mode

Debug output is controlled via environment variables. Default values are configured in `core/__init__.py`:
- `AAUTH_DEBUG`: Defaults to `"0"` (disabled)
- `AAUTH_DEBUG_HTTP`: Defaults to `"1"` (enabled)

### AAUTH_DEBUG

Enable detailed signature verification debug output:

```bash
AAUTH_DEBUG=1 python demo_phase2.py
```

**Note:** By default, `AAUTH_DEBUG` is disabled (`"0"`). Set it to `"1"` to enable.

This shows:
- Signature base construction
- Component parsing
- Timestamp validation
- Key extraction and matching
- JWKS fetching steps (for `sig=jwks`)
- Signature verification results

### AAUTH_DEBUG_HTTP

HTTP-level request/response logging (curl-like format):

```bash
AAUTH_DEBUG_HTTP=1 python demo_phase2.py
```

**Note:** By default, `AAUTH_DEBUG_HTTP` is enabled (`"1"`). Set it to `"0"` to disable.

This shows:
- Full HTTP request headers and bodies
- Full HTTP response headers and bodies
- Both for agent→resource requests
- Both for resource→agent metadata/JWKS fetches

### Combined Debug

Enable both debug modes:

```bash
AAUTH_DEBUG=1 AAUTH_DEBUG_HTTP=1 python demo_phase2.py
```

**Note:** Since `AAUTH_DEBUG_HTTP` is enabled by default, you only need to set `AAUTH_DEBUG=1` to enable both modes.

## Backward Compatibility

Phase 2 maintains full backward compatibility with Phase 1:

- ✅ Existing `/data` endpoint still works (defaults to `sig=hwk`)
- ✅ Phase 1 tests (`tests/test_phase1.py`) still pass
- ✅ `sig=hwk` scheme unchanged
- ✅ No breaking changes to API



## What Was Implemented

### Core Components

1. **Metadata Module** (`core/metadata.py`)
   - `generate_agent_metadata()` - Generates agent metadata JSON per AAuth spec Section 8.1
   - `fetch_metadata()` - Fetches metadata documents via HTTPS

2. **Agent Updates** (`participants/agent.py`)
   - Added `/.well-known/aauth-agent` metadata endpoint
   - Updated `/jwks.json` endpoint to include `kid` in keys
   - Made signing scheme configurable (`sig_scheme` parameter)
   - Added `sig_scheme` parameter to `sign_request()` and `request_resource()` methods
   - Defaults to `sig=hwk` for backward compatibility

3. **Resource Updates** (`participants/resource.py`)
   - Added separate endpoints:
     - `/data-hwk` - Requires `sig=hwk` scheme (Phase 1)
     - `/data-jwks` - Requires `sig=jwks` scheme (Phase 2)
   - Kept `/data` endpoint for backward compatibility (defaults to `sig=hwk`)
   - Added scheme validation (rejects wrong scheme for endpoint)
   - Implemented `_fetch_jwks_for_agent()` using Mode 2 discovery (spec Section 10.7)
   - Added JWKS fetching with debug support

4. **HTTPSig Updates** (`core/httpsig.py`)
   - Updated `_verify_signature_manual()` to handle both `sig=hwk` and `sig=jwks`
   - Added debug output for JWKS fetching steps
   - Enhanced `verify_signature()` to support `jwks_fetcher` callback

## Output

```bash
❯ python demo_phase2.py
================================================================================
Phase 2 Demo: Agent Identity via JWKS
================================================================================

Starting resource server on port 8002...
Starting agent server on port 8001...
Waiting for servers to start...
INFO:     Started server process [94662]
INFO:     Waiting for application startup.
INFO:     Started server process [94662]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8001 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://127.0.0.1:8002 (Press CTRL+C to quit)

================================================================================
Demo 1: sig=hwk on /data-hwk endpoint (Phase 1)
================================================================================

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-hwk
================================================================================
GET http://127.0.0.1:8002/data-hwk HTTP/1.1
Signature: sig1=:b2M-N-k6lllKCDYvtn1kJICoeksEmFY6RCXvavBdYBqqpX3ZHy2H3AGo6FvSCbm02HAIgc7ckEPfB_XGWmi8BQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785793
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-hwk HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:b2M-N-k6lllKCDYvtn1kJICoeksEmFY6RCXvavBdYBqqpX3ZHy2H3AGo6FvSCbm02HAIgc7ckEPfB_XGWmi8BQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785793
signature-key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
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

INFO:     127.0.0.1:58632 - "GET /data-hwk HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-hwk
================================================================================
HTTP/1.1 200 OK
content-length: 90
content-type: application/json
date: Mon, 19 Jan 2026 01:23:13 GMT
server: uvicorn

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================

Status: 200
Response: {'message': 'Access granted', 'data': 'This is protected data', 'scheme': 'hwk', 'method': 'GET'}
✓ sig=hwk works on /data-hwk endpoint

Press Enter to continue to Demo 2...

================================================================================
Demo 2: sig=jwks on /data-jwks endpoint (Phase 2)
================================================================================

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-jwks
================================================================================
GET http://127.0.0.1:8002/data-jwks HTTP/1.1
Signature: sig1=:0O48KtRbtfpgIZdCVdPZkHQNzBCZmOnPjTDYW0JN4qET18p4toSEE7ZIZo1v5Hf7CZKPugAhiSkrWuNmekUvAQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785796
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-jwks HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:0O48KtRbtfpgIZdCVdPZkHQNzBCZmOnPjTDYW0JN4qET18p4toSEE7ZIZo1v5Hf7CZKPugAhiSkrWuNmekUvAQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785796
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58634 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58635 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 126
content-type: application/json

[Body (126 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"jwks","method":"GET","agent_id":"http://127.0.0.1:8001"}
================================================================================

INFO:     127.0.0.1:58633 - "GET /data-jwks HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-jwks
================================================================================
HTTP/1.1 200 OK
content-length: 126
content-type: application/json
date: Mon, 19 Jan 2026 01:23:16 GMT
server: uvicorn

[Body (126 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"jwks","method":"GET","agent_id":"http://127.0.0.1:8001"}
================================================================================

Status: 200
Response: {'message': 'Access granted', 'data': 'This is protected data', 'scheme': 'jwks', 'method': 'GET', 'agent_id': 'http://127.0.0.1:8001'}
✓ sig=jwks works on /data-jwks endpoint
  Agent ID: http://127.0.0.1:8001

Press Enter to continue to Demo 3...

================================================================================
Demo 3: Verify metadata endpoint
================================================================================
INFO:     127.0.0.1:58636 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
Status: 200
Metadata: {'agent': 'http://127.0.0.1:8001', 'jwks_uri': 'http://127.0.0.1:8001/jwks.json'}
✓ Agent metadata endpoint works

Press Enter to continue to Demo 4...

================================================================================
Demo 4: Verify JWKS endpoint
================================================================================
INFO:     127.0.0.1:58637 - "GET /jwks.json HTTP/1.1" 200 OK
Status: 200
JWKS: {'keys': [{'kty': 'OKP', 'crv': 'Ed25519', 'x': 'b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY', 'kid': 'key-1'}]}
✓ Agent JWKS endpoint works
  Key ID (kid): key-1

Press Enter to continue to Demo 5...

================================================================================
Demo 5: Wrong scheme rejected
================================================================================

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-jwks
================================================================================
GET http://127.0.0.1:8002/data-jwks HTTP/1.1
Signature: sig1=:zDrickfQykjSZFv04VG3PGpAYledPVEIGdHuZToURTMWvyInF9LMF-6fKtn2vKKjWUKyJaAB29rL475BJVR5Aw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785799
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-jwks HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:zDrickfQykjSZFv04VG3PGpAYledPVEIGdHuZToURTMWvyInF9LMF-6fKtn2vKKjWUKyJaAB29rL475BJVR5Aw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785799
signature-key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; identity=?1
content-length: 48

[Body (48 bytes)]
Invalid signature scheme: expected jwks, got hwk
================================================================================

INFO:     127.0.0.1:58638 - "GET /data-jwks HTTP/1.1" 401 Unauthorized

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-jwks
================================================================================
HTTP/1.1 401 Unauthorized
agent-auth: httpsig; identity=?1
content-length: 48
date: Mon, 19 Jan 2026 01:23:19 GMT
server: uvicorn

[Body (48 bytes)]
Invalid signature scheme: expected jwks, got hwk
================================================================================

Status: 401
Response: Invalid signature scheme: expected jwks, got hwk
✓ Wrong scheme correctly rejected

Press Enter to continue to Demo 6...

================================================================================
Demo 6: Both endpoints work independently
================================================================================

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-hwk
================================================================================
GET http://127.0.0.1:8002/data-hwk HTTP/1.1
Signature: sig1=:b2M-N-k6lllKCDYvtn1kJICoeksEmFY6RCXvavBdYBqqpX3ZHy2H3AGo6FvSCbm02HAIgc7ckEPfB_XGWmi8BQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785844
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-hwk HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:b2M-N-k6lllKCDYvtn1kJICoeksEmFY6RCXvavBdYBqqpX3ZHy2H3AGo6FvSCbm02HAIgc7ckEPfB_XGWmi8BQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785844
signature-key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="b-8CW2TppDJhevm4Db2QaKelJ1NLKQtZg1mwazqD9iY")
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

INFO:     127.0.0.1:58639 - "GET /data-hwk HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-hwk
================================================================================
HTTP/1.1 200 OK
content-length: 90
content-type: application/json
date: Mon, 19 Jan 2026 01:24:04 GMT
server: uvicorn

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================


================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-jwks
================================================================================
GET http://127.0.0.1:8002/data-jwks HTTP/1.1
Signature: sig1=:0O48KtRbtfpgIZdCVdPZkHQNzBCZmOnPjTDYW0JN4qET18p4toSEE7ZIZo1v5Hf7CZKPugAhiSkrWuNmekUvAQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785844
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-jwks HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:0O48KtRbtfpgIZdCVdPZkHQNzBCZmOnPjTDYW0JN4qET18p4toSEE7ZIZo1v5Hf7CZKPugAhiSkrWuNmekUvAQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785844
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58641 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58642 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 126
content-type: application/json

[Body (126 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"jwks","method":"GET","agent_id":"http://127.0.0.1:8001"}
================================================================================

INFO:     127.0.0.1:58640 - "GET /data-jwks HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-jwks
================================================================================
HTTP/1.1 200 OK
content-length: 126
content-type: application/json
date: Mon, 19 Jan 2026 01:24:04 GMT
server: uvicorn

[Body (126 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"jwks","method":"GET","agent_id":"http://127.0.0.1:8001"}
================================================================================

/data-hwk status: 200
/data-jwks status: 200
✓ Both endpoints work independently

================================================================================
Phase 2 Demo Complete!
================================================================================

Summary:
- sig=hwk works on /data-hwk endpoint (Phase 1)
- sig=jwks works on /data-jwks endpoint (Phase 2)
- Agent metadata endpoint works
- Agent JWKS endpoint works
- Wrong scheme correctly rejected
- Both endpoints work independently

Servers are still running. Press Ctrl+C to stop.
```