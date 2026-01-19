# Phase 7: Token Exchange

## Overview

Phase 7 implements **Token Exchange** as described in SPEC.md Section 3.9 and 9.10. This enables multi-hop resource access where a resource (acting as an agent) can exchange an upstream auth token to access a downstream resource.

When a resource needs to call a downstream resource to fulfill a request, it:
1. Presents the upstream auth token to the downstream auth server
2. Uses `request_type=exchange` to request a new token
3. Receives a new auth token with an `act` claim showing the delegation chain
4. Uses this new token to access the downstream resource

## Key Concepts

### Token Exchange Flow

```mermaid
sequenceDiagram
    participant Agent1 as Agent 1
    participant Resource1 as Resource 1 / Agent 2
    participant Auth2 as Auth Server 2
    participant Resource2 as Resource 2

    Agent1->>Resource1: HTTPSig request with auth_token
    Note over Agent1,Resource1: Agent 1 accesses Resource 1
    
    Resource1->>Resource2: Attempt access (no auth)
    Resource2->>Resource1: 401 with resource_token
    Note over Resource1,Resource2: Resource 2 challenges Resource 1
    
    Resource1->>Auth2: request_type=exchange<br/>+ resource_token<br/>(scheme=jwt with upstream auth_token)
    Note over Resource1,Auth2: Resource 1 exchanges upstream token
    
    Auth2->>Auth2: Validate upstream token<br/>Check federation trust<br/>Build act claim
    Auth2->>Resource1: auth_token with act claim
    
    Resource1->>Resource2: HTTPSig request with new auth_token
    Resource2->>Resource1: 200 OK
    
    Resource1->>Agent1: 200 OK (aggregated response)
```

### Federation Trust

Token exchange requires **federation trust** between auth servers:

- Auth Server 2 must trust Auth Server 1 to validate upstream tokens
- This is configured via the `trusted_auth_servers` parameter on `AuthServer`
- Without trust, the exchange request is rejected

```python
# Auth Server 2 trusts Auth Server 1
auth_server2 = AuthServer(
    "http://auth2.example",
    port=8005,
    trusted_auth_servers=["http://auth1.example"]
)
```

### Actor (`act`) Claim

The `act` claim represents the delegation chain. It shows who delegated authority to the current agent:

```json
{
  "iss": "https://auth2.example",
  "aud": "https://resource2.example",
  "agent": "https://resource1.example",
  "sub": "user-12345",
  "scope": "data.read",
  "act": {
    "agent": "https://agent1.example",
    "agent_delegate": "api-service-instance-abc",
    "sub": "user-12345"
  }
}
```

**Required fields in `act`:**
- `agent`: The HTTPS URL of the upstream agent

**Optional fields in `act`:**
- `agent_delegate`: The upstream agent delegate identifier
- `sub`: The user identifier (if present in upstream token)
- `act`: Nested actor claim for multi-hop chains (3+ levels)

### Multi-Hop Delegation Chains

For chains with more than two hops, the `act` claim can be nested:

```json
{
  "agent": "https://resource2.example",
  "act": {
    "agent": "https://resource1.example",
    "sub": "user-12345",
    "act": {
      "agent": "https://agent1.example",
      "sub": "user-12345"
    }
  }
}
```

## Implementation Details

### Files Modified

| File | Changes |
|------|---------|
| `core/tokens.py` | Added `act` parameter to `create_auth_token()` |
| `participants/auth_server.py` | Added `_handle_token_exchange()`, `trusted_auth_servers` config |
| `participants/resource.py` | Added `call_downstream_resource()` and `_exchange_token()` methods |

### Key Methods

#### `AuthServer._handle_token_exchange()`

Handles `request_type=exchange` requests:

1. Extracts `resource_token` from request body
2. Validates that `scheme=jwt` is used with upstream auth token
3. Parses and validates upstream token claims
4. Verifies upstream auth server is trusted
5. Fetches and validates upstream auth server JWKS
6. Validates upstream token signature
7. Validates resource token and extracts scope
8. Verifies upstream token audience matches requesting resource
9. Verifies HTTPSig signature using upstream token's `cnf.jwk`
10. Builds `act` claim from upstream token claims
11. Issues new auth token with `act` claim

#### `Resource.call_downstream_resource()`

Enables a resource to act as an agent:

1. Attempts to access downstream resource
2. Parses 401 challenge to extract `resource_token` and `auth_server`
3. Calls `_exchange_token()` to get downstream auth token
4. Signs request with exchanged token
5. Accesses downstream resource

#### `Resource._exchange_token()`

Performs the token exchange:

1. Builds POST request to auth server's token endpoint
2. Signs request with `scheme=jwt` using upstream auth token
3. Parses response to extract new auth token

## Running the Demo

```bash
# Run with debug output (default)
AAUTH_DEBUG=1 python demo_phase7.py

# Run with HTTP debug output
AAUTH_HTTP_DEBUG=1 python demo_phase7.py
```

The demo shows:
1. Agent 1 obtaining an auth token for Resource 1
2. Resource 1 calling Resource 2 via token exchange
3. Verification that the exchanged token contains the `act` claim

## Testing

```bash
# Run Phase 7 tests
pytest tests/test_phase7.py -v

# Run specific test
pytest tests/test_phase7.py::test_token_exchange_flow -v
pytest tests/test_phase7.py::test_token_exchange_returns_act_claim -v
pytest tests/test_phase7.py::test_untrusted_auth_server_rejected -v
```

### Test Coverage

| Test | Description |
|------|-------------|
| `test_create_auth_token_with_act_claim` | Auth token can include `act` claim |
| `test_create_auth_token_with_nested_act` | Nested `act` claims for multi-hop |
| `test_auth_server_with_trusted_servers` | Federation trust configuration |
| `test_token_exchange_flow` | Complete token exchange flow |
| `test_token_exchange_returns_act_claim` | Exchanged token has correct `act` claim |
| `test_untrusted_auth_server_rejected` | Exchange fails without trust |

## Security Considerations

### Federation Trust

- Auth servers MUST have explicit trust relationships configured
- Untrusted upstream tokens are rejected
- Trust relationships should be established through secure channels

### Scope Narrowing

Per SPEC.md, the downstream scope should typically be narrower than or equal to the upstream authorization. This implementation extracts the scope from the resource token.

### Chain Depth Limits

Auth servers MAY enforce limits on delegation chain depth to prevent abuse. The current implementation does not enforce limits but the `act` chain can be inspected for policy decisions.

### User Context Preservation

The `sub` claim MUST be maintained through the chain to preserve user identity. The implementation copies the user identifier from the upstream token to both the new token and the `act` claim.

### Refresh Tokens

Token exchange requests do not return refresh tokens. Resources must re-exchange when tokens expire.

## Reference

- [SPEC.md Section 3.9: Token Exchange](SPEC.md#39-token-exchange)
- [SPEC.md Section 9.10: Token Exchange](SPEC.md#910-token-exchange)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) (conceptual background)

## Output

❯ python demo_phase7.py

================================================================================
Phase 7: Token Exchange Demo
================================================================================

MODE: Automated
================================================================================
This demo shows the token exchange flow:
1. Agent 1 obtains auth_token for Resource 1 from Auth Server 1
2. Agent 1 accesses Resource 1 with auth_token
3. Resource 1 needs to call Resource 2 to fulfill the request
4. Resource 1 receives 401 challenge from Resource 2 with resource_token
5. Resource 1 exchanges upstream auth_token for downstream auth_token at Auth Server 2
6. Auth Server 2 validates upstream token, trusts Auth Server 1, issues token with 'act' claim
7. Resource 1 accesses Resource 2 with exchanged token
8. Resource 1 returns aggregated response to Agent 1

Debug output is enabled by default.
================================================================================

Starting Agent 1...
Starting Resource 1...
Starting Resource 2...
Starting Auth Server 1...
Starting Auth Server 2...
Waiting for servers to start...
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8005 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8004 (Press CTRL+C to quit)

================================================================================
Starting tests...
================================================================================

================================================================================
TEST 1: Agent 1 Obtains Auth Token for Resource 1
================================================================================
Description: Agent 1 requests auth token from Auth Server 1 for Resource 1.
================================================================================

📤 Agent 1 requesting auth token for Resource 1...

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:bfJBXxQfM_-qjKpgUnjsHF_vjkGkMfSvZvcjCR7n0QXGuOWosMpgdQmDraokNjr41wkdy75dfIS-7FXkrjeaDw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:bfJBXxQfM_-qjKpgUnjsHF_vjkGkMfSvZvcjCR7n0QXGuOWosMpgdQmDraokNjr41wkdy75dfIS-7FXkrjeaDw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58718 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58719 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58717 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 401 Unauthorized
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58720 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8003/agent/token
================================================================================
POST http://127.0.0.1:8003/agent/token HTTP/1.1
Content-Digest: sha-256=:Fcjm6yHvR96HB/jUtepWiP8WWE4IjEmjyoecGPccDOw=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:-cxGlWSvyaoSrHQ0XbhsTC3VRowsek8XdsO00POA5LanW3U7Ra6A6AYaV06OQLA9uo1JOZ7cz19nYq79q2fsAA:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRPSFhOMHZBVnJtSEoyeDloMWVYejZlVl9sLUVvc0hWQ2dnaEdiR25CREUiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.Eibyqh1nM1SQkXyggP2W2FuoJO4l0iGufNekJ4oUb22UWLi1Eah0QHwFCdbJ1AXLH9y_lYTec7Hvwu7aC9jdAA&redirect_uri=http://127.0.0.1:8001/callback
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:Fcjm6yHvR96HB/jUtepWiP8WWE4IjEmjyoecGPccDOw=:
content-length: 510
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:-cxGlWSvyaoSrHQ0XbhsTC3VRowsek8XdsO00POA5LanW3U7Ra6A6AYaV06OQLA9uo1JOZ7cz19nYq79q2fsAA:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRPSFhOMHZBVnJtSEoyeDloMWVYejZlVl9sLUVvc0hWQ2dnaEdiR25CREUiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.Eibyqh1nM1SQkXyggP2W2FuoJO4l0iGufNekJ4oUb22UWLi1Eah0QHwFCdbJ1AXLH9y_lYTec7Hvwu7aC9jdAA&redirect_uri=http://127.0.0.1:8001/callback
================================================================================

INFO:     127.0.0.1:58722 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58723 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58724 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58725 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58726 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58727 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUkMtRXZmcnhyZjZ5T29qQ01Hall4d3NEcEZiNExLYTlFNFpMTnNHM3J3QSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.Wl1scb1W2MLmTS-oLkiDDBD5qNnr9x8cxqfwJSJ6KC1RV_850dlSmTHUpQ7TNAy8N3XgSQITNee_Gh9YzacFCA",
  "expires_in": 3600,
  "token_type": "Bearer"
}
================================================================================

INFO:     127.0.0.1:58721 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8003/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 545
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (545 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUkMtRXZmcnhyZjZ5T29qQ01Hall4d3NEcEZiNExLYTlFNFpMTnNHM3J3QSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.Wl1scb1W2MLmTS-oLkiDDBD5qNnr9x8cxqfwJSJ6KC1RV_850dlSmTHUpQ7TNAy8N3XgSQITNee_Gh9YzacFCA","expires_in":3600,"token_type":"Bearer"}
================================================================================


================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:r4bCepCmQ5T0rS8nnzZisfKYe6QGJvOvvDx5js9mBh4qBA3KcSx8ysWF6-uKQHvlmGQj05X_oB9XDCCNlz_VDQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:r4bCepCmQ5T0rS8nnzZisfKYe6QGJvOvvDx5js9mBh4qBA3KcSx8ysWF6-uKQHvlmGQj05X_oB9XDCCNlz_VDQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58729 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58730 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58731 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58732 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58728 - "GET /data-auth HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":null,"scope":"data.read data.write"}
================================================================================


================================================================================
RESOURCE TOKEN (decoded)
================================================================================
Header:
{
  "alg": "EdDSA",
  "kid": "resource-key-1",
  "typ": "resource+jwt"
}

Payload:
{
  "iss": "http://127.0.0.1:8002",
  "aud": "http://127.0.0.1:8003",
  "agent": "http://127.0.0.1:8001",
  "agent_jkt": "4OHXN0vAVrmHJ2x9h1eXz6eV_l-EosHVCgghGbGnBDE",
  "scope": "data.read data.write",
  "exp": 1768786873
}
================================================================================


================================================================================
AUTH TOKEN (decoded)
================================================================================
Header:
{
  "alg": "EdDSA",
  "kid": "auth-key-1",
  "typ": "auth+jwt"
}

Payload:
{
  "iss": "http://127.0.0.1:8003",
  "aud": "http://127.0.0.1:8002",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "RC-Evfrxrf6yOojCMGjYxwsDpFb4LKa9E4ZLNsG3rwA",
      "kid": "key-1"
    }
  },
  "scope": "data.read data.write",
  "exp": 1768789873,
  "agent": "http://127.0.0.1:8001"
}
================================================================================


✓ Auth token obtained: eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4...

Verifying auth token claims:
  iss: http://127.0.0.1:8003
  aud: http://127.0.0.1:8002
  agent: http://127.0.0.1:8001
  scope: data.read data.write

✓ TEST 1 PASSED: Auth token obtained for Resource 1

================================================================================
TEST 2: Resource 1 Calls Resource 2 via Token Exchange
================================================================================
Description: Resource 1 needs data from Resource 2. It exchanges the upstream token
             for a new token from Auth Server 2, which includes an 'act' claim.
================================================================================

📤 Resource 1 calling Resource 2 with token exchange...

================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8004
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8004
signature: sig1=:QyF8FyJHa_L2yYg7_wJL-VUv3oVIQcbQK8UDH3K8zaTTvFYoS3wVoy090jMt330QBvRKZ8Vl46_2iqs8Fn3eAA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8002" kid="resource-key-1" well-known="aauth-resource")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58734 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58735 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58733 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
>>> TOKEN EXCHANGE REQUEST to http://127.0.0.1:8005/agent/token
================================================================================
POST http://127.0.0.1:8005/agent/token HTTP/1.1
Content-Digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
content-length: 470
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8005
signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================

INFO:     127.0.0.1:58737 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58738 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58739 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58740 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58741 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58742 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE (Token Exchange)
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw",
  "expires_in": 3600
}
================================================================================

INFO:     127.0.0.1:58736 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< TOKEN EXCHANGE RESPONSE from http://127.0.0.1:8005/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 589
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (589 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw","expires_in":3600}
================================================================================


================================================================================
>>> RESOURCE (as agent) REQUEST to http://127.0.0.1:8004/data-auth
================================================================================
GET http://127.0.0.1:8004/data-auth HTTP/1.1
Signature: sig1=:ZZneZeSzbj7NQvv_RDs4kjtwKVeXadHCVDWVPrR3kyIRujc_ghFeBJbpfbqH1bbaZbbVuIFvi_PMLuewAibvCw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8004
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8004
signature: sig1=:ZZneZeSzbj7NQvv_RDs4kjtwKVeXadHCVDWVPrR3kyIRujc_ghFeBJbpfbqH1bbaZbbVuIFvi_PMLuewAibvCw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58744 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58745 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58746 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58747 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8002","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58743 - "GET /data-auth HTTP/1.1" 200 OK

================================================================================
<<< DOWNSTREAM RESPONSE from http://127.0.0.1:8004/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8002","agent_delegate":null,"scope":"data.read data.write"}
================================================================================


✓ Resource 2 access granted
  Response: {
  "message": "Access granted",
  "data": "This is protected data (authorized)",
  "scheme": "jwt",
  "token_type": "auth+jwt",
  "method": "GET",
  "agent": "http://127.0.0.1:8002",
  "agent_delegate": null,
  "scope": "data.read data.write"
}

✓ TEST 2 PASSED: Token exchange successful

================================================================================
TEST 3: Verify 'act' Claim in Exchanged Token
================================================================================
Description: Verify that the exchanged token contains an 'act' claim
             showing the delegation chain.
================================================================================

📤 Performing token exchange to inspect 'act' claim...

================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8004
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8004
signature: sig1=:QyF8FyJHa_L2yYg7_wJL-VUv3oVIQcbQK8UDH3K8zaTTvFYoS3wVoy090jMt330QBvRKZ8Vl46_2iqs8Fn3eAA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8002" kid="resource-key-1" well-known="aauth-resource")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58749 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58750 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58748 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
>>> TOKEN EXCHANGE REQUEST to http://127.0.0.1:8005/agent/token
================================================================================
POST http://127.0.0.1:8005/agent/token HTTP/1.1
Content-Digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
content-length: 470
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8005
signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================

INFO:     127.0.0.1:58752 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58753 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58754 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58755 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58756 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58757 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE (Token Exchange)
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw",
  "expires_in": 3600
}
================================================================================

INFO:     127.0.0.1:58751 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< TOKEN EXCHANGE RESPONSE from http://127.0.0.1:8005/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 589
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (589 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw","expires_in":3600}
================================================================================


Exchanged token claims:
  iss: http://127.0.0.1:8005
  aud: http://127.0.0.1:8004
  agent: http://127.0.0.1:8002
  sub: None
  act: {
    "agent": "http://127.0.0.1:8001"
}
  ✓ act.agent correct: http://127.0.0.1:8001

✓ TEST 3 PASSED: 'act' claim present and valid

================================================================================
TEST SUMMARY
================================================================================
✓ PASSED: TEST 1: Agent 1 Obtains Auth Token
✓ PASSED: TEST 2: Resource 1 Calls Resource 2
✓ PASSED: TEST 3: Verify 'act' Claim

--------------------------------------------------------------------------------
Total: 3 | Passed: 3 | Failed: 0
================================================================================


Shutting down all servers...
INFO:     Shutting down
INFO:     Shutting down
INFO:     Shutting down
INFO:     Shutting down
INFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [95877]
INFO:     Application shutdown complete.
INFO:     Finished server process [95877]
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [95877]
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [95877]
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [95877]
All servers terminated.
