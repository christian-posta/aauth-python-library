# Phase 5: Agent is Resource Implementation Plan

## Overview

Phase 5 implements Section 3.5 from SPEC.md: an agent authenticates users to itself (agent identifier matches resource identifier) for both SSO and API access. The agent requests authorization directly with `scope` or `auth_request_url` instead of a `resource_token`. The returned auth token can be used to verify user identity and by agent delegates to call the agent's APIs.

## Key Differences from Phase 4

1. **No resource token**: Agent provides `scope` or `auth_request_url` directly
2. **Agent = Resource**: The `aud` claim in auth token is the agent identifier, and `agent` claim is omitted
3. **Unified token**: Single auth token serves both SSO (user identity) and API access purposes

## Implementation Tasks

### 1. Auth Server: Support Direct Authorization Request (`participants/auth_server.py`)

**Modify `_handle_token_request()` method:**

- **Accept `scope` or `auth_request_url`** when `resource_token` is not provided
- **Validate agent signature** (same as Phase 4)
- **Extract agent identifier** from signature (scheme=jwks)
- **Use agent identifier as resource identifier** when `scope`/`auth_request_url` is provided directly
- **Policy evaluation**: When agent is resource, evaluate policy based on agent identifier as both agent and resource
- **Token issuance**: Issue auth token with:
  - `aud` = agent identifier (agent is the resource)
  - `agent` claim **omitted** (per SPEC.md Section 7.3: "When the agent uses the auth server for SSO... `aud` is the agent identifier and this claim is omitted")
  - `sub` = user identifier (after user consent)
  - `scope` = requested scope
  - `cnf.jwk` = agent's signing key

**Key validation logic:**
- If `resource_token` provided → validate resource token (existing Phase 4 logic)
- If `scope` or `auth_request_url` provided → validate agent signature, use agent as resource
- Exactly one of `resource_token`, `scope`, or `auth_request_url` must be provided (per SPEC.md Section 9.3)

### 2. Auth Server: Update Token Issuance (`participants/auth_server.py`)

**Modify `_issue_auth_token()` method:**

- **Add parameter** `agent_is_resource: bool = False`
- **When `agent_is_resource=True`**:
  - Set `aud` = agent identifier (not resource parameter)
  - Omit `agent` claim from payload
- **When `agent_is_resource=False`** (existing behavior):
  - Set `aud` = resource parameter
  - Include `agent` claim

**Update `create_auth_token()` in `core/tokens.py`:**

- **Add parameter** `agent_is_resource: bool = False`
- **Conditionally include `agent` claim**: Only include if `agent_is_resource=False`
- **Set `aud` appropriately**: Use agent identifier when `agent_is_resource=True`

### 3. Agent: Direct Authorization Request (`participants/agent.py`)

**Add new method `request_self_authorization()`:**

- **Parameters**: `scope: str`, `auth_server: str`, `redirect_uri: str`
- **Make signed request** to auth server's token endpoint with:
  - `request_type=auth`
  - `scope=<scope>` (no `resource_token`)
  - `redirect_uri=<redirect_uri>`
- **Handle 202 deferred response** (same as Phase 4: pending URL, interaction code, polling)
- **Complete user consent at `/interact`** (same as Phase 4)
- **Store auth token** for use in SSO and API access

**Update `_request_auth_token()` method:**

- **Support both flows**: Resource token flow (Phase 4) and direct scope flow (Phase 5)
- **Detect flow type**: Check if `resource_token` or `scope` is provided

### 4. Demo Script (`demo_phase5.py`)

**Create new demo script:**

- **Setup**: Agent, Auth Server (with user consent enabled)
- **Flow**:
  1. Agent requests self-authorization with `scope=profile email`
  2. Auth server returns 202 + pending URL + interaction code
  3. User simulator completes consent at `/interact`
  4. Agent polls pending URL until `auth_token`
  5. **Verify auth token claims**:
     - `aud` = agent identifier
     - `agent` claim omitted
     - `sub` = user identifier
     - `scope` = requested scope
  6. **Demonstrate dual use**:
     - Use token for SSO (verify user identity from `sub` claim)
     - Use token for API access (agent delegates can use it)

### 5. Tests (`tests/test_phase5.py`)

**Create test suite:**

- **Test direct authorization request** with scope
- **Test auth token claims** when agent is resource:
  - Verify `aud` = agent identifier
  - Verify `agent` claim is omitted
  - Verify `sub` claim present after user consent
- **Test token validation** by agent (as resource) for SSO use case
- **Test token validation** by agent delegates for API access

### 6. Documentation (`PHASE5.md`)

**Create phase documentation:**

- **Flow description**: Agent authenticates users to itself
- **Key features**: Direct authorization, unified token, SSO + API access
- **Sequence diagram**: Show complete flow
- **Testing instructions**: Automated and manual modes
- **Use cases**: SSO, API access by delegates

## Files to Modify

1. `participants/auth_server.py`:
   - `_handle_token_request()`: Support `scope`/`auth_request_url` parameters
   - `_issue_auth_token()`: Add `agent_is_resource` parameter
   - `_evaluate_policy()`: Handle agent-as-resource case

2. `core/tokens.py`:
   - `create_auth_token()`: Add `agent_is_resource` parameter, conditionally omit `agent` claim

3. `participants/agent.py`:
   - Add `request_self_authorization()` method
   - Update `_request_auth_token()` to support both flows

## Files to Create

1. `demo_phase5.py`: Demo script for Phase 5
2. `tests/test_phase5.py`: Test suite for Phase 5
3. `PHASE5.md`: Phase 5 documentation
4. `flows/agent_is_resource.py`: Flow orchestration (optional, similar to `flows/user_delegated.py`)

## Implementation Notes

- **Backward compatibility**: Phase 4 flow (with resource_token) must continue to work
- **Token format**: When `agent_is_resource=True`, the `agent` claim is omitted per SPEC.md Section 7.3
- **Policy evaluation**: Auth server should allow agent to request authorization to itself (agent identifier = resource identifier)
- **User consent**: Same user consent flow as Phase 4, but token issued with different claims structure

## Implementation Todos

1. **auth-server-direct-auth**: Modify auth server `_handle_token_request()` to accept `scope` or `auth_request_url` when `resource_token` is not provided, validate agent signature, and use agent identifier as resource identifier

2. **auth-server-token-issuance**: Update `_issue_auth_token()` and `create_auth_token()` to support `agent_is_resource` parameter, omit `agent` claim when true, and set `aud` to agent identifier
   - Depends on: auth-server-direct-auth

3. **agent-direct-request**: Add `request_self_authorization()` method to Agent class for requesting authorization directly with scope (no `resource_token`)

4. **demo-script**: Create `demo_phase5.py` script demonstrating agent authenticating users to itself with SSO and API access use cases
   - Depends on: auth-server-direct-auth, agent-direct-request

5. **tests**: Create `test_phase5.py` with tests for direct authorization, token claims validation (`aud`=agent, `agent` omitted, `sub` present), and dual-use scenarios
   - Depends on: auth-server-token-issuance, agent-direct-request

6. **documentation**: Create `PHASE5.md` documenting the flow, key features, sequence diagram, and testing instructions
   - Depends on: demo-script

