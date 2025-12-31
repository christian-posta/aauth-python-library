# Phase 1 Spec Compliance Fixes

## Issues Fixed

### 1. Agent-Auth Header (Section 4)
**Before:** Using `WWW-Authenticate: AAuth`  
**After:** Using `Agent-Auth: httpsig` per spec Section 4.1

### 2. Signature-Key Header Format (Section 10.1)
**Before:** `sig=hwk; kty="OKP"; crv="Ed25519"; x="..."`  
**After:** `sig=(scheme=hwk kty="OKP" crv="Ed25519" x="...")`  
**Reason:** Must be RFC 8941 Structured Fields Dictionary format

### 3. Signature-Input Header (Section 10)
**Before:** Missing entirely  
**After:** `sig1=("@method" "@authority" "@path" "signature-key");created=1730217600`  
**Reason:** Required by RFC 9421 and AAuth spec

### 4. Covered Components (Section 10.3)
**Before:** Using `@target-uri`  
**After:** Using `@authority` and `@path` separately  
**Reason:** Spec requires separate components, not combined

### 5. Signature-Key Component Coverage
**Before:** Not including `signature-key` in covered components  
**After:** Always including `signature-key` as required component  
**Reason:** Spec Section 10 states `signature-key` MUST always be covered

### 6. Content-Digest Format
**Before:** Custom format  
**After:** RFC 9530 format: `sha-256=:base64:`  
**Reason:** Spec Section 10.3 requires RFC 9530 compliance

## Implementation Details

### Signature Generation
- Uses `@method`, `@authority`, `@path` (always)
- Adds `@query` if query string present
- Adds `content-type` and `content-digest` if body present
- Always includes `signature-key` component
- Generates `Signature-Input` header with component list and `created` parameter
- Generates `Signature` header with base64 signature
- Generates `Signature-Key` header in RFC 8941 format

### Signature Verification
- Parses `Signature-Input` to extract covered components
- Validates `created` timestamp (within 60 seconds)
- Verifies label consistency across all three headers (spec Section 10.1.1)
- Reconstructs signature base from covered components
- Verifies signature using extracted public key

### Error Responses
- All 401 responses now use `Agent-Auth: httpsig` header
- Matches spec Section 4.1 for signature required challenge

