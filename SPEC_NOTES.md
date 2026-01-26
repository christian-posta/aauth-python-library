Regarding Content-Digest in Signature:

Looking back at the search results, there's actually some nuance here. Let me search for more clarity on the body signing requirements:This is a great question because there's some nuance here. Looking at the current spec (README.md), **content-digest is NOT required by default**, even for requests with bodies.

## Default Requirements (All Requests)

Only these four components are mandatory:
- `@method`
- `@authority`
- `@path`
- `signature-key`

## Body-Related Components Are Optional (Server-Specific)

Content-type and content-digest are only required **if the server explicitly requests them** via `additional_signature_components` in their metadata:

```json
{
  "resource": "https://resource.example",
  "additional_signature_components": ["content-type", "content-digest"]
}
```

## Proof from the Examples

**Example 3** - POST with body, default coverage (no content-digest!):
```http
POST /api/data HTTP/1.1
Host: resource.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
...
{"action":"update","value":42}
```

**Example 5** - POST with body integrity (server-specific requirement):
```http
POST /api/data HTTP/1.1
...
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=1730217600
```

---

This design choice makes sense given your earlier debugging struggles with content-digest mismatches from JSON serialization differences. Making it opt-in lets servers decide whether they want to accept the implementation complexity of raw body handling for signature verification.