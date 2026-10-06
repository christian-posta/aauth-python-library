# aauth-signing

Standalone HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and the [Signature-Key header](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/), with the algorithm and validation rules used by AAuth Protocol draft -11.

```python
from aauth_signing import sign_request, verify_signature
from aauth_signing.keys.keypair import generate_ed25519_keypair

private_key, public_key = generate_ed25519_keypair()
headers = {"Content-Type": "application/json"}
body = b'{"message":"hello"}'
headers.update(sign_request(
    "POST", "https://resource.example/data", headers, body, private_key,
    sig_scheme="hwk",
    additional_signature_components=["content-digest", "content-type"],
))
assert verify_signature(
    "POST", "https://resource.example/data", headers, body,
    headers["Signature-Input"], headers["Signature"], headers["Signature-Key"],
)
```

Supports `hwk`, `jwks_uri`, `jwt`, and `jkt-jwt`. AAuth agents use `jwt`; the generic schemes remain available for other callers. X.509 verification is not implemented.

Generated keys carry `alg` (`Ed25519`, `ES256`, or `ES384`). Verifiers reject missing or incompatible algorithms, missing/stale signature creation timestamps, expired signatures, missing required components, and body/digest mismatches. The default required components are `@method`, `@authority`, `@path`, and `signature-key`; configure `required_components` for the recipient's additional requirements. `authorization` is automatically covered when present.

Bodies are signed when requested through `additional_signature_components`. PS/AS and revocation callers must include `content-digest` and `content-type`. Verification checks the digest against received bytes. HTTP verification supports EC DER and P1363 signatures; JWT encoding uses standard JOSE encoding.

`jwks_fetcher(issuer, dwk, kid)` is synchronous and must perform admitted, identity-checked discovery and caching. The signing layer authenticates key possession; applications enforce JWT type, issuer trust, audience, authorization, and revocation. Use the `aauth` package for those protocol checks.

Development from the repository root:

```bash
pip install -e ./aauth-signing
```
