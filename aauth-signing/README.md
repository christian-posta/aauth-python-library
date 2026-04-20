# aauth-signing

HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and the **Signature-Key** header ([draft-hardt-httpbis-signature-key](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/)) as used by [AAuth](https://github.com/ietf-wg-aauth).

This package is **AAuth-oriented** (e.g. `aa-agent+jwt` / `aa-auth+jwt` in the `jwt` signature scheme, optional `aauth-mission` covered component).

## Install

```bash
pip install aauth-signing
```

## Usage

```python
from aauth_signing import sign_request, verify_signature
from aauth_signing import build_signature_key_header, parse_signature_key
```

## Development

From the repository root:

```bash
pip install -e ./aauth-signing
```
