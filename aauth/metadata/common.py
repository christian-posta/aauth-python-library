"""Metadata identity checks for draft -11 discovery."""

from urllib.parse import urlsplit
from ..identifiers import validate_server_identifier, validate_endpoint_url
from ..errors import MetadataError


def validate_metadata(metadata, issuer, required=()):
    try:
        validate_server_identifier(issuer)
        if not isinstance(metadata, dict) or "issuer" not in metadata:
            raise MetadataError(
                "Metadata issuer is missing", details={"error_code": "issuer_missing"}
            )
        if metadata["issuer"] != issuer:
            raise MetadataError(
                "Metadata issuer mismatch", details={"error_code": "issuer_mismatch"}
            )
        for name in required:
            if name not in metadata:
                raise MetadataError(f"Metadata missing {name}")
        for name, value in metadata.items():
            if name.endswith("_endpoint"):
                validate_endpoint_url(value)
            if name == "jwks_uri" and (
                not isinstance(value, str) or urlsplit(value).scheme != "https"
            ):
                raise MetadataError("JWKS URI must be HTTPS")
        return metadata
    except MetadataError:
        raise
    except (ValueError, TypeError) as exc:
        raise MetadataError(str(exc)) from exc


def common_fields(
    issuer,
    jwks_uri,
    *,
    name=None,
    description=None,
    documentation_uri=None,
    accept_signature_algs=None,
):
    m = {"issuer": issuer, "jwks_uri": jwks_uri}
    for field, value in [
        ("name", name),
        ("description", description),
        ("documentation_uri", documentation_uri),
        ("accept_signature_algs", accept_signature_algs),
    ]:
        if value is not None:
            m[field] = value
    return validate_metadata(m, issuer, ("jwks_uri",))


def issuer_from_metadata_url(url):
    marker = "/.well-known/"
    if marker not in url:
        raise MetadataError("Expected a well-known metadata URL")
    issuer, _, suffix = url.partition(marker)
    if not suffix or "/" in suffix or "?" in suffix or "#" in suffix:
        raise MetadataError("Invalid metadata URL")
    return issuer
