"""Signature-Input header parsing and building for AAuth."""

import re
import time
from typing import List, Dict, Any, Optional


def build_signature_input_header(
    covered_components: List[str],
    label: str = "sig1",
    created: Optional[int] = None
) -> str:
    """Build Signature-Input header per RFC 9421 Section 4.1.
    
    Args:
        covered_components: List of component names to cover
        label: Signature label (default: "sig1")
        created: Creation timestamp (Unix time). If None, uses current time.
        
    Returns:
        Signature-Input header value
    """
    if created is None:
        created = int(time.time())
    
    # Format components: "@method" "@authority" "content-type"
    component_list = ' '.join([
        f'"{comp}"' for comp in covered_components
    ])
    
    return f'{label}=({component_list});created={created}'


def parse_signature_input(header_value: str) -> tuple[List[str], Dict[str, Any]]:
    """Parse Signature-Input header to extract covered components and parameters.
    
    Args:
        header_value: Signature-Input header value
        
    Returns:
        Tuple of (components list, parameters dict)
        
    Raises:
        ValueError: If header format is invalid
    """
    match = re.match(r'(\w+)=\((.*)\)(?:;(.*))?', header_value)
    if not match:
        raise ValueError(f"Invalid Signature-Input format: {header_value}")
    
    label = match.group(1)
    components_str = match.group(2)
    params_str = match.group(3) or ""
    
    components = []
    for match in re.finditer(r'"([^"]+)"', components_str):
        components.append(match.group(1))
    
    params = {}
    for match in re.finditer(r'(\w+)=([^\s;]+)', params_str):
        key = match.group(1)
        value = match.group(2).strip('"')
        params[key] = value
    
    return components, params

