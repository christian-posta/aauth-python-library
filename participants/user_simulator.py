"""User simulator for automated browser redirect simulation in Phase 4."""

import httpx
from typing import Optional, Dict, Any
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import _is_debug_enabled


class UserSimulator:
    """Simulates a user browser for automated testing of user consent flows."""
    
    def __init__(self, username: str = "testuser", password: str = "testpass"):
        """Initialize user simulator.
        
        Args:
            username: Username for authentication
            password: Password for authentication
        """
        self.username = username
        self.password = password
        self.debug = _is_debug_enabled()
    
    async def complete_flow(
        self,
        request_token_url: str,
        redirect_uri: str,
        auth_server_base: Optional[str] = None
    ) -> Optional[str]:
        """Complete the full user consent flow.
        
        Args:
            request_token_url: Full URL with request_token and redirect_uri parameters
            redirect_uri: The agent's callback URI
            auth_server_base: Base URL of auth server (extracted from request_token_url if not provided)
            
        Returns:
            Authorization code if successful, None otherwise
        """
        if self.debug:
            print(f"DEBUG USER_SIM: Starting user consent flow", file=sys.stderr, flush=True)
            print(f"DEBUG USER_SIM:   Request token URL: {request_token_url}", file=sys.stderr, flush=True)
            print(f"DEBUG USER_SIM:   Redirect URI: {redirect_uri}", file=sys.stderr, flush=True)
        
        # Parse the request_token_url to extract parameters
        parsed_url = urlparse(request_token_url)
        query_params = parse_qs(parsed_url.query)
        
        request_token = query_params.get("request_token", [None])[0]
        redirect_uri_param = query_params.get("redirect_uri", [redirect_uri])[0]
        
        if not request_token:
            if self.debug:
                print(f"DEBUG USER_SIM:   No request_token found in URL", file=sys.stderr, flush=True)
            return None
        
        # Extract auth server base URL
        if not auth_server_base:
            auth_server_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Step 1: Follow redirect to auth server's /agent/auth endpoint
        auth_url = f"{auth_server_base}/agent/auth?request_token={request_token}&redirect_uri={redirect_uri_param}"
        
        if self.debug:
            print(f"DEBUG USER_SIM:   Fetching auth page: {auth_url}", file=sys.stderr, flush=True)
        
        async with httpx.AsyncClient(follow_redirects=False) as client:
            # Step 2: GET /agent/auth (may redirect to login or show consent)
            response = await client.get(auth_url)
            
            if self.debug:
                print(f"DEBUG USER_SIM:   Auth page response: {response.status_code}", file=sys.stderr, flush=True)
            
            # Step 3: Check if we need to authenticate first
            # If response contains login form, authenticate
            if response.status_code == 200:
                content = response.text
                
                # Check if this is a login page (contains username/password fields)
                if "username" in content.lower() and "password" in content.lower():
                    if self.debug:
                        print(f"DEBUG USER_SIM:   Login page detected, authenticating...", file=sys.stderr, flush=True)
                    
                    # Step 4: Submit login form
                    login_response = await client.post(
                        f"{auth_server_base}/agent/auth",
                        data={
                            "request_token": request_token,
                            "redirect_uri": redirect_uri_param,
                            "username": self.username,
                            "password": self.password,
                            "action": "login"
                        },
                        follow_redirects=False
                    )
                    
                    if self.debug:
                        print(f"DEBUG USER_SIM:   Login response: {login_response.status_code}", file=sys.stderr, flush=True)
                    
                    # If login redirects, follow it
                    if login_response.status_code in (302, 303, 307, 308):
                        location = login_response.headers.get("Location")
                        if location:
                            if self.debug:
                                print(f"DEBUG USER_SIM:   Following login redirect: {location}", file=sys.stderr, flush=True)
                            response = await client.get(location, follow_redirects=False)
                            content = response.text
                
                # Step 5: Now we should be on the consent page
                # Extract consent form data and submit grant
                if "consent" in content.lower() or "grant" in content.lower():
                    if self.debug:
                        print(f"DEBUG USER_SIM:   Consent page detected, granting consent...", file=sys.stderr, flush=True)
                    
                    # Step 6: Submit consent form (grant)
                    consent_response = await client.post(
                        f"{auth_server_base}/agent/auth",
                        data={
                            "request_token": request_token,
                            "redirect_uri": redirect_uri_param,
                            "consent": "grant"
                        },
                        follow_redirects=False
                    )
                    
                    if self.debug:
                        print(f"DEBUG USER_SIM:   Consent response: {consent_response.status_code}", file=sys.stderr, flush=True)
                    
                    # Step 7: Extract authorization code from redirect
                    if consent_response.status_code in (302, 303, 307, 308):
                        location = consent_response.headers.get("Location")
                        if location:
                            if self.debug:
                                print(f"DEBUG USER_SIM:   Redirect location: {location}", file=sys.stderr, flush=True)
                            
                            # Parse redirect URL to extract code
                            redirect_parsed = urlparse(location)
                            redirect_query = parse_qs(redirect_parsed.query)
                            
                            code = redirect_query.get("code", [None])[0]
                            
                            if code:
                                if self.debug:
                                    print(f"DEBUG USER_SIM:   Authorization code extracted: {code[:20]}...", file=sys.stderr, flush=True)
                                return code
                            else:
                                error = redirect_query.get("error", [None])[0]
                                if error:
                                    if self.debug:
                                        print(f"DEBUG USER_SIM:   Error in redirect: {error}", file=sys.stderr, flush=True)
                                    return None
        
        if self.debug:
            print(f"DEBUG USER_SIM:   Flow completed but no authorization code found", file=sys.stderr, flush=True)
        
        return None
    
    async def deny_consent(
        self,
        request_token_url: str,
        redirect_uri: str,
        auth_server_base: Optional[str] = None
    ) -> bool:
        """Simulate user denying consent.
        
        Args:
            request_token_url: Full URL with request_token and redirect_uri parameters
            redirect_uri: The agent's callback URI
            auth_server_base: Base URL of auth server
            
        Returns:
            True if denial was successful, False otherwise
        """
        if self.debug:
            print(f"DEBUG USER_SIM: Simulating consent denial", file=sys.stderr, flush=True)
        
        # Similar to complete_flow but submit consent=deny
        parsed_url = urlparse(request_token_url)
        query_params = parse_qs(parsed_url.query)
        
        request_token = query_params.get("request_token", [None])[0]
        redirect_uri_param = query_params.get("redirect_uri", [redirect_uri])[0]
        
        if not request_token:
            return False
        
        if not auth_server_base:
            auth_server_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        async with httpx.AsyncClient(follow_redirects=False) as client:
            # Get auth page (may need to authenticate first)
            auth_url = f"{auth_server_base}/agent/auth?request_token={request_token}&redirect_uri={redirect_uri_param}"
            response = await client.get(auth_url)
            
            if response.status_code == 200:
                content = response.text
                
                # Authenticate if needed
                if "username" in content.lower() and "password" in content.lower():
                    await client.post(
                        f"{auth_server_base}/agent/auth",
                        data={
                            "request_token": request_token,
                            "redirect_uri": redirect_uri_param,
                            "username": self.username,
                            "password": self.password,
                            "action": "login"
                        },
                        follow_redirects=False
                    )
                    # Re-fetch consent page
                    response = await client.get(auth_url, follow_redirects=False)
                    content = response.text
                
                # Submit denial
                if "consent" in content.lower():
                    consent_response = await client.post(
                        f"{auth_server_base}/agent/auth",
                        data={
                            "request_token": request_token,
                            "redirect_uri": redirect_uri_param,
                            "consent": "deny"
                        },
                        follow_redirects=False
                    )
                    
                    # Check if redirect contains error
                    if consent_response.status_code in (302, 303, 307, 308):
                        location = consent_response.headers.get("Location")
                        if location and "error=access_denied" in location:
                            return True
        
        return False

