"""
JSentinel Authentication Module
Handles cookies, headers, passwords, and session management for authenticated JS fetching.
"""

import json
import os
from typing import Dict, Optional, Any


class AuthManager:
    """Manages authentication credentials for accessing protected JS files."""

    def __init__(self, auth_file: Optional[str] = None):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.bearer_token: Optional[str] = None
        self.basic_auth: Optional[tuple] = None
        self.session_data: Dict[str, Any] = {}

        if auth_file and os.path.exists(auth_file):
            self.load_from_file(auth_file)

    def load_from_file(self, filepath: str):
        """Load auth data from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)

        self.cookies = data.get('cookies', {})
        self.headers = data.get('headers', {})
        self.bearer_token = data.get('bearer_token')
        self.basic_auth = tuple(data['basic_auth']) if 'basic_auth' in data else None
        self.session_data = data.get('session_data', {})

        # Auto-populate Authorization header if bearer token provided
        if self.bearer_token:
            self.headers['Authorization'] = f'Bearer {self.bearer_token}'

    def set_cookie(self, name: str, value: str):
        """Set a single cookie."""
        self.cookies[name] = value

    def set_header(self, name: str, value: str):
        """Set a custom header."""
        self.headers[name] = value

    def set_bearer_token(self, token: str):
        """Set Bearer token for JWT/API auth."""
        self.bearer_token = token
        self.headers['Authorization'] = f'Bearer {token}'

    def set_basic_auth(self, username: str, password: str):
        """Set Basic Auth credentials."""
        self.basic_auth = (username, password)

    def set_session_cookie(self, session_string: str):
        """Parse and set session cookie from browser string.

        Example: "sessionid=abc123; csrftoken=xyz789"
        """
        for cookie in session_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                self.cookies[name] = value

    def get_request_kwargs(self) -> Dict[str, Any]:
        """Get kwargs for requests library."""
        kwargs = {
            'cookies': self.cookies if self.cookies else None,
            'headers': self.headers if self.headers else None,
        }
        if self.basic_auth:
            kwargs['auth'] = self.basic_auth
        # Remove None values
        return {k: v for k, v in kwargs.items() if v is not None}

    def is_configured(self) -> bool:
        """Check if any auth method is configured."""
        return bool(self.cookies or self.headers or self.bearer_token or self.basic_auth)

    def save_to_file(self, filepath: str):
        """Save current auth config to JSON file."""
        data = {
            'cookies': self.cookies,
            'headers': self.headers,
            'bearer_token': self.bearer_token,
            'basic_auth': list(self.basic_auth) if self.basic_auth else None,
            'session_data': self.session_data,
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def __repr__(self):
        methods = []
        if self.cookies:
            methods.append(f"cookies({len(self.cookies)})")
        if self.headers:
            methods.append(f"headers({len(self.headers)})")
        if self.bearer_token:
            methods.append("bearer_token")
        if self.basic_auth:
            methods.append("basic_auth")
        return f"AuthManager({', '.join(methods)})"


def create_auth_from_prompt() -> AuthManager:
    """Interactive prompt to create auth configuration."""
    auth = AuthManager()

    print("\n[JSentinel Auth Setup]")
    print("-" * 40)

    # Bearer token
    token = input("Bearer Token (press Enter to skip): ").strip()
    if token:
        auth.set_bearer_token(token)

    # Cookies
    cookies = input("Cookie string (e.g., sessionid=abc; csrftoken=xyz): ").strip()
    if cookies:
        auth.set_session_cookie(cookies)

    # Custom headers
    while True:
        header = input("Custom header (Name:Value, press Enter to skip): ").strip()
        if not header:
            break
        if ':' in header:
            name, value = header.split(':', 1)
            auth.set_header(name.strip(), value.strip())

    # Basic auth
    basic = input("Basic Auth (username:password, press Enter to skip): ").strip()
    if basic and ':' in basic:
        user, pwd = basic.split(':', 1)
        auth.set_basic_auth(user, pwd)

    print(f"\nAuth configured: {auth}")
    return auth
