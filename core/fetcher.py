"""
JSentinel Fetcher Module
Downloads JavaScript files with authentication support and preprocessing.
"""

import os
import time
import hashlib
import requests
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm
import jsbeautifier

from core.auth import AuthManager


class JSFetcher:
    """Fetches and preprocesses JavaScript files."""

    def __init__(self, auth_manager: Optional[AuthManager] = None, 
                 timeout: int = 30, max_retries: int = 3,
                 delay: float = 0.5, verify_ssl: bool = False,
                 user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"):
        self.auth = auth_manager or AuthManager()
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent})

    def fetch(self, url: str) -> Tuple[bool, str, Dict]:
        """
        Fetch a single JS file.

        Returns:
            (success: bool, content: str, metadata: dict)
        """
        metadata = {
            'url': url,
            'status_code': None,
            'content_length': 0,
            'content_type': None,
            'source_map_url': None,
            'error': None,
            'authenticated': self.auth.is_configured(),
        }

        kwargs = self.auth.get_request_kwargs()
        kwargs['timeout'] = self.timeout
        kwargs['verify'] = self.verify_ssl

        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, **kwargs)
                metadata['status_code'] = response.status_code

                if response.status_code == 200:
                    content = response.text
                    metadata['content_length'] = len(content)
                    metadata['content_type'] = response.headers.get('Content-Type', '')

                    # Extract source map URL
                    if '//# sourceMappingURL=' in content:
                        sm_url = self._extract_source_map_url(content, url)
                        metadata['source_map_url'] = sm_url

                    return True, content, metadata

                elif response.status_code in (401, 403):
                    metadata['error'] = f"Auth required ({response.status_code})"
                    if not self.auth.is_configured():
                        return False, "", metadata
                    # Retry with auth if not already using it

                elif response.status_code == 404:
                    metadata['error'] = "Not found (404)"
                    return False, "", metadata

                else:
                    metadata['error'] = f"HTTP {response.status_code}"

            except requests.exceptions.Timeout:
                metadata['error'] = f"Timeout (attempt {attempt + 1})"
            except requests.exceptions.ConnectionError:
                metadata['error'] = f"Connection error (attempt {attempt + 1})"
            except Exception as e:
                metadata['error'] = str(e)

            if attempt < self.max_retries - 1:
                time.sleep(self.delay * (attempt + 1))

        return False, "", metadata

    def fetch_source_map(self, source_map_url: str) -> Tuple[bool, str]:
        """Fetch source map file."""
        kwargs = self.auth.get_request_kwargs()
        kwargs['timeout'] = self.timeout
        kwargs['verify'] = self.verify_ssl

        try:
            response = self.session.get(source_map_url, **kwargs)
            if response.status_code == 200:
                return True, response.text
        except Exception as e:
            pass
        return False, ""

    def fetch_all(self, urls: List[str], output_dir: str = "output/js_cache") -> List[Dict]:
        """
        Fetch all JS files from URL list.

        Returns list of dicts with url, content, metadata.
        """
        os.makedirs(output_dir, exist_ok=True)
        results = []

        print(f"\n[+] Fetching {len(urls)} JavaScript files...")
        if self.auth.is_configured():
            print(f"    Auth: {self.auth}")

        for url in tqdm(urls, desc="Downloading JS"):
            success, content, metadata = self.fetch(url)

            if success:
                # Save to cache
                filename = self._url_to_filename(url)
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                metadata['cache_path'] = filepath

                # Try to fetch source map
                if metadata.get('source_map_url'):
                    sm_success, sm_content = self.fetch_source_map(metadata['source_map_url'])
                    if sm_success:
                        sm_path = filepath + ".map"
                        with open(sm_path, 'w', encoding='utf-8') as f:
                            f.write(sm_content)
                        metadata['source_map_cache'] = sm_path

            results.append({
                'url': url,
                'success': success,
                'content': content if success else "",
                'metadata': metadata
            })

            time.sleep(self.delay)

        successful = sum(1 for r in results if r['success'])
        print(f"\n[+] Fetched {successful}/{len(urls)} files successfully")

        return results

    def beautify(self, js_code: str) -> str:
        """Beautify minified JavaScript."""
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.max_preserve_newlines = 2
            return jsbeautifier.beautify(js_code, opts)
        except Exception:
            return js_code

    def _extract_source_map_url(self, content: str, base_url: str) -> Optional[str]:
        """Extract source map URL from JS content."""
        for line in content.split('\n'):
            if '//# sourceMappingURL=' in line:
                sm_url = line.split('//# sourceMappingURL=')[-1].strip()
                if sm_url.startswith('http'):
                    return sm_url
                else:
                    # Relative URL
                    base = '/'.join(base_url.split('/')[:-1])
                    return f"{base}/{sm_url}"
        return None

    def _url_to_filename(self, url: str) -> str:
        """Convert URL to safe filename."""
        parsed = urlparse(url)
        safe = parsed.path.replace('/', '_').replace('\\', '_')
        if not safe:
            safe = 'index'
        hash_suffix = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"{safe}_{hash_suffix}.js"
