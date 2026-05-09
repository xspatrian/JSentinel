#!/usr/bin/env python3
"""
JSentinel - JavaScript Security Reconnaissance Agent
=====================================================
AI-powered JS analysis tool for bug bounty hunting.

Usage:
    python main.py js.txt [--auth auth.json] [--config config.yaml]

Arguments:
    js.txt          File containing JS URLs (one per line)
    --auth          Optional auth config JSON file
    --config        Optional YAML config file
    --no-ai         Skip Gemini AI analysis (regex only)
    --output        Output directory (default: output)
"""

import argparse
import os
import sys
import yaml
from datetime import datetime

from colorama import init, Fore, Style

from core.auth import AuthManager, create_auth_from_prompt
from core.fetcher import JSFetcher
from core.analyzer import JSAnalyzer
from core.reporter import HTMLReporter, JSONReporter

init(autoreset=True)


def load_config(config_path):
    """Load configuration from YAML file."""
    if not os.path.exists(config_path):
        print(f"{Fore.YELLOW}[!] Config file not found: {config_path}, using defaults{Style.RESET_ALL}")
        return {}
    with open(config_path, 'r') as f:
        return yaml.safe_load(f) or {}


def load_js_urls(js_file):
    """Load JS URLs from file, ignoring comments and empty lines."""
    urls = []
    with open(js_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


def print_banner():
    """Print JSentinel banner."""
    print()
    print(Fore.CYAN + "    ================================================")
    print(Fore.CYAN + "     JSentinel - JavaScript Security Reconnaissance")
    print(Fore.CYAN + "    ================================================")
    print()
    print(Fore.YELLOW + "    AI-Powered Bug Bounty Intelligence Agent")
    print(Fore.GREEN + "    Powered by Gemini AI + 180+ Validated Patterns")
    print()
    print(Fore.CYAN + "    ___________     _____       _       _ _")
def main():
    parser = argparse.ArgumentParser(
        description='JSentinel - JavaScript Security Reconnaissance Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py js.txt
  python main.py js.txt --auth auth.json --config config.yaml
  python main.py js.txt --no-ai --output ./reports
  python main.py js.txt --interactive-auth
        """
    )

    parser.add_argument('js_file', help='File containing JS URLs (one per line)')
    parser.add_argument('--auth', help='Auth config JSON file')
    parser.add_argument('--config', default='config/config.yaml', help='Config YAML file')
    parser.add_argument('--no-ai', action='store_true', help='Skip Gemini AI analysis')
    parser.add_argument('--output', default='output', help='Output directory')
    parser.add_argument('--interactive-auth', action='store_true', help='Interactive auth setup')
    parser.add_argument('--gemini-key', help='Gemini API key (overrides config)')

    args = parser.parse_args()

    print_banner()

    # Load configuration
    print(f"{Fore.BLUE}[*] Loading configuration...{Style.RESET_ALL}")
    config = load_config(args.config)

    # Setup auth
    auth_manager = AuthManager()
    if args.interactive_auth:
        auth_manager = create_auth_from_prompt()
    elif args.auth:
        auth_manager.load_from_file(args.auth)
        print(f"{Fore.GREEN}[+] Auth loaded from {args.auth}{Style.RESET_ALL}")

    # Load JS URLs
    if not os.path.exists(args.js_file):
        print(f"{Fore.RED}[!] File not found: {args.js_file}{Style.RESET_ALL}")
        sys.exit(1)

    urls = load_js_urls(args.js_file)
    print(f"{Fore.GREEN}[+] Loaded {len(urls)} JS URLs from {args.js_file}{Style.RESET_ALL}")

    if not urls:
        print(f"{Fore.RED}[!] No URLs found in file{Style.RESET_ALL}")
        sys.exit(1)

    # Setup fetcher
    fetch_config = config.get('fetching', {})
    fetcher = JSFetcher(
        auth_manager=auth_manager,
        timeout=fetch_config.get('timeout', 30),
        max_retries=fetch_config.get('max_retries', 3),
        delay=fetch_config.get('delay_between_requests', 0.5),
        verify_ssl=fetch_config.get('verify_ssl', False),
        user_agent=fetch_config.get('user_agent', 'Mozilla/5.0')
    )

    # Fetch JS files
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[PHASE 1] Fetching JavaScript Files{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    fetched = fetcher.fetch_all(urls, output_dir=os.path.join(args.output, 'js_cache'))
    successful = [f for f in fetched if f['success']]

    if not successful:
        print(f"{Fore.RED}[!] No JS files could be fetched. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    # Setup analyzer
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[PHASE 2] Analyzing JavaScript Files{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    gemini_config = config.get('gemini', {})
    api_key = args.gemini_key or gemini_config.get('api_key')

    if args.no_ai or not api_key or api_key == 'YOUR_GEMINI_API_KEY_HERE':
        print(f"{Fore.YELLOW}[!] Running in regex-only mode (no AI){Style.RESET_ALL}")
        api_key = None
    else:
        print(f"{Fore.GREEN}[+] Gemini AI enabled ({gemini_config.get('model', 'gemini-2.5-flash')}){Style.RESET_ALL}")

    analyzer = JSAnalyzer(
        gemini_api_key=api_key,
        model=gemini_config.get('model', 'gemini-2.5-flash'),
        max_tokens=gemini_config.get('max_tokens', 8192),
        temperature=gemini_config.get('temperature', 0.2)
    )

    # Analyze each file
    for item in successful:
        content = item['content']
        url = item['url']

        # Beautify if minified
        if len(content) > 0 and ('.min.' in url or len(content.split('\n')) < 5):
            print(f"{Fore.BLUE}    Beautifying {url}{Style.RESET_ALL}")
            content = fetcher.beautify(content)

        print(f"{Fore.BLUE}    Analyzing {url}{Style.RESET_ALL}")
        findings = analyzer.analyze_file(url, content)
        print(f"    Found {len(findings)} patterns")

    # Summary
    summary = analyzer.get_summary()
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[PHASE 3] Analysis Complete{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total Findings: {summary['total']}{Style.RESET_ALL}")
    print(f"  P1 (Critical): {summary.get('p1_count', 0)}")
    print(f"  P2 (High):     {summary.get('p2_count', 0)}")
    print(f"  P3 (Medium):   {summary.get('p3_count', 0)}")
    print(f"  P4 (Low):      {summary.get('p4_count', 0)}")
    print(f"  P5 (Info):     {summary.get('p5_count', 0)}")

    if summary['by_category']:
        print(f"\n{Fore.CYAN}Top Categories:{Style.RESET_ALL}")
        for cat, count in sorted(summary['by_category'].items(), key=lambda x: -x[1])[:5]:
            print(f"  {cat}: {count}")

    # Generate reports
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[PHASE 4] Generating Reports{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    scan_metadata = {
        'files_analyzed': len(successful),
        'total_urls': len(urls),
        'successful_fetches': len(successful),
        'failed_fetches': len(fetched) - len(successful),
        'timestamp': datetime.now().isoformat(),
        'gemini_enabled': api_key is not None,
    }

    # HTML Report
    html_reporter = HTMLReporter()
    html_path = html_reporter.generate(
        analyzer.findings,
        output_path=os.path.join(args.output, 'report.html'),
        scan_metadata=scan_metadata
    )

    # JSON Report
    json_reporter = JSONReporter()
    json_path = json_reporter.generate(
        analyzer.findings,
        output_path=os.path.join(args.output, 'report.json'),
        scan_metadata=scan_metadata
    )

    # Export raw findings
    analyzer.export_json(os.path.join(args.output, 'findings_raw.json'))

    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}JSentinel scan complete!{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"HTML Report:  {html_path}")
    print(f"JSON Report:  {json_path}")
    print(f"Raw Findings: {os.path.join(args.output, 'findings_raw.json')}")
    print(f"JS Cache:     {os.path.join(args.output, 'js_cache')}")
    print(f"\n{Fore.YELLOW}Open {html_path} in your browser to view the full report.{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
