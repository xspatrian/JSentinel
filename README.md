# JSentinel - JavaScript Security Reconnaissance Agent

> AI-powered JavaScript analysis tool for bug bounty hunting.  
> Powered by **Gemini AI** + **180+ validated bug bounty patterns** from real-world reports.

---

## Features

- **AI-Powered Analysis** - Gemini AI enhances regex findings with context, exploitability scoring, and historical references
- **Authentication Support** - Access authenticated JS files via cookies, Bearer tokens, Basic Auth, or custom headers
- **40+ Secret Patterns** - AWS, Stripe, Firebase, JWT, OAuth, Slack, GitHub, MongoDB, and more
- **Endpoint Discovery** - Extract hidden APIs, admin panels, GraphQL endpoints, WebSockets
- **Auth Logic Detection** - Find client-side admin checks, debug flags, JWT flaws, CORS misconfigs
- **Source Map Analysis** - Auto-detect and fetch `.js.map` files for source reconstruction
- **Beautiful HTML Reports** - Interactive charts, severity filters, AI analysis, and exploitation guides
- **JSON Export** - Machine-readable output for CI/CD integration

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Get Gemini API Key (Free)

1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Create an API key
3. Paste it in `config/config.yaml`:

```yaml
gemini:
  api_key: "your-api-key-here"
```

### 3. Create `js.txt`

```
https://target.com/static/main.js
https://target.com/static/app.bundle.js
https://target.com/api/config.js
```

### 4. Run the Scan

```bash
python main.py js.txt
```

### 5. View Report

Open `output/report.html` in your browser.

---

## Authentication

For authenticated JS files, create `auth.json`:

```json
{
  "bearer_token": "eyJhbGciOiJIUzI1NiIs...",
  "cookies": {
    "sessionid": "abc123",
    "csrftoken": "xyz789"
  },
  "headers": {
    "X-Custom-Header": "value"
  },
  "basic_auth": ["username", "password"]
}
```

Then run:
```bash
python main.py js.txt --auth auth.json
```

Or use interactive mode:
```bash
python main.py js.txt --interactive-auth
```

---

## Command Line Options

```
python main.py js.txt [options]

Options:
  --auth FILE          Auth config JSON file
  --config FILE        Config YAML file (default: config/config.yaml)
  --no-ai              Skip Gemini AI analysis (regex only)
  --output DIR         Output directory (default: output)
  --interactive-auth   Interactive authentication setup
  --gemini-key KEY     Override Gemini API key
```

---

## Repo Structure

```
JSentinel/
├── config/
│   └── config.yaml          # API keys, settings
├── core/
│   ├── __init__.py
│   ├── auth.py              # Authentication handler
│   ├── fetcher.py           # JS file downloader
│   ├── analyzer.py          # Regex + AI analysis engine
│   └── reporter.py          # HTML/JSON report generator
├── skills/
│   └── skills.md            # Vulnerability knowledge base
├── utils/
│   ├── __init__.py
│   └── patterns.py          # Regex pattern library
├── output/                  # Generated reports
├── js.txt                   # Input: JS URLs
├── main.py                  # Entry point
├── requirements.txt
└── README.md
```

---

## How It Works

```
js.txt (URLs)
    |
    v
[Fetcher]  --auth-->  Download JS + .map files
    |
    v
[Analyzer] --regex-->  Pattern matching (40+ patterns)
    |          |
    |          v
    |      [Gemini AI] --> Context analysis, exploitability scoring
    |          |
    v          v
[Reporter] --> HTML report with charts + JSON export
```

---

## Pattern Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| **Secrets** | 25+ | AWS keys, Stripe keys, Firebase, JWT secrets, OAuth |
| **Endpoints** | 12+ | fetch(), axios, XHR, GraphQL, WebSocket, admin paths |
| **Auth Logic** | 15+ | Admin checks, debug flags, JWT flaws, CORS, role bypass |
| **GraphQL** | 4+ | Query definitions, client configs, batching detection |

---

## Report Features

The HTML report includes:
- **Severity Dashboard** - P1-P5 stat cards with color coding
- **Interactive Charts** - Severity doughnut, category bar, file distribution, AI confidence
- **Filterable Findings** - Filter by severity (All/P1/P2/P3/P4/P5)
- **AI Analysis** - Gemini-powered context, confidence score, exploitability/impact ratings
- **Exploitation Guides** - Step-by-step reproduction steps
- **Evidence Boxes** - Exact code snippets with line numbers
- **Historical References** - Similar real-world bug bounty cases

---

## Tips for Best Results

1. **Include source maps** - The tool auto-detects `.js.map` references
2. **Use authentication** - Many juicy JS files are behind auth
3. **Beautify minified code** - Enabled by default for better analysis
4. **Check P1 findings first** - These have highest bounty potential
5. **Review AI recommendations** - Gemini provides exploitation guidance

---

## License

MIT License - Use responsibly for authorized bug bounty programs only.

---

> **Remember:** Only test targets you have explicit permission to test. JSentinel is designed for authorized bug bounty hunting and security research.
