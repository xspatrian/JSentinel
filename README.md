# JSentinel
AI‑Powered Client‑Side Attack Surface Intelligence Agent for detecting sensitive endpoints and exposed secrets from publicly accessible JavaScript.

## 🚀 Overview

Modern single‑page applications (SPAs) expose significant application logic and API structures through client‑side JavaScript bundles. Traditional tooling is capable of extracting syntactic information such as URLs or secrets, but lacks the contextual understanding required to differentiate between benign application functionality and sensitive privileged operations.

JSentinel addresses this by combining static JavaScript analysis with LLM‑based contextual inference to transform publicly accessible frontend code into actionable security intelligence.

---

## 🧠 Key Capabilities

- Subdomain Attack Surface Discovery
- Automated JavaScript Asset Collection
- Endpoint Extraction
- Secret Candidate Detection
- Parameter Identification
- Business Logic Mapping
- Client‑Side Authorization Logic Detection
- AI‑Based Security Context Inference
- Endpoint Risk Classification
- Exposure Validation
- Automated Bug Bounty Report Generation

---

## 📐 High‑Level Workflow

```
Target Scope
    ↓
Subdomain Discovery
    ↓
Web Crawler (JS Discovery)
    ↓
JS Collection
    ↓
JS Parsing Engine
    ↓
Structured Intelligence Output
    ↓
AI Decision Engine
    ↓
Risk Analysis
    ↓
Endpoint Validation
    ↓
Finding Correlation
    ↓
Bug Bounty Report
```

---

## 🤖 AI‑Decision Engine

JSentinel integrates a **provider‑agnostic LLM inference layer** to perform contextual security analysis on extracted JavaScript intelligence.

Currently Supported:
- ✅ Google Gemini API

Planned Support:
- 🔜 OpenAI
- 🔜 Anthropic Claude
- 🔜 Local LLMs (Ollama / Llama)

The AI engine performs:
- Sensitive endpoint detection
- Admin API identification
- Internal service discovery
- Business logic exposure inference
- Secret risk classification
- Authorization logic assessment

---

## 🗂️ Project Architecture

```
Recon Engine → Intelligence Extraction → AI Inference → Risk Scoring → Validation → Reporting

```

---

## 🧱 Folder Structure

```
jsentinel/
│
├── crawler/
├── js_collector/
├── parser/
├── intelligence/
├── ai_engine/
│   ├── base_provider.py
│   ├── gemini_provider.py
│   ├── openai_provider.py   (future)
│   ├── claude_provider.py   (future)
│   └── provider_factory.py
│
├── validator/
├── correlator/
├── reporting/
├── config/
└── main.py
```

---

## ⚙️ Setup

### Install Dependencies

```
pip install -r requirements.txt
```

---

### Gemini API Configuration

Create a config file:

```
config/config.yaml
```

```
ai_provider: gemini
api_key: YOUR_GEMINI_API_KEY
```

---

## ▶️ Usage

```
python main.py --target example.com
```

JSentinel will:

1. Discover subdomains
2. Crawl web assets
3. Collect JavaScript files
4. Extract endpoints and secrets
5. Send intelligence to AI engine
6. Perform risk inference
7. Validate exposures
8. Generate a structured report

---

## 📝 Sample Finding

```
Sensitive Admin Endpoint Exposure
---------------------------------
Endpoint: /v1/admin/export
Source: static/js/admin.bundle.js
Risk: HIGH
Reason: Privileged export functionality exposed in client‑side bundle.
```

---

## 🛣️ Roadmap

- [ ] Multiprovider AI Integration
- [ ] GraphQL Schema Detection
- [ ] Runtime JS Behavior Analysis
- [ ] Mobile SDK Analysis
- [ ] Local LLM Support
- [ ] SaaS Dashboard


---

## 🤝 Contribution

Contributions are welcome. Please open an issue or submit a pull request.

---

## ⚠️ Disclaimer

JSentinel is intended for security research and authorized testing only. Users are responsible for complying with applicable laws and target bug bounty program policies.
