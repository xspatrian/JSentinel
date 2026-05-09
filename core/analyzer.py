"""
JSentinel Analyzer Module
Regex-based detection + Gemini AI-powered analysis and classification.
"""

import re
import json
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

import google.generativeai as genai

from utils.patterns import get_all_patterns


@dataclass
class Finding:
    """Represents a single security finding."""
    id: str
    file_url: str
    pattern_name: str
    category: str
    severity: str
    description: str
    evidence: str
    line_number: int
    ai_analysis: str = ""
    ai_confidence: float = 0.0
    ai_recommendation: str = ""
    historical_reference: str = ""
    exploitability: int = 0
    impact: int = 0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return asdict(self)


class JSAnalyzer:
    """Analyzes JavaScript files for security vulnerabilities."""

    SEVERITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}

    def __init__(self, gemini_api_key: Optional[str] = None, 
                 model: str = "gemini-2.5-flash",
                 max_tokens: int = 8192,
                 temperature: float = 0.2):
        self.gemini_api_key = gemini_api_key
        self.model_name = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.gemini_model = None

        if gemini_api_key:
            self._init_gemini()

        self.patterns = get_all_patterns()
        self.findings: List[Finding] = []

    def _init_gemini(self):
        """Initialize Gemini AI model."""
        try:
            genai.configure(api_key=self.gemini_api_key)
            self.gemini_model = genai.GenerativeModel(self.model_name)
            print(f"[+] Gemini AI initialized ({self.model_name})")
        except Exception as e:
            print(f"[!] Failed to initialize Gemini: {e}")
            self.gemini_model = None

    def analyze_file(self, url: str, content: str, beautify: bool = True) -> List[Finding]:
        """
        Analyze a single JS file for vulnerabilities.

        Args:
            url: Source URL of the JS file
            content: JS file content
            beautify: Whether content is already beautified

        Returns:
            List of Finding objects
        """
        file_findings = []
        lines = content.split('\n')

        # Phase 1: Regex-based detection
        for pattern in self.patterns:
            matches = self._find_pattern_matches(pattern, content, lines, url)
            file_findings.extend(matches)

        # Phase 2: AI-powered analysis (if Gemini is available)
        if self.gemini_model and file_findings:
            file_findings = self._ai_enhance_findings(file_findings, content, url)

        self.findings.extend(file_findings)
        return file_findings

    def _find_pattern_matches(self, pattern: Dict, content: str, 
                              lines: List[str], url: str) -> List[Finding]:
        """Find all matches for a single pattern."""
        matches = []
        regex = re.compile(pattern['pattern'], re.IGNORECASE)

        for line_num, line in enumerate(lines, 1):
            for match in regex.finditer(line):
                evidence = match.group(0)
                # Truncate long evidence
                if len(evidence) > 300:
                    evidence = evidence[:150] + " ... " + evidence[-150:]

                finding = Finding(
                    id=f"{pattern['name']}_{line_num}_{hash(evidence) % 10000:04d}",
                    file_url=url,
                    pattern_name=pattern['name'],
                    category=pattern.get('category', 'Unknown'),
                    severity=pattern.get('severity', 'P3'),
                    description=pattern.get('description', 'Pattern match'),
                    evidence=evidence,
                    line_number=line_num,
                )
                matches.append(finding)

        return matches

    def _ai_enhance_findings(self, findings: List[Finding], 
                             content: str, url: str) -> List[Finding]:
        """Use Gemini AI to enhance findings with context and recommendations."""

        # Group findings by severity for batch analysis
        p1_findings = [f for f in findings if f.severity == 'P1']
        p2_findings = [f for f in findings if f.severity == 'P2']
        other_findings = [f for f in findings if f.severity not in ('P1', 'P2')]

        # Prioritize P1/P2 for AI analysis
        priority_findings = p1_findings[:10] + p2_findings[:10]

        for finding in priority_findings:
            try:
                ai_result = self._analyze_with_gemini(finding, content, url)
                finding.ai_analysis = ai_result.get('analysis', '')
                finding.ai_confidence = ai_result.get('confidence', 0.0)
                finding.ai_recommendation = ai_result.get('recommendation', '')
                finding.exploitability = ai_result.get('exploitability', 0)
                finding.impact = ai_result.get('impact', 0)
                finding.historical_reference = ai_result.get('historical_reference', '')
            except Exception as e:
                finding.ai_analysis = f"AI analysis failed: {str(e)}"

        return findings

    def _analyze_with_gemini(self, finding: Finding, content: str, 
                             url: str) -> Dict[str, Any]:
        """Send finding to Gemini for intelligent analysis."""

        prompt = f"""You are JSentinel, an expert JavaScript security analyst specializing in bug bounty hunting.

Analyze this security finding from a JavaScript file and provide:
1. Detailed analysis of the vulnerability
2. Confidence score (0.0-1.0)
3. Exploitability rating (1-10)
4. Impact rating (1-10)
5. Step-by-step exploitation recommendation
6. Historical bug bounty reference (similar real-world finding)

FINDING DETAILS:
- File: {url}
- Pattern: {finding.pattern_name}
- Category: {finding.category}
- Severity: {finding.severity}
- Description: {finding.description}
- Evidence: {finding.evidence}
- Line: {finding.line_number}

CONTEXT (surrounding code):
```javascript
{self._get_context(content, finding.line_number)}
```

Respond in JSON format:
{{
  "analysis": "detailed explanation",
  "confidence": 0.85,
  "exploitability": 8,
  "impact": 9,
  "recommendation": "step-by-step exploitation guide",
  "historical_reference": "similar real bug bounty case"
}}
"""

        response = self.gemini_model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
            )
        )

        # Parse JSON from response
        try:
            text = response.text
            # Extract JSON if wrapped in markdown
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0]
            elif '```' in text:
                text = text.split('```')[1].split('```')[0]

            result = json.loads(text.strip())
            return result
        except Exception:
            # Fallback if JSON parsing fails
            return {
                "analysis": response.text[:500],
                "confidence": 0.5,
                "exploitability": 5,
                "impact": 5,
                "recommendation": "Manual review recommended",
                "historical_reference": "Unknown"
            }

    def _get_context(self, content: str, line_number: int, 
                     context_lines: int = 5) -> str:
        """Get surrounding lines for context."""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary statistics."""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_category": {}}

        by_severity = {}
        by_category = {}

        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1

        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "p1_count": by_severity.get('P1', 0),
            "p2_count": by_severity.get('P2', 0),
            "p3_count": by_severity.get('P3', 0),
            "files_analyzed": len(set(f.file_url for f in self.findings)),
        }

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def export_json(self, filepath: str):
        """Export all findings to JSON."""
        data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "model": self.model_name,
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def clear(self):
        """Clear all findings."""
        self.findings = []
