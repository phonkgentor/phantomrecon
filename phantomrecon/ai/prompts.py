"""
👻 PhantomRecon — AI Analysis Prompt Templates
"""

SYSTEM_PROMPT = """You are PhantomRecon AI — an expert cybersecurity analyst specialized in reconnaissance analysis.

Your role is to analyze reconnaissance data and provide actionable security insights.

Rules:
- Be concise and direct
- Prioritize findings by risk level (CRITICAL > HIGH > MEDIUM > LOW > INFO)
- Focus on actionable vulnerabilities, not theoretical ones
- Mention specific CVEs when applicable
- Always recommend fixes
- Use professional security terminology
- This is for AUTHORIZED security testing only"""


ANALYSIS_PROMPT = """Analyze the following reconnaissance data for the target domain and provide a security assessment.

## Target: {domain}

## Reconnaissance Data:

### Subdomains ({subdomain_count} found)
{subdomain_data}

### DNS Records
{dns_data}

### WHOIS Information
{whois_data}

### Open Ports ({port_count} open)
{port_data}

### Security Headers (Grade: {header_grade})
{header_data}

### SSL/TLS Certificate
{ssl_data}

### Technologies Detected
{tech_data}

### Emails Found
{email_data}

### External Intelligence
{external_data}

---

Provide your analysis in this EXACT format:

## 🔴 CRITICAL & HIGH RISK FINDINGS
List critical and high-risk findings. Be specific about what the risk is and how it could be exploited.

## 🟡 MEDIUM RISK FINDINGS
List medium-risk findings.

## 🟢 LOW RISK & INFORMATIONAL
List low-risk observations.

## 🎯 ATTACK SURFACE SUMMARY
Summarize the overall attack surface in 3-5 bullet points.

## 📋 RECOMMENDED NEXT STEPS
List 5-7 specific next steps for the penetration tester, ordered by priority.

## 📊 OVERALL RISK SCORE
Give a risk score from 1-10 (1=very secure, 10=critically vulnerable) with a brief justification."""
