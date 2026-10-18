# 🔍 Phishing Email Investigation

A Python-based email triage tool that extracts email headers, identifies potential phishing indicators, analyzes URL-like strings locally, and generates structured JSON investigation reports.

This project demonstrates foundational cybersecurity skills relevant to Security Operations Center (SOC) Analyst roles, including email investigation, indicator extraction, evidence documentation, Python scripting, and automated testing.

> ⚠️ **Safety notice:** This project uses fictional email samples for cybersecurity education. The samples do not represent confirmed real-world phishing incidents.

---

## 📑 Table of Contents

- [Project Overview](#project-overview)
- [Project Objectives](#project-objectives)
- [Technologies Used](#technologies-used)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Example Investigation Findings](#example-investigation-findings)
- [Automated Testing](#automated-testing)
- [Evidence and Reports](#evidence-and-reports)
- [Security and Safe Handling](#security-and-safe-handling)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Skills Demonstrated](#skills-demonstrated)

---

## Project Overview

Phishing emails are a common security threat. Security analysts investigate suspicious messages by examining email headers, reviewing URLs, identifying suspicious patterns, and documenting their findings.

This project implements a basic email triage workflow using Python.

The analyzer processes `.eml` files, extracts relevant email metadata, identifies selected indicators, performs local URL parsing, and generates JSON reports for further investigation.

The tool is designed for **static analysis and preliminary triage**. It does not independently determine whether an email is malicious.

## Project Objectives

- Parse `.eml` files and extract important email headers.
- Identify urgency-related wording in email subjects.
- Extract URL-like strings from email bodies.
- Identify defanged URL notation and extract hostnames locally.
- Compare sender and Reply-To email addresses.
- Collect Return-Path and Received headers when available.
- Generate structured JSON investigation reports.
- Document investigation evidence and limitations.
- Validate core functionality using automated unit tests.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core implementation and email analysis |
| `email` | Parsing email messages and headers |
| `re` | Pattern matching and URL extraction |
| `urllib.parse` | Local URL parsing and hostname extraction |
| `pathlib` | File and directory handling |
| `json` | Generating structured investigation reports |
| `unittest` | Automated testing |
| Git | Version control |
| GitHub | Repository hosting and project documentation |
| GitHub Desktop | Graphical Git workflow |
| Visual Studio Code | Development environment |

The analyzer uses Python's standard library and does not require third-party packages for its core functionality.

---

## Features

### 1. Email Header Extraction

Extracts relevant email metadata when available:

- From
- To
- Subject
- Date
- Reply-To
- Message-ID
- Return-Path
- Received

Missing headers are documented as observations rather than treated as proof of malicious activity.

### 2. Basic Phishing Indicators

The analyzer checks email subjects for selected urgency-related terms, including:

- Urgent
- Verify
- Suspended
- Immediately
- Action required
- Account restriction

These indicators can help prioritize manual review.

**Important:** Urgency-related wording alone does not establish that an email is malicious.

### 3. URL Extraction and Analysis

The analyzer:

- Extracts HTTP and HTTPS URLs, along with supported defanged URL schemes.
- Removes duplicate URL-like strings.
- Identifies defanged URL notation.
- Extracts hostnames using local URL parsing.
- Records URL-related observations in JSON reports.

> 🛡️ **Safety:** Extracted URLs are not opened, and hostname parsing does not initiate network connections.

The tool does not determine whether a URL is live, malicious, or associated with a known threat.

### 4. Sender and Reply-To Comparison

The analyzer compares the parsed sender address with the Reply-To address when both are available.

A mismatch is recorded as an investigative observation.

Legitimate emails can also use different sender and reply addresses, so a mismatch is not definitive proof of phishing.

### 5. Routing Header Collection

The analyzer collects Return-Path and Received headers when present.

These headers can provide useful context during email investigations. However, the script does not independently authenticate header values or validate the message's delivery path.

### 6. Structured JSON Reports

Each analyzed email produces a JSON report containing information such as:

- Email metadata
- Sender and Reply-To analysis
- Collected routing headers
- Extracted URL-like strings
- Local URL analysis
- Investigation observations
- Tool limitations

The reports provide a structured record of the analyzer's findings.

### 7. Automated Unit Tests

The project includes automated tests for core functionality, covering URL extraction, URL analysis, header comparison, and email analysis.

**Current development milestone: 15 unit tests passed.**

---

## Project Structure

```text
Phishing-Email-Investigation/
├── evidence/
│   ├── email_analysis.md
│   ├── header_analysis.md
│   └── simulated_header_findings.md
├── reports/
│   ├── sample_phishing_email_report.json
│   └── sample_test_email_report.json
├── samples/
│   ├── sample_phishing_email.eml
│   ├── sample_test_email.eml
│   └── simulated_email_headers.txt
├── scripts/
│   └── analyze_email.py
├── tests/
│   └── test_analyze_email.py
├── .gitignore
└── README.md