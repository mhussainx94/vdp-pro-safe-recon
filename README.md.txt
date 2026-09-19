# VDP-PRO Safe Recon Pipeline

**A passive reconnaissance and web asset discovery pipeline for authorized security testing, vulnerability disclosure programs, and local security labs.**

![Bash](https://img.shields.io/badge/Bash-4.x%2B-121011?logo=gnu-bash\&logoColor=white)
![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux\&logoColor=black)
![Security](https://img.shields.io/badge/Focus-Reconnaissance-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

**VDP-PRO Safe Recon Pipeline** is a Bash-based reconnaissance framework that organizes common passive security reconnaissance tasks into a repeatable workflow.

The project is designed for:

* Authorized Vulnerability Disclosure Programs (VDPs)
* Bug bounty reconnaissance within defined scope
* Local cybersecurity laboratories
* Security research environments
* Authorized web application assessments
* Learning and demonstrating reconnaissance methodology

The pipeline supports two primary modes:

```text
URL / LAB MODE
     │
     └── Local or authorized web application
             │
             ├── HTTP discovery
             ├── Fingerprinting
             ├── JavaScript discovery
             ├── Header inventory
             └── Reporting


DOMAIN / VDP MODE
     │
     └── Authorized domain
             │
             ├── Passive subdomain discovery
             ├── Certificate Transparency
             ├── DNS resolution
             ├── HTTP discovery
             ├── Historical URLs
             ├── Parameter discovery
             ├── JavaScript analysis
             ├── Passive candidate identification
             └── Reporting
```

The project intentionally keeps intrusive operations disabled in the safe reconnaissance workflow.

---

## ⚠️ Authorization & Legal Notice

**Use this project only against systems you own or systems for which you have explicit authorization to perform security testing.**

Do not use this tool to scan:

* Random public websites
* Third-party infrastructure without permission
* University infrastructure without authorization
* Client infrastructure without authorization
* VDP assets outside their published scope
* Systems where automated reconnaissance is prohibited

The author is not responsible for unauthorized or illegal use of this software.

Always read and follow the target organization's security testing policy before running reconnaissance.

---

# Features

### Passive Asset Discovery

* Passive subdomain enumeration
* Certificate Transparency discovery through `crt.sh`
* Scope filtering
* DNS resolution
* CNAME discovery

### HTTP Reconnaissance

* HTTP/HTTPS liveness detection
* Status-code detection
* Content-length detection
* Content-type detection
* Redirect detection
* HTTP method identification
* Web-server fingerprinting
* Technology detection
* IP identification
* Page-title extraction

### Historical Reconnaissance

* Historical URL collection
* URL parameter extraction
* High-value parameter identification
* Passive URL analysis

### JavaScript Reconnaissance

* JavaScript URL discovery
* JavaScript extraction from HTTP responses
* API-path discovery
* Potential secret pattern analysis
* Firebase URL identification
* Internal-path identification

### Passive Security Analysis

* CORS wildcard observation
* CORS credential observation
* Security-header inventory
* Passive takeover candidate identification
* Cloud-storage candidate generation

### Reporting

* Timestamped output directories
* Structured result files
* Pipeline logs
* Technology summaries
* Final reconnaissance report

---

# Safety Design

VDP-PRO is intentionally designed around a **safe reconnaissance model**.

The following operations are disabled:

```text
Active vulnerability scanning       DISABLED
Active port scanning                DISABLED
Active cloud bucket probing         DISABLED
Automatic .git probing              DISABLED
Automatic .env probing              DISABLED
```

The script explicitly records these disabled capabilities in its output and report.

This means the project should be considered a **reconnaissance and discovery pipeline**, not a full vulnerability scanner.

---

# Operating Modes

## 1. URL / Lab Mode

URL mode is intended for local applications, virtual machines, and specifically authorized web targets.

Example:

```bash
./recon.sh --url http://TARGET/dvwa/
```

Example local laboratory:

```bash
./recon.sh --url http://192.168.x.x/dvwa/
```

URL mode bypasses the public-domain reconnaissance workflow and focuses on direct HTTP reconnaissance.

---

## 2. Domain / VDP Mode

Domain mode is intended for domains that are explicitly authorized for reconnaissance.

Example:

```bash
./recon.sh --domain example.com
```

Multiple domains can be supplied:

```bash
./recon.sh --domain example.com --domain example.org
```

---

## 3. Scope File

An optional scope file can be provided for authorized assessments:

```bash
./recon.sh --domain example.com --scope config/scope.example.txt
```

Example:

```text
example.com
www.example.com
api.example.com
```

Only use scope information that you are authorized to test.

---

# Reconnaissance Workflow

The pipeline is organized into stages:

```text
                    ┌──────────────────┐
                    │ Target Selection │
                    └────────┬─────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
        URL / LAB MODE                DOMAIN / VDP MODE
              │                             │
              │                    Passive Subdomains
              │                             │
              │                       Certificate
              │                       Transparency
              │                             │
              │                        DNS Resolution
              │                             │
              └──────────────┬──────────────┘
                             │
                       HTTP Discovery
                             │
                       Fingerprinting
                             │
                 ┌───────────┴───────────┐
                 │                       │
          Historical URLs           JavaScript
                 │                       │
          Parameters                API Paths
                 │                       │
                 └───────────┬───────────┘
                             │
                    Passive Analysis
                             │
                    Header Inventory
                             │
                       Reporting
```

Detailed methodology is available in:

`docs/methodology.md`

---

# Pipeline Stages

| Stage | Function                                  |
| ----- | ----------------------------------------- |
| 1     | Passive subdomain enumeration             |
| 2     | DNS resolution and CNAME discovery        |
| 3     | HTTP liveness and fingerprinting          |
| 4     | Historical URL discovery                  |
| 5     | Parameter extraction                      |
| 6     | JavaScript analysis                       |
| 7     | Passive takeover candidate identification |
| 8     | Technology summary                        |
| 9     | Security-header inventory                 |
| 10    | Port inventory — disabled                 |
| 11    | Cloud-storage candidate generation        |
| 12    | Active vulnerability scanning — disabled  |
| 13    | Optional screenshots                      |
| 14    | Exposure checks — disabled                |
| 15    | Automated report generation               |

The current implementation contains explicit sections for these stages and separates output into dedicated directories.

---

# Requirements

## Core

The primary tools used by the pipeline include:

* Bash
* curl
* jq
* dig
* ProjectDiscovery HTTPX

## Optional

Depending on the operating mode:

* subfinder
* amass
* dnsx
* puredns
* gau
* gowitness

The script checks tool availability before using optional components.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/vdp-pro-safe-recon.git
```

Enter the project:

```bash
cd vdp-pro-safe-recon
```

Make the script executable:

```bash
chmod +x recon.sh
```

Verify the script:

```bash
bash -n recon.sh
```

Display help:

```bash
./recon.sh --help
```

---

# Usage

## Local DVWA Laboratory

```bash
./recon.sh --url http://TARGET_IP/dvwa/
```

Example:

```bash
./recon.sh --url http://192.168.21.136/dvwa/
```

Only run this against your own or explicitly authorized laboratory environment.

---

## Authorized Domain

```bash
./recon.sh --domain example.com
```

---

## Authorized Domain + Scope

```bash
./recon.sh \
    --domain example.com \
    --scope config/scope.example.txt
```

---

## Custom Output Directory

```bash
./recon.sh \
    --url http://TARGET/dvwa/ \
    --outdir results
```

---

## Configuration Options

```text
--url URL
    Authorized local/lab HTTP target.

--domain DOMAIN
    Authorized domain/VDP target.

--scope FILE
    Optional authorized scope file.

--outdir DIR
    Custom output directory.

--threads N
    HTTP/screenshot thread setting.

--rate N
    Rate-limit configuration.

-h, --help
    Display help.
```

---

# Output Structure

Each execution creates a timestamped directory:

```text
vdp_pro_url_YYYYMMDD_HHMMSS/
│
├── subenum/
│   ├── all_subs.txt
│   ├── resolved_subs.txt
│   └── cname_records.txt
│
├── live/
│   ├── live_hosts_full.txt
│   ├── live_urls.txt
│   └── technology_summary.txt
│
├── historical/
│   ├── all_urls.txt
│   ├── params.txt
│   └── high_value_params.txt
│
├── js/
│   ├── all_js.txt
│   ├── api_paths.txt
│   ├── secrets_raw.txt
│   └── internal_paths.txt
│
├── vulns/
│   ├── missing_headers.txt
│   ├── cors_wildcard.txt
│   ├── cors_creds.txt
│   └── takeover_candidates.txt
│
├── ports/
│
├── screenshots/
│
├── cloud/
│
├── reports/
│   └── summary.txt
│
└── pipeline.log
```

The script creates dedicated output directories for subdomain enumeration, live hosts, historical data, JavaScript, vulnerabilities, ports, screenshots, reports, and cloud analysis.

---

# Example Report

A typical report contains:

```text
VDP-PRO SAFE RECONNAISSANCE REPORT
========================================

Mode: url
Target: LOCAL-DVWA-TARGET

--- SUBDOMAIN ENUMERATION ---
Total subdomains:    0
Resolved hosts:      0
Live HTTP hosts:     1

--- HISTORICAL DISCOVERY ---
Historical URLs:     0
Parameters:          0

--- JAVASCRIPT ---
JS files:            1
API paths:           0
Potential secrets:   0

--- PASSIVE CANDIDATES ---
Takeover candidates: 0
Cloud candidates:    0

--- SECURITY HEADERS ---
CORS wildcard:       0
CORS credentials:    0

--- TECHNOLOGY ---
Apache
PHP

========================================
Active vulnerability scanning: DISABLED
Active port scanning:          DISABLED
Active cloud probing:          DISABLED
Active .git/.env probing:      DISABLED
========================================
```

---

# Important Interpretation Notes

A result of `0` does **not** prove that something does not exist.

For example:

```text
Historical URLs: 0
```

means that the configured historical discovery sources did not return URLs.

It does not mean that the target has no historical URLs.

Similarly:

```text
Potential secrets: 0
```

does not prove that an application contains no secrets.

The results represent what the configured reconnaissance methods were able to identify.

---

# Security Header Interpretation

Security-header results should be treated as **observations requiring context**, not automatically as confirmed vulnerabilities.

For example:

```text
Missing HSTS
Missing CSP
Missing X-Content-Type-Options
```

may require additional context before determining security impact.

The project therefore focuses on collecting evidence rather than automatically assigning vulnerability severity.

---

# Project Methodology

The methodology used by VDP-PRO is based on the following principles:

1. Define authorized scope.
2. Select the appropriate operating mode.
3. Perform passive asset discovery where applicable.
4. Resolve discovered infrastructure.
5. Identify live HTTP services.
6. Fingerprint technologies and responses.
7. Collect historical information where available.
8. Extract parameters and JavaScript resources.
9. Perform passive security observations.
10. Generate structured evidence.
11. Produce a reproducible report.
12. Keep intrusive operations disabled by default.

See:

`docs/methodology.md`

for the complete methodology.

---

# Limitations

VDP-PRO is not intended to replace a professional vulnerability scanner or manual security assessment.

Current limitations include:

* Passive discovery can miss assets.
* Historical sources may contain incomplete information.
* Local/private targets generally have no useful public historical data.
* Technology fingerprinting can produce duplicates or false positives.
* Header observations require manual interpretation.
* Passive takeover identification only identifies candidates.
* Cloud candidate generation does not prove bucket existence.
* Active vulnerability scanning is intentionally disabled.

---

# Roadmap

### v1.0

* [x] URL/lab mode
* [x] Domain mode
* [x] Passive subdomain discovery
* [x] DNS resolution
* [x] HTTP fingerprinting
* [x] Historical URL processing
* [x] Parameter extraction
* [x] JavaScript discovery
* [x] Security-header inventory
* [x] Structured reports
* [x] Safety restrictions

### Future

* [ ] Improved dependency validation
* [ ] Cleaner URL-mode execution path
* [ ] Technology normalization
* [ ] JSON report generation
* [ ] Configuration file support
* [ ] Automated test suite
* [ ] Better evidence classification
* [ ] Improved error handling
* [ ] CI testing
* [ ] Expanded passive intelligence sources

---

# Project Structure

```text
vdp-pro-safe-recon/
│
├── recon.sh
├── README.md
├── LICENSE
├── .gitignore
│
├── config/
│   └── scope.example.txt
│
├── docs/
│   └── methodology.md
│
├── examples/
│   └── sample-report.txt
│
└── screenshots/
```

---

# Why This Project?

The project was created to demonstrate how reconnaissance activities can be organized into a repeatable and safety-conscious workflow.

It combines:

* Linux
* Bash scripting
* HTTP reconnaissance
* DNS
* Web technology fingerprinting
* Passive OSINT
* Security automation
* Structured reporting
* Git/GitHub workflow

---

# Author

**Muhammad Hussain**

Cybersecurity / Computer Science Student

Interested in:

* Cybersecurity
* Security Automation
* Reconnaissance
* SOC Operations
* Web Security
* Cloud Security

---

# License

This project is released under the MIT License.

See `LICENSE` for details.
