# VDP-PRO Reconnaissance Methodology

## 1. Purpose

VDP-PRO follows a structured reconnaissance methodology designed to collect information about authorized targets while minimizing unnecessary interaction with target infrastructure.

The methodology is intended for:

* Authorized vulnerability disclosure programs
* Authorized bug bounty programs
* Local security laboratories
* Web application security research
* Security education

The process emphasizes:

* Scope control
* Passive information collection
* Evidence preservation
* Repeatability
* Safe automation
* Clear reporting

---

# 2. Scope Definition

Reconnaissance begins by defining what may be tested.

VDP-PRO supports:

```text
URL Mode
    └── Direct authorized web target

Domain Mode
    └── Authorized domain
         └── Optional scope file
```

The target must be explicitly authorized before execution.

A scope file can be used to restrict discovered assets to approved entries.

---

# 3. Operating Modes

## URL / Laboratory Mode

URL mode is intended for direct web application targets.

Typical examples include:

* DVWA
* OWASP Juice Shop
* WebGoat
* Authorized test servers
* Personal virtual machines

The URL is passed directly into the HTTP reconnaissance workflow.

This avoids performing unnecessary public-domain enumeration against laboratory targets.

---

## Domain / VDP Mode

Domain mode is intended for authorized domain-based assessments.

The workflow can include:

```text
Domain
   ↓
Subdomain discovery
   ↓
Certificate Transparency
   ↓
DNS resolution
   ↓
HTTP discovery
```

The resulting assets are then processed by later reconnaissance stages.

---

# 4. Passive Subdomain Discovery

The domain workflow can use passive sources and tools such as:

* subfinder
* Amass passive enumeration
* Certificate Transparency through crt.sh

The objective is to identify possible subdomains without actively probing large numbers of unknown hosts.

Discovered results are:

1. collected
2. normalized
3. deduplicated
4. filtered
5. placed into the appropriate scope workflow

The script implements separate outputs for raw, filtered, and in-scope subdomain information.

---

# 5. DNS Resolution

Discovered subdomains are resolved to identify hosts that currently return DNS records.

The pipeline can use:

* puredns
* dnsx
* configured resolvers

The result is stored separately from the original discovery data.

This distinction is important because:

```text
Discovered asset
        ≠
Currently resolved asset
```

An asset discovered through passive intelligence may no longer resolve.

---

# 6. CNAME Analysis

CNAME records are collected for discovered domains.

The purpose is to identify external service relationships that may require additional manual review.

VDP-PRO does not automatically claim a takeover vulnerability.

Instead, it produces **passive takeover candidates** based on observed CNAME patterns.

This distinction is important:

```text
CNAME candidate
       ↓
Manual verification required
       ↓
Confirmed issue only after validation
```

The current implementation explicitly describes this stage as passive candidate identification.

---

# 7. HTTP Discovery

After candidate assets have been identified, the pipeline determines which targets respond over HTTP or HTTPS.

The HTTP fingerprinting stage collects information such as:

* HTTP status code
* Content length
* Content type
* Redirect location
* Page title
* HTTP method
* Web server
* Detected technologies
* IP address

ProjectDiscovery HTTPX is used where available.

The URL mode directly seeds the HTTP workflow with the supplied target.

---

# 8. Redirect Analysis

Redirects are recorded because the original URL and final destination may provide different information.

For example:

```text
http://target/app/
        ↓
302
        ↓
/login.php
        ↓
200
```

The final destination may reveal:

* authentication pages
* application paths
* HTTPS enforcement
* canonical URLs
* application structure

Redirect information is therefore retained as reconnaissance evidence.

---

# 9. Historical URL Discovery

Historical URL discovery attempts to identify previously observed URLs associated with authorized domains.

The purpose is to discover application paths that may not be visible from the current homepage.

Potential sources include:

* historical URL datasets
* passive intelligence sources

Historical data is treated as intelligence rather than proof of current availability.

A historical URL may represent:

```text
Current endpoint
Old endpoint
Removed endpoint
Redirected endpoint
Archived endpoint
```

Therefore, historical results should be validated before drawing conclusions.

---

# 10. Parameter Extraction

Parameters are extracted from discovered URLs.

Examples include:

```text
?id=
?page=
?file=
?redirect=
?url=
?path=
?download=
```

The pipeline additionally identifies parameters that may deserve manual security review.

The purpose is **prioritization**, not exploitation.

A parameter such as:

```text
?id=
```

does not prove SQL injection.

A parameter such as:

```text
?file=
```

does not prove local file inclusion.

The output only identifies areas that may warrant authorized manual testing.

---

# 11. JavaScript Reconnaissance

JavaScript resources can contain useful application information.

VDP-PRO attempts to identify JavaScript resources from:

* historical URLs
* current HTTP responses

The pipeline maintains separate files for JavaScript resources and additional extracted information.

Potential areas of interest include:

* API paths
* internal paths
* Firebase URLs
* potential secret patterns

These are discovery results and require manual verification.

A detected string resembling a credential does not automatically constitute a valid secret.

---

# 12. Technology Fingerprinting

Technology identification provides contextual information about the target.

Examples include:

```text
Apache
Nginx
IIS
PHP
Node.js
WordPress
Laravel
Next.js
```

Technology fingerprinting can help analysts understand the application stack and identify areas for subsequent authorized research.

However:

```text
Fingerprint ≠ confirmed software inventory
```

Fingerprinting results may contain:

* false positives
* duplicate detections
* version ambiguity
* proxy-generated information

Therefore, technology results should be treated as evidence rather than absolute truth.

---

# 13. Security Header Inventory

The pipeline examines HTTP response headers for security-related observations.

Current checks include:

* Access-Control-Allow-Origin
* Access-Control-Allow-Credentials
* Strict-Transport-Security
* X-Content-Type-Options
* X-Frame-Options
* Content-Security-Policy

The objective is to identify configuration areas that may require manual review.

For example:

```text
Missing CSP
```

means that a CSP header was not detected.

It does **not** automatically mean:

```text
Confirmed vulnerability
```

Security impact depends on application behavior, deployment architecture, browser context, and other controls.

---

# 14. Cloud Candidate Generation

The pipeline can generate possible cloud-storage naming candidates from discovered hostnames.

For example:

```text
assets
backup
uploads
media
storage
files
```

These are candidate names only.

Automatic cloud probing is intentionally disabled.

Therefore:

```text
Candidate generated
       ≠
Cloud resource exists
```

---

# 15. Port Scanning

Active port scanning is intentionally disabled in the safe reconnaissance pipeline.

The project records this explicitly rather than silently pretending that ports were assessed.

This allows the same reporting framework to distinguish:

```text
Not assessed
```

from:

```text
No ports found
```

This distinction is important for accurate security reporting.

---

# 16. Active Vulnerability Scanning

Active vulnerability scanning is disabled.

VDP-PRO is therefore not intended to replace tools such as:

* authenticated vulnerability scanners
* web vulnerability scanners
* manual penetration testing
* application-specific security testing

The project focuses on reconnaissance and evidence collection.

If active testing is authorized, it should be performed separately according to the organization's approved methodology and scope.

---

# 17. Screenshot Collection

Screenshots are optional and depend on the availability of the configured screenshot utility.

The purpose is to provide visual evidence of discovered web interfaces.

Screenshots can help with:

* asset identification
* report documentation
* application classification
* historical comparison

Screenshots should never contain confidential information when included in a public portfolio repository.

---

# 18. Evidence Collection

Each execution creates a timestamped output directory.

Evidence is separated by category:

```text
subenum/
live/
historical/
js/
vulns/
ports/
screenshots/
cloud/
reports/
```

This structure allows individual findings to be traced back to the relevant reconnaissance stage.

The pipeline also records execution information in:

```text
pipeline.log
```

---

# 19. Reporting

The final report summarizes:

* target information
* discovered assets
* live HTTP services
* historical URLs
* parameters
* JavaScript resources
* passive candidates
* security-header observations
* technology information
* disabled active capabilities

The report is intended to provide a high-level assessment summary while the individual output files preserve the underlying evidence.

---

# 20. Result Interpretation

VDP-PRO follows an evidence-first interpretation model.

The following distinction is important:

```text
0 findings
    ≠
No vulnerability exists
```

Instead:

```text
0 findings
    =
Configured discovery method did not identify the item
```

Likewise:

```text
Candidate
    ≠
Confirmed vulnerability
```

and:

```text
Fingerprint
    ≠
Confirmed software inventory
```

This approach reduces false conclusions from automated reconnaissance.

---

# 21. Safety Principles

The methodology follows five primary principles.

### 1. Authorization

Only test assets that are explicitly authorized.

### 2. Scope

Respect the target's published scope and testing policy.

### 3. Minimal Interaction

Prefer passive discovery and lightweight HTTP reconnaissance.

### 4. Evidence

Preserve the raw results that support conclusions.

### 5. Transparency

Clearly identify which capabilities were skipped or disabled.

---

# 22. Reproducibility

A reconnaissance run should be reproducible.

Each run therefore records:

* execution timestamp
* target
* operating mode
* output directory
* tool results
* pipeline log
* summary report

This makes it possible to compare reconnaissance results between different runs.

---

# 23. Current Scope of the Project

VDP-PRO currently focuses on:

```text
Passive Reconnaissance
        +
HTTP Discovery
        +
Technology Fingerprinting
        +
JavaScript Discovery
        +
Security Header Inventory
        +
Structured Reporting
```

It deliberately does not attempt to become a full exploitation or vulnerability-assessment framework.

---

# 24. Future Methodology Improvements

Future versions can improve:

* dependency validation
* URL-mode separation
* technology normalization
* report severity classification
* JSON output
* configuration management
* automated tests
* CI validation
* passive intelligence sources
* evidence classification

The objective is to improve reliability and reporting quality without turning the safe reconnaissance workflow into an uncontrolled active scanner.
