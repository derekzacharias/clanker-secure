# Vulnerability Scanner Functional Requirements

Purpose: Non-negotiable functional requirements

## 1. Core Scanning Capabilities (Required)

The system SHALL support:

### 1.1 Authentication
- Authenticated and unauthenticated scanning
- SSH, WinRM, and API-based authentication

### 1.2 Network Scanning
- Open port detection
- Service identification
- Protocol weakness detection
- External enumeration tooling (nmap NSE, Nikto, WhatWeb, Masscan, OpenSSL/TestSSL.sh) to deepen coverage while prioritizing accuracy and authenticated contexts when available
- Curated CPE inference for SSH/agent observations with service/version normalization

### 1.3 Host and OS Scanning
- CVE mapping for Linux, Windows, and macOS
- Credentialed host hardening checks (e.g., Lynis) when authenticated/local access is provided

### 1.4 Web and API Scanning
- OWASP Top 10 coverage
- REST and GraphQL API scanning
- HTTP/HTTPS fingerprinting and vuln enumeration via Nikto/WhatWeb/TestSSL.sh integrated into scan flow

### 1.5 Configuration and Compliance
- CIS Benchmark checks
- Cloud misconfiguration detection
- Credentialed compliance checks
- STIG, CIS, and NIST mappings

---

## 2. CVE and Intelligence Management (Required)

The system SHALL support:

- Automated CVE ingestion from NVD and vendor advisories
- Distro-aware OSV/OVAL ingestion (backport-aware) for credentialed scans
- Exploitability awareness
- Known Exploited Vulnerabilities support
- EPSS scoring
- Risk-based prioritization combining severity, exploitability, and asset value
- Zero-day and emerging threat tracking
- Custom vulnerability definitions

---

## 3. Cloud and Container Security (Required)

The system SHALL support:

### 3.1 Cloud Platforms
- AWS, Azure, and GCP scanning
- IAM misconfiguration detection
- Network exposure analysis

### 3.2 Containers and Kubernetes
- Container image scanning for OS packages and language dependencies
- Kubernetes security checks
- Pod security validation
- RBAC analysis
- Detection of exposed services

### 3.3 Infrastructure as Code
- Terraform scanning
- CloudFormation scanning
- Kubernetes manifest scanning

---

## 4. Asset Discovery and Inventory (Required)

The system SHALL support:

- Automated asset discovery via network scanning and cloud APIs
- DNS/IP/domain enumeration (e.g., Amass, Subfinder) to surface related assets and subdomains
- Asset classification by criticality and environment
- Continuous inventory tracking
- Support for ephemeral assets including containers and auto-scaling workloads

---

## 5. DevSecOps and CI/CD Integration (Required)

The system SHALL support:

- CI/CD integrations with GitHub Actions, GitLab CI, Jenkins, and Azure DevOps
- Pre-deployment scanning
- Fail-build policy enforcement
- SBOM ingestion and analysis
- Developer-readable remediation output

---

## 6. Remediation and Workflow (Required)

The system SHALL support:

- Clear remediation guidance
- Patch availability detection
- Jira and ServiceNow integration
- Ownership assignment
- False-positive suppression
- Exception handling and risk acceptance workflows

---

## 7. Reporting and Visualization (Required)

The system SHALL support:

- Technical vulnerability reports with CVE details and evidence
- Executive summaries showing risk posture and trends
- Custom dashboards
- Compliance-ready audit reports
- Export formats including JSON, CSV, PDF
- Full reporting via API
- Evidence grading and traceability (why-trace) exposed via API/UI with filtering, sorting, and exports

---

## 8. Scalability and Performance (Required)

The system SHALL support:

- Distributed scanning architecture
- Horizontal scaling
- Scan throttling and scheduling
- Background job queue observability (metrics/logging), configurable concurrency, and compatibility path for Redis/RQ-style backends
- Agent-based and agentless scanning
- Low-impact scanning modes

---

## 9. Security and Access Control (Required)

The system SHALL support:

- Role-based access control
- Multi-tenant architecture
- SSO and MFA
- Audit logging
- Secure secret storage

---

## 10. Platform and API Capabilities (Required)

The system SHALL support:

- Full REST API
- Webhooks
- Plugin or extension framework
- Custom policy engine
- Automation hooks

---

## 11. Competitive Differentiators (Optional)

The system MAY support:

- Attack-path analysis
- Vulnerability chaining
- Threat modeling integration
- AI-assisted prioritization
- Context-aware risk scoring
- SIEM and SOAR integrations
- Live exposure graphs
