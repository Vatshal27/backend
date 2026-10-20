# SentinelAI Backend

<div align="center">

[![Node.js](https://img.shields.io/badge/node.js-v18+-43853d?style=flat-square&logo=node.js)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/express.js-v5.2+-000000?style=flat-square&logo=express)](https://expressjs.com/)
[![Docker](https://img.shields.io/badge/docker-support-2496ed?style=flat-square&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-ISC-blue?style=flat-square)](LICENSE)

**Local-first developer security scanner — early-stage prototype**

A local backend for static security scanning, dependency/secrets/configuration checks, and limited runtime validation from the SentinelAI VS Code extension. It is not a security certification or a substitute for a professional assessment.

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🎯 Overview

The backend is a loopback-only service used by the VS Code extension. The stable features today are file-based static scanning, offline heuristic checks, optional exact-version npm advisory lookup, bounded job management, redacted evidence, and a narrow local runtime-validation flow. Results are limited to the checks and routes actually exercised; the product is an early-stage prototype, not security certification.

## ✨ Features

- **🔍 Static analysis**
  - Existing Docker scanner pipeline (Semgrep/Bandit according to scanner image/configuration).
  - Coverage is reported separately from findings; scan success does not mean complete coverage.
  
- **🤖 Optional AI assistance**
  - Ollama can add explanation/recommendation text to findings when enabled.
  - AI output is advisory and must not be treated as a verified vulnerability verdict.

- **🐳 Docker runtime tools**
  - Safe Simulation runs the configured scanner against isolated synthetic Docker fixtures and shows simulated attack paths/data exposure, not project-specific evidence.
  - Project Validation sends supported, bounded probes to an authorized live localhost project and reports observed behavior/data exposure; it is not an unrestricted all-vulnerability attack.


- **📊 Evidence-oriented reporting**
  - Findings, coverage, provenance, runtime verdicts, and redacted exposure candidates.
  - Heuristic candidates are not independently verified as exploitable.

- **🔐 Workbench profiles**
  - Source, dependencies, secrets, infrastructure, and comprehensive profiles.
  - OSV advisory queries are opt-in and require network consent.
  - Secrets/PII exposure checks are heuristic; output should contain masked values only.

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ ([Download](https://nodejs.org/))
- npm or yarn
- Docker Engine (required for the configured static scanner image and paired lab)
- The pinned/configured scanner image must be present or pullable

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinelai.git
cd sentinelai/backend

# Install dependencies
npm install

# Verify Docker support (optional)
npm run scanner:check
```

### Basic Usage

```bash
# Start the server
npm start

# Backend binds to http://127.0.0.1:3000 by default. It is local-only.
```

## 📚 Documentation

### Project Structure

```
backend/
├── server.js                 # Local-only Express API
├── docker-sandbox.js         # Docker container management
├── docker-scanner.js         # Docker integration utilities
├── package.json              # Dependencies and scripts
│
├── llm/
│   ├── analyzer.js          # LLM-based analysis
│   ├── ollama.js            # Ollama integration
│   └── prompt-builder.js    # Dynamic prompt generation
│
├── docker/                  # Existing scanner, runtime validation, reports
├── security/                # Workbench profiles, dependency checks, redaction
├── jobs/                    # Bounded local async job service
├── tests/                   # Node test-runner suites
└── scanner/                 # Legacy experimental CLI; not used by server.js
```

### API Endpoints

#### Current routes

The backend API is intended for the local VS Code extension; do not expose it to an untrusted network.

- `GET /health` — backend/optional Ollama status.
- `POST /analyze-project` — legacy static/LLM analysis; request `{ "files": [{ "path": "src/app.js", "code": "..." }] }`.
- `POST /sandbox/run`, `POST /sandbox/stop`, `GET /sandbox/check` — existing simulation/project validation workflow.
- `GET /runtime/discover`, `POST /runtime/check` — local runtime discovery/check.
- `GET /security/capabilities` — scan profiles and their supported checks/limitations.
- `POST /security/jobs`, `GET /security/jobs/:id`, `DELETE /security/jobs/:id`, `GET /security/jobs/:id/events` — local asynchronous scan jobs, polling, cancellation and SSE.
- `GET /api/mail/status`, `POST /api/mail/test` — optional mail service; delivery is disabled unless configured.

For details and limitations see [SECURITY-WORKBENCH.md](SECURITY-WORKBENCH.md).
Project Validation's implemented checks and explicit coverage gaps are listed in [PROJECT-VALIDATION-COVERAGE.md](PROJECT-VALIDATION-COVERAGE.md).

### Configuration

#### Environment Variables

Create a `.env` file in the backend directory:

```env
# Server binds to loopback; PORT changes the local port only.
PORT=3000

# Scanner configuration
SENTINEL_SCANNER_IMAGE=sentinelai-scanner@sha256:12409d64fc81b229982bdad27749a4f35013f975dcb88d96e561b421d7ccd212

# LLM Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mistral

# Optional OSV dependency lookup is separately consented in the UI per scan.
```

The default scanner reference is pinned to the immutable digest verified in the local Docker daemon. To update it, inspect the replacement image and record its upstream source, tool versions, revision, SBOM/security review, and digest; run the scanner lifecycle tests and Docker lab against that exact digest; then update this example and `docker-scanner.js` together. Do not use mutable `latest` tags for reproducible runs.

#### Workbench capabilities

`GET /security/capabilities` is the source of truth for available scan profiles and checks. Static Analysis reports common suspicious source patterns as candidate findings. The optional LLM explains those candidates and suggests possible fixes; it is advisory, not proof. Safe Simulation uses synthetic Docker fixtures to demonstrate scanner behavior and simulated data exposure. Project Validation probes an authorized live localhost project with bounded supported checks; it is not a guarantee that every vulnerability class was tested. Authentication/business-logic checks need trusted identity and ownership context not currently provided.

## 🛠️ Development

### Running Tests

```bash
# Run unit/integration tests (Docker lab skipped by default)
npm test


```

### Linting

```bash
# Check code quality
npx eslint .

# Fix linting issues
npx eslint . --fix
```

### Adding or expanding a check

1. Add a failing vulnerable/fixed fixture test before implementation.
2. Make capability/coverage accurately state prerequisites and unsupported states.
3. Keep passive checks passive; require explicit consent and a user-owned local target for active Project Validation.
4. Assert no raw credentials/PII reach reports, logs, or the webview.
5. Measure false positives and detection rate on a labeled corpus before claiming the check is effective.

## 🔒 Security Considerations

- **Sandboxing**: Use Docker sandbox for untrusted code analysis
- **Output Sanitization**: All outputs are sanitized to prevent information leakage
- **Rule Validation**: Security rules are validated before execution
- **Dependency Updates**: Keep dependencies updated with `npm audit`

```bash
# Check for vulnerabilities
npm audit

# Fix automatically fixable issues
npm audit fix
```

## 📊 Supported Languages & Tools

| Language | Tools | Detection Level |
|----------|-------|-----------------|
| JavaScript/TypeScript and other supported source types | Configured Docker scanner image | Static patterns; coverage depends on available scanners/rules |
| npm dependencies | package-lock.json + opt-in OSV | Exact lockfile package/version advisory matching; no reachability analysis |
| Secrets / personal data | Offline pattern heuristics | Candidate exposure only; values masked, formats incomplete |
| Runtime | Local Project Validation | Bounded discovered routes; no generic authenticated/browser assurance |

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contributing Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 Test semantics

Synthetic labs validate SentinelAI's own test logic only. They never confirm vulnerabilities in the user's workspace. Project Validation is limited to discovered routes on an explicitly local runtime, may miss routes and data behind authentication, and reports only the evidence obtained from probes actually run.

## 🐛 Known Issues & Limitations

- Docker sandbox requires Docker daemon to be running
- Ollama integration requires local Ollama instance
- Large projects may take longer to analyze
- Checks are best-effort and coverage-specific; no result means no finding among checks actually run, not security certification.
- Authenticated access-control/business-logic, real-browser execution, and other context-dependent scenarios are unsupported unless explicitly reported as supported by capabilities.

## 📈 Performance

Runtime depends on Docker availability, scanner image, files/bytes collected, and optional OSV/LLM services; no stable benchmark has been published yet.

### Benchmark protocol before accuracy claims

The repository does not yet contain an independently labeled representative project corpus or a reproducible end-to-end precision/recall benchmark. The synthetic secret fixtures are regression checks for one heuristic only; Docker paired-lab results test SentinelAI against controlled fixtures, not vulnerability discovery in user projects. Do not cite either as general detection accuracy.

Before making accuracy claims, publish a versioned manifest containing the code commit, scanner and lab image digests, runtime/tool versions, exact input fixtures, profile/check configuration, expected labels and their independent adjudication source, and actual per-case outcomes. Separate static candidate, observed exposure, runtime-confirmed, synthetic self-test, skipped, unsupported, inconclusive and failed results. Define duplicate handling and report precision/recall with class counts and uncertainty intervals; include fixed/negative and inconclusive cases, and provide an executable command that regenerates all counts from the manifest. Never treat absence of findings as evidence of complete coverage.

## 📦 Dependencies

- **express** - Web framework
- **axios** - HTTP client
- **dockerode** - Docker integration
- **sqlite3** - Database
- **cors** - CORS middleware
- **eslint** - JavaScript linting
- **nodemailer** - optional SMTP delivery (disabled unless configured)
- Semgrep/Bandit run inside the configured Docker scanner image; they are not backend npm dependencies.

See [package.json](package.json) for complete list.

## 🔄 Current architecture

```text
VS Code extension
  ├─ existing scan/simulation/project-validation commands
  └─ Security Workbench (profiles, consent, async jobs, evidence/export)
        │ loopback HTTP
        ▼
Express backend (127.0.0.1 by default)
  ├─ /security/* → bounded job manager
  │    ├─ source → docker-scanner.js → configured scanner image
  │    ├─ dependencies/secrets/infrastructure → security/* heuristics/advisories
  │    └─ synthetic SQL lab → digest-pinned paired fixture
  ├─ legacy /analyze-project and /sandbox/* flows
  └─ reports → redaction, compilation, local files
```

Synthetic lab output tests SentinelAI itself and must never be interpreted as proof about project code. Project Validation uses a user-selected local runtime and bounded discovered routes; authentication/browser limitations remain.

## 📄 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## 🙋 Support

- 📖 [Documentation](./docs)
- 🐛 [Report Issues](https://github.com/yourusername/sentinelai/issues)
- 💬 [Discussions](https://github.com/yourusername/sentinelai/discussions)

---

<div align="center">

Made with ❤️ by the SentinelAI Team

[⬆ Back to top](#sentinelai-backend)

</div>
