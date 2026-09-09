# SentinelAI Backend

<div align="center">

[![Node.js](https://img.shields.io/badge/node.js-v18+-43853d?style=flat-square&logo=node.js)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/express.js-v5.2+-000000?style=flat-square&logo=express)](https://expressjs.com/)
[![Docker](https://img.shields.io/badge/docker-support-2496ed?style=flat-square&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-ISC-blue?style=flat-square)](LICENSE)

**AI-Powered Security Analysis Engine**

A comprehensive backend service for detecting vulnerabilities, security issues, and code quality problems across JavaScript and Python projects.

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🎯 Overview

SentinelAI Backend is a sophisticated security scanning engine that combines multiple analysis tools with AI-powered insights to identify vulnerabilities, security misconfigurations, and code quality issues. It leverages Docker for safe sandboxing and integrates with cutting-edge security analysis tools.

## ✨ Features

- **🔍 Multi-Framework Scanning**
  - ESLint for JavaScript/TypeScript code quality and security rules
  - Bandit for Python security vulnerabilities
  - Semgrep for advanced pattern-based vulnerability detection
  
- **🤖 AI-Powered Analysis**
  - LLM-based vulnerability analysis using Ollama
  - Intelligent prompt generation for context-aware recommendations
  - Code pattern understanding and suggestions

- **🐳 Docker Sandbox**
  - Safe execution environment for code analysis
  - Docker integration for isolated testing
  - Resource-controlled analysis environment

- **📊 Comprehensive Reporting**
  - Detailed vulnerability reports with severity levels
  - Context-aware code recommendations
  - Sanitized output for safe information disclosure

- **🔐 Security Rules**
  - JavaScript-specific security rules
  - Python-specific vulnerability patterns
  - Secrets detection (API keys, credentials, tokens)
  - Customizable rule configurations

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ ([Download](https://nodejs.org/))
- npm or yarn
- Docker (optional, for sandbox features)
- Python 3.8+ (for Bandit scanner)

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

# Server runs on http://localhost:3000
```

## 📚 Documentation

### Project Structure

```
backend/
├── server.js                 # Main Express server
├── docker-sandbox.js         # Docker container management
├── docker-scanner.js         # Docker integration utilities
├── package.json              # Dependencies and scripts
│
├── llm/
│   ├── analyzer.js          # LLM-based analysis
│   ├── ollama.js            # Ollama integration
│   └── prompt-builder.js    # Dynamic prompt generation
│
├── scanner/
│   ├── scanner.js           # Main scanner orchestrator
│   ├── eslint.js            # ESLint integration
│   ├── bandit.js            # Bandit integration
│   ├── semgrep.js           # Semgrep integration
│   ├── context.js           # Code context extraction
│   ├── normalize.js         # Output normalization
│   ├── sanitizer.js         # Information sanitization
│   └── rules/
│       ├── javascript.yml   # JS security rules
│       ├── python.yml       # Python security rules
│       └── secrets.yml      # Secrets detection rules
│
├── semgrep-test/            # Test fixtures
├── vulnerable_demo/         # Demo vulnerable code
└── test_*.js               # Test suites
```

### API Endpoints

#### Scan Project
```bash
POST /api/scan
Content-Type: application/json

{
  "projectPath": "/path/to/project",
  "language": "javascript|python|all",
  "scanners": ["eslint", "bandit", "semgrep"]
}

Response:
{
  "status": "success",
  "results": {
    "vulnerabilities": [...],
    "recommendations": [...],
    "summary": {...}
  }
}
```

#### Get Analysis
```bash
POST /api/analyze
Content-Type: application/json

{
  "code": "vulnerable code snippet",
  "language": "javascript|python"
}

Response:
{
  "analysis": "AI-generated analysis",
  "recommendations": ["fix1", "fix2"],
  "severity": "high|medium|low"
}
```

### Configuration

#### Environment Variables

Create a `.env` file in the backend directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Docker Configuration
DOCKER_SOCKET=/var/run/docker.sock

# LLM Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mistral

# Database
DATABASE_PATH=./security.db

# Logging
LOG_LEVEL=info
```

#### Scanner Configuration

Edit `scanner/rules/*.yml` to customize detection rules:

```yaml
# Example: javascript.yml
vulnerabilities:
  - name: "SQL Injection"
    pattern: "query\\(.*\\+" 
    severity: "critical"
    message: "Potential SQL injection detected"
    recommendation: "Use parameterized queries"
```

## 🛠️ Development

### Running Tests

```bash
# Test individual scanners
npm run test:eslint
npm run test:bandit
npm run test:semgrep

# Test AI analysis
npm run test:analyzer

# Test Docker sandbox
npm run test:sandbox

# Run all tests
npm test
```

### Linting

```bash
# Check code quality
npx eslint .

# Fix linting issues
npx eslint . --fix
```

### Adding New Scanners

1. Create a new scanner module in `scanner/`
2. Implement the standard scanner interface
3. Add integration to `scanner/scanner.js`
4. Add tests in `test_newscanner.js`

Example Scanner:

```javascript
// scanner/newscan.js
class NewScanner {
  async scan(projectPath) {
    // Implementation
    return {
      issues: [],
      metadata: {}
    };
  }
}

module.exports = NewScanner;
```

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
| JavaScript/TypeScript | ESLint, Semgrep | Code & Pattern |
| Python | Bandit, Semgrep | Code & Pattern |
| Secrets | All Scanners | Pattern-based |

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

## 📝 Testing Vulnerable Code

Test fixtures are included in `semgrep-test/` and `vulnerable_demo/`:

```bash
# Scan test fixtures
node scanner/scanner.js ./semgrep-test

# Scan demo vulnerable code
node scanner/scanner.js ./vulnerable_demo
```

## 🐛 Known Issues & Limitations

- Docker sandbox requires Docker daemon to be running
- Ollama integration requires local Ollama instance
- Large projects may take longer to analyze
- Some Python 2 syntax not fully supported in Bandit

## 📈 Performance

- **Small projects** (<100 files): ~2-5 seconds
- **Medium projects** (100-500 files): ~10-30 seconds
- **Large projects** (500+ files): Variable, 1-5 minutes

## 📦 Dependencies

- **express** - Web framework
- **axios** - HTTP client
- **dockerode** - Docker integration
- **sqlite3** - Database
- **cors** - CORS middleware
- **eslint** - JavaScript linting
- **bandit** - Python security scanner
- **semgrep** - Pattern-based scanner

See [package.json](package.json) for complete list.

## 🔄 Architecture

```
┌─────────────────────────────┐
│   VS Code Extension         │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│   Express Server (Backend)  │
├─────────────────────────────┤
│ ┌─────────┬─────────┬─────┐ │
│ │ ESLint  │ Bandit  │Semi │ │
│ │Scanner  │Scanner  │grep │ │
│ └─────────┴─────────┴─────┘ │
│           │                 │
│ ┌─────────▼─────────────┐  │
│ │  Context Analyzer     │  │
│ │  Output Normalizer    │  │
│ └───────────────────────┘  │
│           │                 │
│ ┌─────────▼─────────────┐  │
│ │  LLM Analysis (Ollama)│  │
│ └───────────────────────┘  │
└─────────────────────────────┘
```

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
