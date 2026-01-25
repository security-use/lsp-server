# Security LSP Server

LSP server for security vulnerability highlighting in VS Code and Cursor. Part of the [security-use](https://github.com/security-use) project.

## What It Does

This LSP server provides real-time security feedback directly in your editor:

- **Squiggly underlines** on vulnerable dependencies and IaC misconfigurations
- **Hover information** showing CVE details, severity, and fix versions
- **Quick fix code actions** to update vulnerable packages with one click
- **Background scanning** with caching for fast, responsive editing

## Features

| Feature | Description |
|---------|-------------|
| Dependency Scanning | Detects vulnerable packages in requirements.txt, pyproject.toml, package.json, etc. |
| IaC Scanning | Detects misconfigurations in Terraform and CloudFormation files |
| Severity Mapping | CVE severity (CRITICAL/HIGH/MEDIUM/LOW) maps to editor diagnostics |
| Quick Fixes | Click the lightbulb to update to a safe version |
| Caching | Results cached by content hash to avoid redundant scans |

## Supported File Types

### Dependency Files
- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`
- JavaScript: `package.json`, `package-lock.json`, `yarn.lock`
- Ruby: `Gemfile`, `Gemfile.lock`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- Java: `pom.xml`

### Infrastructure as Code
- Terraform: `*.tf`, `*.tfvars`
- CloudFormation: `*.yaml`, `*.yml`, `*.json` (in cloudformation directories)
- Kubernetes: `*.yaml`, `*.yml` (in kubernetes/k8s directories)

## Installation

### From PyPI

```bash
pip install security-lsp
```

### From Source

```bash
git clone https://github.com/security-use/lsp-server.git
cd lsp-server
pip install -e .
```

### With Full Scanning (Recommended)

Install with the core security-use package for real vulnerability detection:

```bash
pip install security-lsp[scanner]
# or
pip install security-lsp security-use
```

Without the scanner, the LSP server uses stub data for testing/demo purposes.

## VS Code / Cursor Extension

### Building the Extension

```bash
cd vscode-extension
npm install
npm run package
```

This creates a `.vsix` file you can install in VS Code or Cursor.

### Installing

1. Open VS Code/Cursor
2. Go to Extensions (Cmd+Shift+X)
3. Click "..." menu → "Install from VSIX..."
4. Select the generated `.vsix` file

### Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `securityScanner.enable` | `true` | Enable/disable the scanner |
| `securityScanner.severityThreshold` | `low` | Minimum severity to report (critical/high/medium/low) |
| `securityScanner.scanOnSave` | `true` | Scan files when saved |
| `securityScanner.scanOnOpen` | `true` | Scan files when opened |
| `securityScanner.enableDependencyScanning` | `true` | Enable dependency scanning |
| `securityScanner.enableIaCScanning` | `true` | Enable IaC scanning |
| `securityScanner.pythonPath` | `python` | Path to Python executable |

### Commands

- `Security: Scan Workspace` - Scan all files in the workspace
- `Security: Scan Current File` - Scan the active file
- `Security: Show Vulnerability Report` - Open the output panel

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    VS Code / Cursor                         │
├─────────────────────────────────────────────────────────────┤
│  Extension (TypeScript)                                     │
│  └── Language Client ──────────────────┐                    │
│                                        │                    │
│  ┌─────────────────────────────────────▼──────────────────┐ │
│  │  LSP Server (Python)                                   │ │
│  │  ├── server.py     - LSP protocol handlers             │ │
│  │  ├── diagnostics.py - Creates squiggly underlines      │ │
│  │  ├── code_actions.py - Quick fix suggestions           │ │
│  │  └── scanner.py    - Caches and delegates to scanner   │ │
│  │           │                                            │ │
│  │           ▼                                            │ │
│  │  ┌─────────────────────────────────────────────────┐   │ │
│  │  │  security-use package                           │   │ │
│  │  │  ├── scan_dependencies() - OSV database lookup  │   │ │
│  │  │  └── scan_iac() - IaC rules engine              │   │ │
│  │  └─────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Integration with Other Components

This LSP server is part of a three-component security scanning system:

| Component | Repository | Purpose |
|-----------|------------|---------|
| **security-use** | [security-use/security-use](https://github.com/security-use/security-use) | Core scanning engine (pip package) |
| **lsp-server** | [security-use/lsp-server](https://github.com/security-use/lsp-server) | Editor integration (this repo) |
| **mcp** | [security-use/mcp](https://github.com/security-use/mcp) | AI chat integration |

### Typical Workflow

1. **Editor Highlighting** (LSP Server)
   - Open `requirements.txt` → vulnerable packages get red squiggles
   - Hover to see CVE details and fix version
   - Click lightbulb → apply quick fix

2. **AI-Assisted Fixing** (MCP Server)
   - Ask Cursor AI: "Fix the security vulnerabilities in this project"
   - AI calls MCP tools to scan and fix issues
   - AI applies changes with explanations

## Development

### Prerequisites

- Python 3.10+
- Node.js 18+ (for VS Code extension)

### Setup

```bash
# Clone all repos
git clone https://github.com/security-use/security-use.git
git clone https://github.com/security-use/lsp-server.git
git clone https://github.com/security-use/mcp.git

# Install core package
cd security-use
pip install -e .

# Install LSP server
cd ../lsp-server
pip install -e ".[dev]"

# Install VS Code extension deps
cd vscode-extension
npm install
```

### Running the LSP Server

```bash
# stdio mode (for VS Code)
python -m security_lsp.server

# TCP mode (for debugging)
python -m security_lsp.server --tcp 2087
```

### Running Tests

```bash
pytest -v
```

### Project Structure

```
lsp-server/
├── pyproject.toml                 # Package configuration
├── src/security_lsp/
│   ├── __init__.py
│   ├── server.py                  # Main LSP server
│   ├── diagnostics.py             # Diagnostic creation
│   ├── code_actions.py            # Quick fix code actions
│   └── scanner.py                 # Scanning with caching
├── tests/
│   ├── test_scanner.py            # Scanner and caching tests
│   ├── test_code_actions.py       # Code action tests
│   └── test_iac_diagnostics.py    # IaC diagnostic tests
└── vscode-extension/
    ├── package.json               # Extension manifest
    ├── src/extension.ts           # Extension entry point
    └── tsconfig.json              # TypeScript config
```

## License

MIT
