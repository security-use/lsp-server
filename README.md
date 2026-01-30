# Security LSP Server

LSP server for security vulnerability highlighting in VS Code and Cursor. Part of the [security-use](https://github.com/security-use) project.

## What It Does

This LSP server provides real-time security feedback directly in your editor:

- **Squiggly underlines** on vulnerable dependencies and IaC misconfigurations
- **Hover information** showing CVE details, severity, fix versions, and compliance frameworks
- **Quick fix code actions** to update vulnerable packages with one click
- **Ignore/suppress** vulnerabilities via inline comments or config file
- **Code lens** showing vulnerability counts at the top of files
- **Diagnostic links** to CVE databases, documentation, and changelogs
- **Background scanning** with caching for fast, responsive editing
- **Compliance mapping** showing SOC2, HIPAA, PCI-DSS, and other framework violations

## Features

| Feature | Description |
|---------|-------------|
| Dependency Scanning | Detects vulnerable packages in requirements.txt, pyproject.toml, package.json, etc. |
| IaC Scanning | Detects misconfigurations in Terraform and CloudFormation files |
| Compliance Mapping | Maps IaC findings to SOC2, HIPAA, PCI-DSS, NIST, CIS frameworks |
| Hover Details | Rich hover showing CVE info, fix versions, compliance frameworks |
| Code Lens | Shows vulnerability count summary at top of files |
| Quick Fixes | Click the lightbulb to update to a safe version |
| Ignore Actions | Suppress vulnerabilities via inline comments or config file |
| Diagnostic Links | Links to NVD, GitHub Advisory, OSV, PyPI, and Checkov docs |
| Caching | Results cached by content hash to avoid redundant scans |

## Supported File Types

### Dependency Files
- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`
- JavaScript: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Ruby: `Gemfile`, `Gemfile.lock`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- Java: `pom.xml`, `build.gradle`
- .NET: `packages.config`, `*.csproj`
- PHP: `composer.json`, `composer.lock`

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
3. Click "..." menu -> "Install from VSIX..."
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

## New Features

### Hover Information

Hover over a vulnerable dependency or IaC misconfiguration to see:

- CVE/Rule ID with severity badge
- Package name and version
- Fix version recommendation
- Compliance framework mappings (SOC2, HIPAA, PCI-DSS, etc.)
- Links to documentation

### Ignore/Suppress Vulnerabilities

#### Inline Comments

Add ignore comments directly in your code:

```python
# requirements.txt
requests==2.28.0  # security-use: ignore CVE-2024-1234
flask==2.0.0  # security-use: ignore CVE-2024-5678, CVE-2024-9999
```

```hcl
# Terraform
resource "aws_s3_bucket" "example" {
  # security-use: ignore CKV_AWS_19
  acl = "public-read"
}
```

#### Config File

Create `.security-use-ignore.yaml` in your project root:

```yaml
ignores:
  - id: CVE-2024-1234
    reason: "False positive - not exploitable in our context"
    expires: 2025-06-01
  - id: CKV_AWS_20
    paths:
      - "terraform/dev/*"
    reason: "Dev environment - public access intended"
```

### Code Lens

At the top of dependency and IaC files, you'll see:

- **Vulnerability count** with severity breakdown
- **Scan now** button for on-demand scanning

### Diagnostic Links

Each diagnostic includes related information with clickable links to:

- **NVD** for CVE details
- **GitHub Advisory** for GHSA vulnerabilities
- **OSV** for open source vulnerabilities
- **PyPI** for package changelogs
- **Checkov** for IaC rule documentation
- **Terraform Registry** for resource documentation

### Compliance Mapping

IaC findings are automatically mapped to compliance frameworks:

- **SOC2** - Trust Services Criteria
- **HIPAA** - Health Insurance Portability
- **PCI-DSS** - Payment Card Industry
- **NIST 800-53** - Security Controls
- **CIS Benchmarks** - AWS, Azure, GCP, Kubernetes
- **ISO 27001** - Information Security

## How It Works

```
+-------------------------------------------------------------+
|                    VS Code / Cursor                          |
+-------------------------------------------------------------+
|  Extension (TypeScript)                                      |
|  +-- Language Client ----------------------+                 |
|                                            |                 |
|  +----------------------------------------v----------------+ |
|  |  LSP Server (Python)                                    | |
|  |  +-- server.py      - LSP protocol handlers             | |
|  |  +-- diagnostics.py - Creates squiggly underlines       | |
|  |  +-- code_actions.py - Quick fix & ignore suggestions   | |
|  |  +-- scanner.py     - Caches and delegates to scanner   | |
|  |  +-- ignore.py      - Ignore config & inline parsing    | |
|  |           |                                             | |
|  |           v                                             | |
|  |  +---------------------------------------------------+  | |
|  |  |  security-use package (v0.2.8+)                   |  | |
|  |  |  +-- scan_dependencies() - OSV database lookup    |  | |
|  |  |  +-- scan_iac() - IaC rules engine               |  | |
|  |  |  +-- compliance/ - Framework mapping              |  | |
|  |  |  +-- sbom/ - SBOM generation                      |  | |
|  |  +---------------------------------------------------+  | |
|  +--------------------------------------------------------+ |
+-------------------------------------------------------------+
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
   - Open `requirements.txt` -> vulnerable packages get red squiggles
   - Hover to see CVE details, fix version, and compliance info
   - Click lightbulb -> apply quick fix or ignore

2. **AI-Assisted Fixing** (MCP Server)
   - Ask Cursor AI: "Fix the security vulnerabilities in this project"
   - AI calls MCP tools to scan and fix issues
   - AI applies changes with explanations

## Development

### Prerequisites

- Python 3.10+
- Node.js 18+ (for VS Code extension)
- pygls 2.0.0+

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
+-- pyproject.toml                 # Package configuration
+-- src/security_lsp/
|   +-- __init__.py
|   +-- server.py                  # Main LSP server
|   +-- diagnostics.py             # Diagnostic creation
|   +-- code_actions.py            # Quick fix & ignore code actions
|   +-- scanner.py                 # Scanning with caching
|   +-- ignore.py                  # Ignore config & inline parsing
+-- tests/
|   +-- test_scanner.py            # Scanner and caching tests
|   +-- test_code_actions.py       # Code action tests
|   +-- test_iac_diagnostics.py    # IaC diagnostic tests
|   +-- test_new_features.py       # Hover, ignore, code lens tests
+-- vscode-extension/
    +-- package.json               # Extension manifest
    +-- src/extension.ts           # Extension entry point
    +-- tsconfig.json              # TypeScript config
```

## Compatibility

- **security-use**: v0.2.8+
- **pygls**: v2.0.0+
- **Python**: 3.10+
- **VS Code**: 1.85+

## License

MIT
