# Security LSP Server

LSP server for security vulnerability highlighting in VS Code/Cursor. Part of the [security-use](https://github.com/security-use) project.

## Features

- **Dependency Vulnerability Scanning**: Scans `requirements.txt`, `pyproject.toml`, `package.json`, and other dependency files for known vulnerabilities
- **Infrastructure as Code Scanning**: Scans Terraform, CloudFormation, and Kubernetes files for security misconfigurations
- **Real-time Diagnostics**: Shows vulnerabilities as squiggly underlines with severity levels
- **Quick Fix Code Actions**: One-click fixes to update vulnerable dependencies or fix IaC issues
- **Background Scanning**: Non-blocking scans with result caching for performance

## Installation

### LSP Server

```bash
pip install security-lsp
```

### VS Code Extension

1. Build the extension:
   ```bash
   cd vscode-extension
   npm install
   npm run package
   ```

2. Install the generated `.vsix` file in VS Code/Cursor

## Usage

The extension activates automatically when you open supported files:

- **Dependency files**: `requirements.txt`, `pyproject.toml`, `package.json`, `Gemfile`, `go.mod`, `Cargo.toml`, etc.
- **IaC files**: `*.tf`, `*.yaml`, `*.yml`, `*.json` (in terraform/cloudformation/kubernetes directories)

### Commands

- `Security: Scan Workspace` - Scan all files in the workspace
- `Security: Scan Current File` - Scan the active file
- `Security: Show Vulnerability Report` - Open the output panel with scan results

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `securityScanner.enable` | `true` | Enable/disable the scanner |
| `securityScanner.severityThreshold` | `low` | Minimum severity to report |
| `securityScanner.scanOnSave` | `true` | Scan files on save |
| `securityScanner.scanOnOpen` | `true` | Scan files on open |
| `securityScanner.enableDependencyScanning` | `true` | Enable dependency scanning |
| `securityScanner.enableIaCScanning` | `true` | Enable IaC scanning |
| `securityScanner.pythonPath` | `python` | Path to Python executable |

## Architecture

```
security-use/
├── security-use/     # Core scanning package
├── mcp/              # MCP server for AI integration
└── lsp-server/       # This repo - LSP server
    ├── src/
    │   └── security_lsp/
    │       ├── server.py      # Main LSP server
    │       ├── diagnostics.py # Diagnostic creation
    │       ├── code_actions.py # Quick fix actions
    │       └── scanner.py     # Scanning with caching
    └── vscode-extension/
        └── src/
            └── extension.ts   # VS Code client
```

## Development

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm

### Setup

```bash
# Install Python dependencies
pip install -e ".[dev]"

# Install VS Code extension dependencies
cd vscode-extension
npm install
```

### Running Locally

```bash
# Start LSP server directly
python -m security_lsp.server

# Or with TCP transport for debugging
python -m security_lsp.server --tcp 2087
```

### Testing

```bash
# Run Python tests
pytest

# Lint
ruff check src/
mypy src/
```

## Integration with MCP Server

The LSP server works alongside the [MCP server](https://github.com/security-use/mcp) to provide AI-powered vulnerability remediation:

1. LSP server highlights vulnerabilities in the editor
2. User asks Cursor AI to "fix security issues"
3. MCP server provides tools for the AI to list and fix vulnerabilities
4. AI generates and applies fixes

## License

MIT
