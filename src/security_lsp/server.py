"""Main LSP server implementation using pygls."""

from __future__ import annotations

import asyncio
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lsprotocol import types as lsp
from pygls.server import LanguageServer

from security_lsp.diagnostics import (
    create_dependency_diagnostics,
    create_iac_diagnostics,
)
from security_lsp.code_actions import create_code_actions
from security_lsp.scanner import SecurityScanner
from security_lsp.ignore import (
    IgnoreConfig,
    load_ignore_config,
    parse_inline_ignores,
    create_inline_ignore_comment,
    create_ignore_config_entry,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
}

IAC_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
IAC_PATTERNS = {"terraform", "cloudformation", "kubernetes", "helm", "docker"}


class SecurityLanguageServer(LanguageServer):
    """Language server for security vulnerability highlighting."""

    def __init__(self) -> None:
        super().__init__(
            name="security-lsp",
            version="0.1.0",
        )
        self.scanner = SecurityScanner()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._debounce_tasks: dict[str, asyncio.Task[None]] = {}
        self._scan_in_progress: dict[str, bool] = {}
        # Store diagnostics per URI for hover lookups
        self._diagnostics: dict[str, list[lsp.Diagnostic]] = {}
        # Ignore configuration
        self._ignore_config: IgnoreConfig = IgnoreConfig()

    def load_ignore_config(self) -> None:
        """Load ignore configuration from workspace."""
        self._ignore_config = load_ignore_config(self.workspace.root_uri)

    def is_dependency_file(self, uri: str) -> bool:
        """Check if the file is a dependency manifest."""
        path = Path(uri.replace("file://", ""))
        return path.name in DEPENDENCY_FILES

    def is_iac_file(self, uri: str) -> bool:
        """Check if the file is an Infrastructure as Code file."""
        path = Path(uri.replace("file://", ""))
        if path.suffix not in IAC_EXTENSIONS:
            return False
        # Check if path or content suggests IaC
        path_lower = str(path).lower()
        return any(pattern in path_lower for pattern in IAC_PATTERNS) or path.suffix == ".tf"


server = SecurityLanguageServer()


@server.feature(lsp.INITIALIZE)
def initialize(params: lsp.InitializeParams) -> lsp.InitializeResult:
    """Handle LSP initialize request."""
    logger.info("Initializing security-lsp server")
    logger.info(f"Root URI: {params.root_uri}")
    logger.info(f"Capabilities: {params.capabilities}")

    return lsp.InitializeResult(
        capabilities=lsp.ServerCapabilities(
            text_document_sync=lsp.TextDocumentSyncOptions(
                open_close=True,
                change=lsp.TextDocumentSyncKind.Incremental,
                save=lsp.SaveOptions(include_text=True),
            ),
            code_action_provider=lsp.CodeActionOptions(
                code_action_kinds=[
                    lsp.CodeActionKind.QuickFix,
                ],
                resolve_provider=True,
            ),
            diagnostic_provider=lsp.DiagnosticOptions(
                identifier="security-lsp",
                inter_file_dependencies=False,
                workspace_diagnostics=False,
            ),
            hover_provider=True,
            execute_command_provider=lsp.ExecuteCommandOptions(
                commands=[
                    "security-lsp.ignoreInline",
                    "security-lsp.ignoreConfig",
                    "security-lsp.reloadIgnoreConfig",
                ]
            ),
        ),
        server_info=lsp.ServerInfo(
            name="security-lsp",
            version="0.1.0",
        ),
    )


@server.feature(lsp.INITIALIZED)
def initialized(params: lsp.InitializedParams) -> None:
    """Handle LSP initialized notification."""
    logger.info("Server initialized successfully")
    # Load ignore configuration
    server.load_ignore_config()
    # Scan workspace on startup
    if server.workspace.root_uri:
        asyncio.create_task(scan_workspace(server.workspace.root_uri))


@server.feature(lsp.SHUTDOWN)
def shutdown(params: None) -> None:
    """Handle LSP shutdown request."""
    logger.info("Shutting down security-lsp server")
    server.executor.shutdown(wait=False)


@server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
async def did_open(params: lsp.DidOpenTextDocumentParams) -> None:
    """Handle document open - trigger scan."""
    uri = params.text_document.uri
    logger.info(f"Document opened: {uri}")
    await schedule_scan(uri, params.text_document.text)


@server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
async def did_save(params: lsp.DidSaveTextDocumentParams) -> None:
    """Handle document save - trigger scan."""
    uri = params.text_document.uri
    text = params.text or ""
    logger.info(f"Document saved: {uri}")
    await schedule_scan(uri, text)


@server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
async def did_change(params: lsp.DidChangeTextDocumentParams) -> None:
    """Handle document change - debounced scan."""
    uri = params.text_document.uri
    # Get the current document text
    doc = server.workspace.get_text_document(uri)
    await schedule_scan(uri, doc.source, debounce_ms=500)


@server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
def did_close(params: lsp.DidCloseTextDocumentParams) -> None:
    """Handle document close - clear diagnostics."""
    uri = params.text_document.uri
    logger.info(f"Document closed: {uri}")
    server.publish_diagnostics(uri, [])
    # Clear stored diagnostics
    if uri in server._diagnostics:
        del server._diagnostics[uri]
    # Cancel any pending scans
    if uri in server._debounce_tasks:
        server._debounce_tasks[uri].cancel()
        del server._debounce_tasks[uri]


async def schedule_scan(uri: str, content: str, debounce_ms: int = 0) -> None:
    """Schedule a scan with optional debouncing."""
    # Cancel any existing debounce task for this URI
    if uri in server._debounce_tasks:
        server._debounce_tasks[uri].cancel()

    async def do_scan() -> None:
        if debounce_ms > 0:
            await asyncio.sleep(debounce_ms / 1000)
        await run_scan(uri, content)

    server._debounce_tasks[uri] = asyncio.create_task(do_scan())


async def run_scan(uri: str, content: str) -> None:
    """Run security scan and publish diagnostics."""
    if server._scan_in_progress.get(uri):
        return

    server._scan_in_progress[uri] = True

    try:
        # Show progress
        async with server.progress(
            lsp.WorkDoneProgressCreateParams(
                token=f"scan-{uri}",
            )
        ) as progress:
            progress.begin(lsp.WorkDoneProgressBegin(
                title="Security Scan",
                message=f"Scanning {Path(uri).name}...",
                cancellable=False,
            ))

            diagnostics: list[lsp.Diagnostic] = []

            if server.is_dependency_file(uri):
                # Run dependency scan in background thread
                loop = asyncio.get_event_loop()
                dep_results = await loop.run_in_executor(
                    server.executor,
                    server.scanner.scan_dependencies,
                    uri,
                    content,
                )
                diagnostics.extend(create_dependency_diagnostics(dep_results, content))

            elif server.is_iac_file(uri):
                # Run IaC scan in background thread
                loop = asyncio.get_event_loop()
                iac_results = await loop.run_in_executor(
                    server.executor,
                    server.scanner.scan_iac,
                    uri,
                    content,
                )
                diagnostics.extend(create_iac_diagnostics(iac_results, content))

            # Filter out ignored vulnerabilities
            filtered_diagnostics = _filter_ignored_diagnostics(uri, content, diagnostics)
            ignored_count = len(diagnostics) - len(filtered_diagnostics)

            progress.report(lsp.WorkDoneProgressReport(
                message=f"Found {len(filtered_diagnostics)} issues ({ignored_count} ignored)",
            ))

            # Store and publish diagnostics
            server._diagnostics[uri] = filtered_diagnostics
            server.publish_diagnostics(uri, filtered_diagnostics)
            logger.info(f"Published {len(filtered_diagnostics)} diagnostics for {uri} ({ignored_count} ignored)")

            progress.end(lsp.WorkDoneProgressEnd(
                message="Scan complete",
            ))

    except Exception as e:
        logger.exception(f"Error scanning {uri}: {e}")
    finally:
        server._scan_in_progress[uri] = False


async def scan_workspace(root_uri: str) -> None:
    """Scan all relevant files in the workspace."""
    root_path = Path(root_uri.replace("file://", ""))
    logger.info(f"Scanning workspace: {root_path}")

    # Find all dependency and IaC files
    files_to_scan: list[Path] = []

    for dep_file in DEPENDENCY_FILES:
        files_to_scan.extend(root_path.rglob(dep_file))

    for ext in IAC_EXTENSIONS:
        files_to_scan.extend(root_path.rglob(f"*{ext}"))

    logger.info(f"Found {len(files_to_scan)} files to scan")

    for file_path in files_to_scan:
        if file_path.is_file():
            uri = f"file://{file_path}"
            try:
                content = file_path.read_text()
                await run_scan(uri, content)
            except Exception as e:
                logger.warning(f"Could not scan {file_path}: {e}")


def _filter_ignored_diagnostics(
    uri: str,
    content: str,
    diagnostics: list[lsp.Diagnostic],
) -> list[lsp.Diagnostic]:
    """Filter out diagnostics that are ignored by config or inline comments."""
    # Get file path from URI
    file_path = uri.replace("file://", "")

    # Determine file type for inline ignore parsing
    if "requirements" in uri.lower() or uri.endswith(".txt"):
        file_type = "requirements.txt"
    elif uri.endswith(".tf"):
        file_type = "terraform"
    elif uri.endswith((".yaml", ".yml")):
        file_type = "yaml"
    elif uri.endswith(".json"):
        file_type = "json"
    else:
        file_type = "requirements.txt"

    # Parse inline ignores
    inline_ignores = parse_inline_ignores(content, file_type)

    filtered: list[lsp.Diagnostic] = []

    for diagnostic in diagnostics:
        vuln_id = str(diagnostic.code) if diagnostic.code else ""

        # Check config-based ignore
        is_ignored, reason = server._ignore_config.is_ignored(vuln_id, file_path)
        if is_ignored:
            logger.debug(f"Ignoring {vuln_id} via config: {reason}")
            continue

        # Check inline ignore
        line_num = diagnostic.range.start.line
        if line_num in inline_ignores and vuln_id in inline_ignores[line_num]:
            logger.debug(f"Ignoring {vuln_id} via inline comment at line {line_num}")
            continue

        filtered.append(diagnostic)

    return filtered


@server.feature(lsp.TEXT_DOCUMENT_CODE_ACTION)
def code_action(params: lsp.CodeActionParams) -> list[lsp.CodeAction]:
    """Provide code actions for diagnostics."""
    uri = params.text_document.uri
    diagnostics = params.context.diagnostics

    actions = create_code_actions(uri, diagnostics, server.scanner)
    logger.info(f"Returning {len(actions)} code actions for {uri}")
    return actions


@server.feature(lsp.CODE_ACTION_RESOLVE)
def code_action_resolve(params: lsp.CodeAction) -> lsp.CodeAction:
    """Resolve code action details."""
    return params


@server.feature(lsp.TEXT_DOCUMENT_HOVER)
def hover(params: lsp.HoverParams) -> lsp.Hover | None:
    """Provide hover information for vulnerabilities."""
    uri = params.text_document.uri
    position = params.position

    # Get diagnostics for this URI
    diagnostics = server._diagnostics.get(uri, [])

    # Find diagnostic at this position
    for diagnostic in diagnostics:
        if _position_in_range(position, diagnostic.range):
            hover_content = _create_hover_content(diagnostic)
            if hover_content:
                return lsp.Hover(
                    contents=lsp.MarkupContent(
                        kind=lsp.MarkupKind.Markdown,
                        value=hover_content,
                    ),
                    range=diagnostic.range,
                )

    return None


def _position_in_range(position: lsp.Position, range: lsp.Range) -> bool:
    """Check if a position is within a range."""
    if position.line < range.start.line or position.line > range.end.line:
        return False
    if position.line == range.start.line and position.character < range.start.character:
        return False
    if position.line == range.end.line and position.character > range.end.character:
        return False
    return True


def _create_hover_content(diagnostic: lsp.Diagnostic) -> str | None:
    """Create markdown hover content for a diagnostic."""
    data = diagnostic.data
    if not isinstance(data, dict):
        return None

    vuln_type = data.get("type")
    lines: list[str] = []

    if vuln_type == "dependency":
        # Dependency vulnerability hover
        package_name = data.get("package_name", "Unknown")
        installed_version = data.get("installed_version", "Unknown")
        fix_version = data.get("fix_version")
        vuln_id = data.get("vulnerability_id", "")

        # Get severity from diagnostic
        severity_map = {
            lsp.DiagnosticSeverity.Error: "Critical/High",
            lsp.DiagnosticSeverity.Warning: "Medium",
            lsp.DiagnosticSeverity.Information: "Low",
            lsp.DiagnosticSeverity.Hint: "Unknown",
        }
        severity = severity_map.get(diagnostic.severity, "Unknown")

        # Build hover content
        code = diagnostic.code or vuln_id
        lines.append(f"**{code}** ({severity})")
        lines.append("")
        lines.append(f"**Package:** {package_name}@{installed_version}")
        lines.append("")

        if fix_version:
            lines.append(f"**Fix:** Upgrade to >= {fix_version}")
            lines.append("")

        # Add link to vulnerability database
        if code:
            if str(code).startswith("CVE-"):
                lines.append(f"[View on NVD](https://nvd.nist.gov/vuln/detail/{code})")
            elif str(code).startswith("GHSA-"):
                lines.append(f"[View on GitHub Advisory](https://github.com/advisories/{code})")
            else:
                lines.append(f"[View on OSV](https://osv.dev/vulnerability/{code})")

    elif vuln_type == "iac":
        # IaC vulnerability hover
        rule_id = data.get("rule_id", "Unknown")
        resource_type = data.get("resource_type", "Unknown")
        resource_path = data.get("resource_path", "")
        fix_code = data.get("fix_code")

        # Get severity from diagnostic
        severity_map = {
            lsp.DiagnosticSeverity.Error: "Critical/High",
            lsp.DiagnosticSeverity.Warning: "Medium",
            lsp.DiagnosticSeverity.Information: "Low",
            lsp.DiagnosticSeverity.Hint: "Unknown",
        }
        severity = severity_map.get(diagnostic.severity, "Unknown")

        # Build hover content
        lines.append(f"**{rule_id}** ({severity})")
        lines.append("")
        lines.append(f"**Resource:** {resource_type}")
        if resource_path:
            lines.append(f"**Path:** {resource_path}")
        lines.append("")

        if fix_code:
            lines.append("**Suggested fix:**")
            lines.append(f"```")
            lines.append(fix_code)
            lines.append("```")
            lines.append("")

        # Add link to documentation
        if rule_id.startswith("CKV_"):
            lines.append(f"[View on Checkov](https://www.checkov.io/5.Policy%20Index/{rule_id}.html)")

    else:
        return None

    return "\n".join(lines)


@server.command("security-lsp.ignoreInline")
async def ignore_inline(args: list[Any]) -> dict[str, Any]:
    """Add an inline ignore comment for a vulnerability."""
    if len(args) < 3:
        return {"success": False, "error": "Missing arguments"}

    uri = args[0]
    vuln_id = args[1]
    line_num = int(args[2])

    try:
        doc = server.workspace.get_text_document(uri)
        lines = doc.source.split("\n")

        if line_num >= len(lines):
            return {"success": False, "error": "Invalid line number"}

        # Determine file type
        if "requirements" in uri.lower() or uri.endswith(".txt"):
            file_type = "requirements.txt"
        elif uri.endswith(".tf"):
            file_type = "terraform"
        elif uri.endswith((".yaml", ".yml")):
            file_type = "yaml"
        elif uri.endswith(".json"):
            file_type = "json"
        else:
            file_type = "requirements.txt"

        # Create the new line with ignore comment
        new_line = create_inline_ignore_comment(file_type, vuln_id, lines[line_num])

        # Apply the edit
        edit = lsp.WorkspaceEdit(
            changes={
                uri: [
                    lsp.TextEdit(
                        range=lsp.Range(
                            start=lsp.Position(line=line_num, character=0),
                            end=lsp.Position(line=line_num, character=len(lines[line_num])),
                        ),
                        new_text=new_line,
                    )
                ]
            }
        )

        await server.apply_edit_async(edit)
        logger.info(f"Added inline ignore for {vuln_id} at line {line_num} in {uri}")
        return {"success": True}

    except Exception as e:
        logger.exception(f"Error adding inline ignore: {e}")
        return {"success": False, "error": str(e)}


@server.command("security-lsp.ignoreConfig")
async def ignore_config(args: list[Any]) -> dict[str, Any]:
    """Add a vulnerability to the ignore config file."""
    if len(args) < 2:
        return {"success": False, "error": "Missing arguments"}

    uri = args[0]
    vuln_id = args[1]
    reason = args[2] if len(args) > 2 else ""

    try:
        root_uri = server.workspace.root_uri
        if not root_uri:
            return {"success": False, "error": "No workspace root"}

        root_path = Path(root_uri.replace("file://", ""))
        config_path = root_path / ".security-use-ignore.yaml"

        # Create entry
        entry = create_ignore_config_entry(vuln_id, reason)

        if config_path.exists():
            # Append to existing file
            content = config_path.read_text()
            if "ignores:" not in content:
                content = "ignores:\n" + content
            new_content = content.rstrip() + "\n" + entry + "\n"
        else:
            # Create new file
            new_content = f"# Security vulnerability ignore configuration\n# See: https://github.com/security-use/lsp-server\n\nignores:\n{entry}\n"

        # Apply the edit via workspace edit
        config_uri = f"file://{config_path}"
        edit = lsp.WorkspaceEdit(
            document_changes=[
                lsp.CreateFile(uri=config_uri, options=lsp.CreateFileOptions(overwrite=True)),
                lsp.TextDocumentEdit(
                    text_document=lsp.OptionalVersionedTextDocumentIdentifier(
                        uri=config_uri,
                        version=None,
                    ),
                    edits=[
                        lsp.TextEdit(
                            range=lsp.Range(
                                start=lsp.Position(line=0, character=0),
                                end=lsp.Position(line=0, character=0),
                            ),
                            new_text=new_content,
                        )
                    ],
                ),
            ]
        )

        await server.apply_edit_async(edit)

        # Reload ignore config
        server.load_ignore_config()

        logger.info(f"Added {vuln_id} to ignore config")
        return {"success": True}

    except Exception as e:
        logger.exception(f"Error adding to ignore config: {e}")
        return {"success": False, "error": str(e)}


@server.command("security-lsp.reloadIgnoreConfig")
def reload_ignore_config(args: list[Any]) -> dict[str, Any]:
    """Reload the ignore configuration."""
    try:
        server.load_ignore_config()
        logger.info("Reloaded ignore configuration")
        return {"success": True}
    except Exception as e:
        logger.exception(f"Error reloading ignore config: {e}")
        return {"success": False, "error": str(e)}


def main() -> None:
    """Entry point for the LSP server."""
    logger.info("Starting security-lsp server")

    if len(sys.argv) > 1 and sys.argv[1] == "--tcp":
        host = "127.0.0.1"
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 2087
        logger.info(f"Starting TCP server on {host}:{port}")
        server.start_tcp(host, port)
    else:
        logger.info("Starting stdio server")
        server.start_io()


if __name__ == "__main__":
    main()
