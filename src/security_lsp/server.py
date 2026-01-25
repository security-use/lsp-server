"""Main LSP server implementation using pygls."""

from __future__ import annotations

import asyncio
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from lsprotocol import types as lsp
from pygls.server import LanguageServer

from security_lsp.diagnostics import (
    create_dependency_diagnostics,
    create_iac_diagnostics,
)
from security_lsp.code_actions import create_code_actions
from security_lsp.scanner import SecurityScanner

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

            progress.report(lsp.WorkDoneProgressReport(
                message=f"Found {len(diagnostics)} issues",
            ))

            # Publish diagnostics
            server.publish_diagnostics(uri, diagnostics)
            logger.info(f"Published {len(diagnostics)} diagnostics for {uri}")

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
    """Provide hover information for diagnostics."""
    uri = params.text_document.uri
    position = params.position

    doc = server.workspace.get_text_document(uri)

    # Find any diagnostic at this position
    # This is a simplified implementation - in production you'd
    # maintain a mapping of positions to diagnostic data
    return None


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
