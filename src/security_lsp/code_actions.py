"""Code actions for fixing security vulnerabilities."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from lsprotocol import types as lsp

if TYPE_CHECKING:
    from security_lsp.scanner import SecurityScanner


def create_code_actions(
    uri: str,
    diagnostics: list[lsp.Diagnostic],
    scanner: SecurityScanner,
) -> list[lsp.CodeAction]:
    """Create code actions for the given diagnostics."""
    actions: list[lsp.CodeAction] = []

    for diagnostic in diagnostics:
        if diagnostic.source != "security-lsp":
            continue

        data = diagnostic.data
        if not isinstance(data, dict):
            continue

        vuln_type = data.get("type")

        if vuln_type == "dependency":
            action = create_dependency_fix_action(uri, diagnostic, data)
            if action:
                actions.append(action)

        elif vuln_type == "iac":
            action = create_iac_fix_action(uri, diagnostic, data)
            if action:
                actions.append(action)

        # Add ignore actions for all vulnerability types
        ignore_inline_action = create_ignore_inline_action(uri, diagnostic, data)
        if ignore_inline_action:
            actions.append(ignore_inline_action)

        ignore_config_action = create_ignore_config_action(uri, diagnostic, data)
        if ignore_config_action:
            actions.append(ignore_config_action)

    return actions


def create_dependency_fix_action(
    uri: str,
    diagnostic: lsp.Diagnostic,
    data: dict[str, Any],
) -> lsp.CodeAction | None:
    """Create a code action to update a vulnerable dependency."""
    package_name = data.get("package_name")
    fix_version = data.get("fix_version")

    if not package_name or not fix_version:
        return None

    # Determine the edit based on file type
    if uri.endswith("requirements.txt") or "requirements" in uri:
        new_text = f"{package_name}>={fix_version}"
    elif uri.endswith("pyproject.toml"):
        new_text = f'"{package_name}>={fix_version}"'
    elif uri.endswith("package.json"):
        new_text = f'"{package_name}": "^{fix_version}"'
    else:
        new_text = f"{package_name}>={fix_version}"

    edit = lsp.WorkspaceEdit(
        changes={
            uri: [
                lsp.TextEdit(
                    range=diagnostic.range,
                    new_text=new_text,
                )
            ]
        }
    )

    return lsp.CodeAction(
        title=f"Update {package_name} to {fix_version}",
        kind=lsp.CodeActionKind.QuickFix,
        diagnostics=[diagnostic],
        is_preferred=True,
        edit=edit,
    )


def create_iac_fix_action(
    uri: str,
    diagnostic: lsp.Diagnostic,
    data: dict[str, Any],
) -> lsp.CodeAction | None:
    """Create a code action to fix an IaC vulnerability."""
    rule_id = data.get("rule_id")
    fix_code = data.get("fix_code")

    if not fix_code:
        # No automatic fix available - provide a manual fix suggestion
        return lsp.CodeAction(
            title=f"View fix for {rule_id}",
            kind=lsp.CodeActionKind.QuickFix,
            diagnostics=[diagnostic],
            command=lsp.Command(
                title="Open Documentation",
                command="vscode.open",
                arguments=[f"https://www.checkov.io/5.Policy%20Index/{rule_id}.html"],
            ),
        )

    edit = lsp.WorkspaceEdit(
        changes={
            uri: [
                lsp.TextEdit(
                    range=diagnostic.range,
                    new_text=fix_code,
                )
            ]
        }
    )

    return lsp.CodeAction(
        title=f"Apply fix for {rule_id}",
        kind=lsp.CodeActionKind.QuickFix,
        diagnostics=[diagnostic],
        is_preferred=True,
        edit=edit,
    )


def create_ignore_inline_action(
    uri: str,
    diagnostic: lsp.Diagnostic,
    data: dict[str, Any],
) -> lsp.CodeAction | None:
    """Create a code action to add an inline ignore comment."""
    code = diagnostic.code
    if not code:
        return None

    return lsp.CodeAction(
        title=f"Ignore {code} (inline comment)",
        kind=lsp.CodeActionKind.QuickFix,
        diagnostics=[diagnostic],
        is_preferred=False,
        command=lsp.Command(
            title="Add inline ignore comment",
            command="security-lsp.ignoreInline",
            arguments=[uri, str(code), diagnostic.range.start.line],
        ),
    )


def create_ignore_config_action(
    uri: str,
    diagnostic: lsp.Diagnostic,
    data: dict[str, Any],
) -> lsp.CodeAction | None:
    """Create a code action to add to ignore config file."""
    code = diagnostic.code
    if not code:
        return None

    return lsp.CodeAction(
        title=f"Ignore {code} (add to config)",
        kind=lsp.CodeActionKind.QuickFix,
        diagnostics=[diagnostic],
        is_preferred=False,
        command=lsp.Command(
            title="Add to ignore config",
            command="security-lsp.ignoreConfig",
            arguments=[uri, str(code)],
        ),
    )


def create_ignore_action(
    uri: str,
    diagnostic: lsp.Diagnostic,
    data: dict[str, Any],
) -> lsp.CodeAction:
    """Create a code action to ignore/suppress a vulnerability (legacy)."""
    vuln_type = data.get("type")
    code = diagnostic.code

    if vuln_type == "dependency":
        title = f"Ignore {code}"
    else:
        title = f"Ignore {code} (add inline comment)"

    return lsp.CodeAction(
        title=title,
        kind=lsp.CodeActionKind.QuickFix,
        diagnostics=[diagnostic],
        is_preferred=False,
        command=lsp.Command(
            title="Add to ignore list",
            command="security-lsp.ignore",
            arguments=[uri, code],
        ),
    )
