"""Diagnostics creation for security vulnerabilities."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from lsprotocol import types as lsp

if TYPE_CHECKING:
    from security_lsp.scanner import DependencyVulnerability, IaCVulnerability


def severity_to_lsp(severity: str) -> lsp.DiagnosticSeverity:
    """Map CVE/rule severity to LSP diagnostic severity."""
    severity_upper = severity.upper()
    if severity_upper in ("CRITICAL", "HIGH"):
        return lsp.DiagnosticSeverity.Error
    elif severity_upper == "MEDIUM":
        return lsp.DiagnosticSeverity.Warning
    elif severity_upper == "LOW":
        return lsp.DiagnosticSeverity.Information
    else:
        return lsp.DiagnosticSeverity.Hint


def find_package_position(content: str, package_name: str) -> tuple[int, int, int, int]:
    """Find the line and character position of a package in the content.

    Returns (start_line, start_char, end_line, end_char).
    """
    lines = content.split("\n")
    package_lower = package_name.lower()

    for line_num, line in enumerate(lines):
        line_lower = line.lower()
        # Handle various formats:
        # requirements.txt: package==1.0.0, package>=1.0.0, package
        # pyproject.toml: "package>=1.0.0", 'package>=1.0.0'
        # package.json: "package": "^1.0.0"

        # Try to find the package name
        patterns = [
            rf'\b{re.escape(package_lower)}[=<>!\[\]@~\s,"\']',  # package with version spec
            rf'"{re.escape(package_lower)}"',  # quoted package name
            rf"'{re.escape(package_lower)}'",  # single quoted
            rf'^{re.escape(package_lower)}$',  # exact match
        ]

        for pattern in patterns:
            match = re.search(pattern, line_lower)
            if match:
                start_char = match.start()
                # Find the end of the package specification
                end_char = len(line.rstrip())
                return (line_num, start_char, line_num, end_char)

    # Default to first line if not found
    return (0, 0, 0, len(lines[0]) if lines else 0)


def find_iac_position(content: str, resource_path: str, line_hint: int | None = None) -> tuple[int, int, int, int]:
    """Find the position of an IaC resource in the content.

    Returns (start_line, start_char, end_line, end_char).
    """
    lines = content.split("\n")

    # If we have a line hint, use it
    if line_hint is not None and 0 <= line_hint < len(lines):
        line = lines[line_hint]
        return (line_hint, 0, line_hint, len(line))

    # Try to find the resource by path components
    path_parts = resource_path.split(".")

    for line_num, line in enumerate(lines):
        # Look for resource definitions in Terraform
        if 'resource "' in line or "resource '" in line:
            for part in path_parts:
                if part in line:
                    return (line_num, 0, line_num, len(line))

        # Look for property names
        for part in path_parts:
            if part in line:
                return (line_num, 0, line_num, len(line))

    # Default to first line
    return (0, 0, 0, len(lines[0]) if lines else 0)


def create_dependency_diagnostics(
    vulnerabilities: list[DependencyVulnerability],
    content: str,
) -> list[lsp.Diagnostic]:
    """Create LSP diagnostics for dependency vulnerabilities."""
    diagnostics: list[lsp.Diagnostic] = []

    for vuln in vulnerabilities:
        start_line, start_char, end_line, end_char = find_package_position(
            content, vuln.package_name
        )

        # Build message with CVE details
        message_parts = [f"Vulnerable dependency: {vuln.package_name}@{vuln.installed_version}"]

        if vuln.cve_id:
            message_parts.append(f"CVE: {vuln.cve_id}")

        message_parts.append(f"Severity: {vuln.severity}")

        if vuln.fix_version:
            message_parts.append(f"Fix: Upgrade to {vuln.fix_version}")

        if vuln.description:
            message_parts.append(f"Details: {vuln.description}")

        message = " | ".join(message_parts)

        # Create diagnostic with code linking to CVE
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=start_line, character=start_char),
                end=lsp.Position(line=end_line, character=end_char),
            ),
            message=message,
            severity=severity_to_lsp(vuln.severity),
            source="security-lsp",
            code=vuln.cve_id or vuln.vulnerability_id,
            code_description=lsp.CodeDescription(
                href=vuln.reference_url or f"https://osv.dev/vulnerability/{vuln.vulnerability_id}"
            ) if vuln.cve_id or vuln.vulnerability_id else None,
            tags=[lsp.DiagnosticTag.Deprecated] if vuln.severity.upper() == "CRITICAL" else None,
            data={
                "type": "dependency",
                "package_name": vuln.package_name,
                "installed_version": vuln.installed_version,
                "fix_version": vuln.fix_version,
                "vulnerability_id": vuln.vulnerability_id,
            },
        )

        diagnostics.append(diagnostic)

    return diagnostics


def create_iac_diagnostics(
    vulnerabilities: list[IaCVulnerability],
    content: str,
) -> list[lsp.Diagnostic]:
    """Create LSP diagnostics for IaC vulnerabilities."""
    diagnostics: list[lsp.Diagnostic] = []

    for vuln in vulnerabilities:
        start_line, start_char, end_line, end_char = find_iac_position(
            content, vuln.resource_path, vuln.line_number
        )

        # Build message with rule details
        message_parts = [f"{vuln.rule_id}: {vuln.title}"]

        if vuln.description:
            message_parts.append(vuln.description)

        if vuln.remediation:
            message_parts.append(f"Fix: {vuln.remediation}")

        message = " | ".join(message_parts)

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=start_line, character=start_char),
                end=lsp.Position(line=end_line, character=end_char),
            ),
            message=message,
            severity=severity_to_lsp(vuln.severity),
            source="security-lsp",
            code=vuln.rule_id,
            code_description=lsp.CodeDescription(
                href=vuln.reference_url or f"https://www.checkov.io/5.Policy%20Index/{vuln.rule_id}.html"
            ) if vuln.rule_id else None,
            data={
                "type": "iac",
                "rule_id": vuln.rule_id,
                "resource_path": vuln.resource_path,
                "resource_type": vuln.resource_type,
                "fix_code": vuln.fix_code,
            },
        )

        diagnostics.append(diagnostic)

    return diagnostics
