"""Tests for quick fix code actions."""

import pytest
from lsprotocol import types as lsp

from security_lsp.code_actions import (
    create_code_actions,
    create_dependency_fix_action,
    create_iac_fix_action,
)
from security_lsp.scanner import SecurityScanner


class TestDependencyCodeActions:
    """Tests for dependency vulnerability code actions."""

    def test_create_dependency_fix_action_requirements(self):
        """Test creating fix action for requirements.txt."""
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=15),
            ),
            message="Vulnerable dependency",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            data={
                "type": "dependency",
                "package_name": "requests",
                "installed_version": "2.28.0",
                "fix_version": "2.31.0",
            },
        )

        action = create_dependency_fix_action(
            "file:///project/requirements.txt",
            diagnostic,
            diagnostic.data,
        )

        assert action is not None
        assert action.kind == lsp.CodeActionKind.QuickFix
        assert "requests" in action.title
        assert "2.31.0" in action.title
        assert action.is_preferred is True
        assert action.edit is not None
        assert action.edit.changes is not None

    def test_create_dependency_fix_action_pyproject(self):
        """Test creating fix action for pyproject.toml."""
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=5, character=4),
                end=lsp.Position(line=5, character=25),
            ),
            message="Vulnerable dependency",
            severity=lsp.DiagnosticSeverity.Warning,
            source="security-lsp",
            data={
                "type": "dependency",
                "package_name": "django",
                "installed_version": "4.1.0",
                "fix_version": "4.2.7",
            },
        )

        action = create_dependency_fix_action(
            "file:///project/pyproject.toml",
            diagnostic,
            diagnostic.data,
        )

        assert action is not None
        assert "django" in action.title
        # pyproject.toml uses quoted strings
        edit = action.edit.changes["file:///project/pyproject.toml"][0]
        assert '"' in edit.new_text

    def test_create_dependency_fix_action_no_fix_version(self):
        """Test that no action is created when fix version is unknown."""
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=10),
            ),
            message="Vulnerable dependency",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            data={
                "type": "dependency",
                "package_name": "legacy-package",
                "installed_version": "1.0.0",
                "fix_version": None,
            },
        )

        action = create_dependency_fix_action(
            "file:///project/requirements.txt",
            diagnostic,
            diagnostic.data,
        )

        assert action is None


class TestIaCCodeActions:
    """Tests for IaC vulnerability code actions."""

    def test_create_iac_fix_action_with_fix_code(self):
        """Test creating fix action when fix code is available."""
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=2, character=0),
                end=lsp.Position(line=2, character=22),
            ),
            message="CKV_AWS_19: S3 Bucket has public ACL",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            data={
                "type": "iac",
                "rule_id": "CKV_AWS_19",
                "resource_path": "aws_s3_bucket.example.acl",
                "fix_code": '  acl = "private"',
            },
        )

        action = create_iac_fix_action(
            "file:///project/main.tf",
            diagnostic,
            diagnostic.data,
        )

        assert action is not None
        assert action.kind == lsp.CodeActionKind.QuickFix
        assert "CKV_AWS_19" in action.title
        assert action.is_preferred is True
        assert action.edit is not None

    def test_create_iac_fix_action_without_fix_code(self):
        """Test creating documentation link when no fix code available."""
        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=30),
            ),
            message="CKV_AWS_18: S3 encryption not enabled",
            severity=lsp.DiagnosticSeverity.Warning,
            source="security-lsp",
            data={
                "type": "iac",
                "rule_id": "CKV_AWS_18",
                "resource_path": "aws_s3_bucket.example",
                "fix_code": None,
            },
        )

        action = create_iac_fix_action(
            "file:///project/main.tf",
            diagnostic,
            diagnostic.data,
        )

        assert action is not None
        assert action.kind == lsp.CodeActionKind.QuickFix
        # Should have a command to open documentation
        assert action.command is not None
        assert "vscode.open" in action.command.command


class TestCodeActionIntegration:
    """Integration tests for code action creation."""

    def test_create_code_actions_filters_non_security_diagnostics(self):
        """Test that non-security diagnostics are ignored."""
        scanner = SecurityScanner()
        diagnostics = [
            lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=0, character=0),
                    end=lsp.Position(line=0, character=10),
                ),
                message="Some other linter warning",
                severity=lsp.DiagnosticSeverity.Warning,
                source="other-linter",  # Not security-lsp
            )
        ]

        actions = create_code_actions(
            "file:///project/requirements.txt",
            diagnostics,
            scanner,
        )

        assert len(actions) == 0

    def test_create_code_actions_handles_multiple_diagnostics(self):
        """Test creating actions for multiple diagnostics."""
        scanner = SecurityScanner()
        diagnostics = [
            lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=0, character=0),
                    end=lsp.Position(line=0, character=15),
                ),
                message="Vulnerable: requests",
                severity=lsp.DiagnosticSeverity.Error,
                source="security-lsp",
                data={
                    "type": "dependency",
                    "package_name": "requests",
                    "installed_version": "2.28.0",
                    "fix_version": "2.31.0",
                },
            ),
            lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=1, character=0),
                    end=lsp.Position(line=1, character=12),
                ),
                message="Vulnerable: flask",
                severity=lsp.DiagnosticSeverity.Warning,
                source="security-lsp",
                data={
                    "type": "dependency",
                    "package_name": "flask",
                    "installed_version": "2.2.0",
                    "fix_version": "2.3.2",
                },
            ),
        ]

        actions = create_code_actions(
            "file:///project/requirements.txt",
            diagnostics,
            scanner,
        )

        assert len(actions) == 2
