"""Tests for new features: hover, ignore, code lens, and diagnostic links."""

import pytest
from datetime import date, timedelta
from lsprotocol import types as lsp


class TestHoverProvider:
    """Tests for hover provider functionality."""

    def test_position_in_range_inside(self):
        """Test position inside range returns True."""
        from security_lsp.server import _position_in_range

        range_ = lsp.Range(
            start=lsp.Position(line=5, character=0),
            end=lsp.Position(line=5, character=20),
        )
        assert _position_in_range(lsp.Position(line=5, character=10), range_) is True

    def test_position_in_range_before(self):
        """Test position before range returns False."""
        from security_lsp.server import _position_in_range

        range_ = lsp.Range(
            start=lsp.Position(line=5, character=0),
            end=lsp.Position(line=5, character=20),
        )
        assert _position_in_range(lsp.Position(line=4, character=10), range_) is False

    def test_position_in_range_after(self):
        """Test position after range returns False."""
        from security_lsp.server import _position_in_range

        range_ = lsp.Range(
            start=lsp.Position(line=5, character=0),
            end=lsp.Position(line=5, character=20),
        )
        assert _position_in_range(lsp.Position(line=6, character=10), range_) is False

    def test_create_hover_content_dependency(self):
        """Test hover content for dependency vulnerabilities."""
        from security_lsp.server import _create_hover_content

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=10),
            ),
            message="test",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            code="CVE-2024-1234",
            data={
                "type": "dependency",
                "package_name": "requests",
                "installed_version": "2.28.0",
                "fix_version": "2.31.0",
                "vulnerability_id": "CVE-2024-1234",
            },
        )
        content = _create_hover_content(diagnostic)
        assert content is not None
        assert "CVE-2024-1234" in content
        assert "requests" in content
        assert "2.31.0" in content
        assert "nvd.nist.gov" in content

    def test_create_hover_content_iac(self):
        """Test hover content for IaC vulnerabilities."""
        from security_lsp.server import _create_hover_content

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=10),
            ),
            message="test",
            severity=lsp.DiagnosticSeverity.Warning,
            source="security-lsp",
            code="CKV_AWS_19",
            data={
                "type": "iac",
                "rule_id": "CKV_AWS_19",
                "resource_type": "aws_s3_bucket",
                "resource_path": "aws_s3_bucket.acl",
                "fix_code": 'acl = "private"',
            },
        )
        content = _create_hover_content(diagnostic)
        assert content is not None
        assert "CKV_AWS_19" in content
        assert "aws_s3_bucket" in content
        assert "checkov.io" in content

    def test_create_hover_content_ghsa_link(self):
        """Test hover content creates GitHub Advisory link for GHSA IDs."""
        from security_lsp.server import _create_hover_content

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=10),
            ),
            message="test",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            code="GHSA-1234-5678-abcd",
            data={
                "type": "dependency",
                "package_name": "example",
                "installed_version": "1.0.0",
                "vulnerability_id": "GHSA-1234-5678-abcd",
            },
        )
        content = _create_hover_content(diagnostic)
        assert content is not None
        assert "github.com/advisories" in content


class TestIgnoreFunctionality:
    """Tests for ignore/suppress functionality."""

    def test_ignore_rule_basic(self):
        """Test basic ignore rule matching."""
        from security_lsp.ignore import IgnoreConfig, IgnoreRule

        rule = IgnoreRule(id="CVE-2024-1234", reason="False positive")
        config = IgnoreConfig(rules=[rule])
        is_ignored, reason = config.is_ignored("CVE-2024-1234")
        assert is_ignored is True
        assert reason == "False positive"

    def test_ignore_rule_not_matching(self):
        """Test ignore rule with non-matching ID."""
        from security_lsp.ignore import IgnoreConfig, IgnoreRule

        rule = IgnoreRule(id="CVE-2024-1234", reason="Test")
        config = IgnoreConfig(rules=[rule])
        is_ignored, _ = config.is_ignored("CVE-2024-5678")
        assert is_ignored is False

    def test_ignore_rule_expired(self):
        """Test expired ignore rule is not applied."""
        from security_lsp.ignore import IgnoreConfig, IgnoreRule

        rule = IgnoreRule(
            id="CVE-2024-1234",
            reason="Expired",
            expires=date.today() - timedelta(days=1),
        )
        config = IgnoreConfig(rules=[rule])
        is_ignored, _ = config.is_ignored("CVE-2024-1234")
        assert is_ignored is False

    def test_ignore_rule_not_expired(self):
        """Test non-expired ignore rule is applied."""
        from security_lsp.ignore import IgnoreConfig, IgnoreRule

        rule = IgnoreRule(
            id="CVE-2024-1234",
            reason="Not expired",
            expires=date.today() + timedelta(days=1),
        )
        config = IgnoreConfig(rules=[rule])
        is_ignored, _ = config.is_ignored("CVE-2024-1234")
        assert is_ignored is True

    def test_ignore_rule_path_matching(self):
        """Test ignore rule with path filtering."""
        from security_lsp.ignore import IgnoreConfig, IgnoreRule

        rule = IgnoreRule(
            id="CVE-2024-1234",
            reason="Dev only",
            paths=["dev/*", "test/*"],
        )
        config = IgnoreConfig(rules=[rule])

        # Should match dev path
        is_ignored, _ = config.is_ignored("CVE-2024-1234", "dev/requirements.txt")
        assert is_ignored is True

        # Should not match prod path
        is_ignored, _ = config.is_ignored("CVE-2024-1234", "prod/requirements.txt")
        assert is_ignored is False

    def test_parse_inline_ignores_single(self):
        """Test parsing single inline ignore comment."""
        from security_lsp.ignore import parse_inline_ignores

        content = "requests==2.28.0  # security-use: ignore CVE-2024-1234"
        ignores = parse_inline_ignores(content, "requirements.txt")
        assert 0 in ignores
        assert "CVE-2024-1234" in ignores[0]

    def test_parse_inline_ignores_multiple(self):
        """Test parsing multiple CVEs in single ignore comment."""
        from security_lsp.ignore import parse_inline_ignores

        content = "requests==2.28.0  # security-use: ignore CVE-2024-1234, CVE-2024-5678"
        ignores = parse_inline_ignores(content, "requirements.txt")
        assert 0 in ignores
        assert "CVE-2024-1234" in ignores[0]
        assert "CVE-2024-5678" in ignores[0]

    def test_parse_inline_ignores_no_comment(self):
        """Test line without ignore comment is not parsed."""
        from security_lsp.ignore import parse_inline_ignores

        content = "requests==2.28.0  # some other comment"
        ignores = parse_inline_ignores(content, "requirements.txt")
        assert 0 not in ignores

    def test_create_inline_ignore_comment_new(self):
        """Test creating new inline ignore comment."""
        from security_lsp.ignore import create_inline_ignore_comment

        result = create_inline_ignore_comment(
            "requirements.txt", "CVE-2024-1234", "requests==2.28.0"
        )
        assert "security-use: ignore CVE-2024-1234" in result
        assert result.startswith("requests==2.28.0")

    def test_create_inline_ignore_comment_append(self):
        """Test appending to existing inline ignore comment."""
        from security_lsp.ignore import create_inline_ignore_comment

        result = create_inline_ignore_comment(
            "requirements.txt",
            "CVE-2024-5678",
            "requests==2.28.0  # security-use: ignore CVE-2024-1234",
        )
        assert "CVE-2024-1234" in result
        assert "CVE-2024-5678" in result

    def test_create_ignore_config_entry(self):
        """Test creating ignore config YAML entry."""
        from security_lsp.ignore import create_ignore_config_entry

        entry = create_ignore_config_entry("CVE-2024-1234", "False positive", ["dev/*"])
        assert "id: CVE-2024-1234" in entry
        assert 'reason: "False positive"' in entry
        assert "dev/*" in entry


class TestCodeActions:
    """Tests for code action functionality."""

    def test_create_ignore_inline_action(self):
        """Test creating inline ignore code action."""
        from security_lsp.code_actions import create_ignore_inline_action

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=5, character=0),
                end=lsp.Position(line=5, character=20),
            ),
            message="test",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            code="CVE-2024-1234",
            data={"type": "dependency", "package_name": "requests"},
        )
        action = create_ignore_inline_action("file:///test.txt", diagnostic, diagnostic.data)
        assert action is not None
        assert "CVE-2024-1234" in action.title
        assert "inline" in action.title.lower()
        assert action.command.command == "security-lsp.ignoreInline"

    def test_create_ignore_config_action(self):
        """Test creating config ignore code action."""
        from security_lsp.code_actions import create_ignore_config_action

        diagnostic = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=5, character=0),
                end=lsp.Position(line=5, character=20),
            ),
            message="test",
            severity=lsp.DiagnosticSeverity.Error,
            source="security-lsp",
            code="CVE-2024-1234",
            data={"type": "dependency", "package_name": "requests"},
        )
        action = create_ignore_config_action("file:///test.txt", diagnostic, diagnostic.data)
        assert action is not None
        assert "CVE-2024-1234" in action.title
        assert "config" in action.title.lower()
        assert action.command.command == "security-lsp.ignoreConfig"


class TestDiagnosticRelatedInfo:
    """Tests for diagnostic related information."""

    def test_dependency_related_info_cve(self):
        """Test related info for CVE vulnerabilities."""
        from security_lsp.diagnostics import _create_dependency_related_info
        from security_lsp.scanner import DependencyVulnerability

        vuln = DependencyVulnerability(
            vulnerability_id="GHSA-1234",
            package_name="requests",
            installed_version="2.28.0",
            severity="HIGH",
            cve_id="CVE-2024-1234",
            fix_version="2.31.0",
        )
        related = _create_dependency_related_info(vuln)
        uris = [r.location.uri for r in related]
        assert any("nvd.nist.gov" in uri for uri in uris)

    def test_dependency_related_info_ghsa(self):
        """Test related info for GHSA vulnerabilities."""
        from security_lsp.diagnostics import _create_dependency_related_info
        from security_lsp.scanner import DependencyVulnerability

        vuln = DependencyVulnerability(
            vulnerability_id="GHSA-1234-5678",
            package_name="requests",
            installed_version="2.28.0",
            severity="HIGH",
            fix_version="2.31.0",
        )
        related = _create_dependency_related_info(vuln)
        uris = [r.location.uri for r in related]
        assert any("github.com/advisories" in uri for uri in uris)

    def test_dependency_related_info_pypi_link(self):
        """Test related info includes PyPI link for fix version."""
        from security_lsp.diagnostics import _create_dependency_related_info
        from security_lsp.scanner import DependencyVulnerability

        vuln = DependencyVulnerability(
            vulnerability_id="GHSA-1234",
            package_name="requests",
            installed_version="2.28.0",
            severity="HIGH",
            fix_version="2.31.0",
        )
        related = _create_dependency_related_info(vuln)
        uris = [r.location.uri for r in related]
        assert any("pypi.org/project/requests/2.31.0" in uri for uri in uris)

    def test_iac_related_info_checkov(self):
        """Test related info for Checkov rules."""
        from security_lsp.diagnostics import _create_iac_related_info
        from security_lsp.scanner import IaCVulnerability

        vuln = IaCVulnerability(
            rule_id="CKV_AWS_19",
            title="S3 Bucket has public ACL",
            severity="HIGH",
            resource_type="aws_s3_bucket",
            resource_path="aws_s3_bucket.acl",
        )
        related = _create_iac_related_info(vuln)
        uris = [r.location.uri for r in related]
        assert any("checkov.io" in uri for uri in uris)

    def test_iac_related_info_terraform_docs(self):
        """Test related info includes Terraform docs link."""
        from security_lsp.diagnostics import _create_iac_related_info
        from security_lsp.scanner import IaCVulnerability

        vuln = IaCVulnerability(
            rule_id="CKV_AWS_19",
            title="S3 Bucket has public ACL",
            severity="HIGH",
            resource_type="aws_s3_bucket",
            resource_path="aws_s3_bucket.acl",
        )
        related = _create_iac_related_info(vuln)
        uris = [r.location.uri for r in related]
        assert any("terraform.io" in uri for uri in uris)

    def test_get_resource_type_docs_aws(self):
        """Test getting docs URL for AWS resources."""
        from security_lsp.diagnostics import _get_resource_type_docs

        assert _get_resource_type_docs("aws_s3_bucket") is not None
        assert "terraform.io" in _get_resource_type_docs("aws_s3_bucket")

    def test_get_resource_type_docs_cloudformation(self):
        """Test getting docs URL for CloudFormation resources."""
        from security_lsp.diagnostics import _get_resource_type_docs

        assert _get_resource_type_docs("AWS::S3::Bucket") is not None
        assert "aws.amazon.com" in _get_resource_type_docs("AWS::S3::Bucket")

    def test_get_resource_type_docs_unknown(self):
        """Test getting docs URL for unknown resources."""
        from security_lsp.diagnostics import _get_resource_type_docs

        assert _get_resource_type_docs("unknown_resource") is None


class TestCodeLens:
    """Tests for code lens functionality."""

    def test_code_lens_with_vulnerabilities(self):
        """Test code lens shows vulnerability count."""
        from security_lsp.server import server, code_lens

        test_uri = "file:///test/requirements.txt"
        server._diagnostics[test_uri] = [
            lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=0, character=0),
                    end=lsp.Position(line=0, character=10),
                ),
                message="Critical",
                severity=lsp.DiagnosticSeverity.Error,
                source="security-lsp",
            ),
            lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=1, character=0),
                    end=lsp.Position(line=1, character=10),
                ),
                message="Medium",
                severity=lsp.DiagnosticSeverity.Warning,
                source="security-lsp",
            ),
        ]

        params = lsp.CodeLensParams(
            text_document=lsp.TextDocumentIdentifier(uri=test_uri)
        )
        lenses = code_lens(params)

        assert len(lenses) >= 2
        assert "2 vulnerabilities" in lenses[0].command.title
        assert "1 critical" in lenses[0].command.title.lower()
        assert "1 medium" in lenses[0].command.title.lower()

        # Clean up
        del server._diagnostics[test_uri]

    def test_code_lens_no_vulnerabilities(self):
        """Test code lens shows no vulnerabilities message."""
        from security_lsp.server import server, code_lens

        test_uri = "file:///test/requirements.txt"
        server._diagnostics[test_uri] = []

        params = lsp.CodeLensParams(
            text_document=lsp.TextDocumentIdentifier(uri=test_uri)
        )
        lenses = code_lens(params)

        assert len(lenses) >= 1
        assert "No vulnerabilities" in lenses[0].command.title

        # Clean up
        del server._diagnostics[test_uri]

    def test_code_lens_scan_now(self):
        """Test code lens includes scan now action."""
        from security_lsp.server import server, code_lens

        test_uri = "file:///test/requirements.txt"
        server._diagnostics[test_uri] = []

        params = lsp.CodeLensParams(
            text_document=lsp.TextDocumentIdentifier(uri=test_uri)
        )
        lenses = code_lens(params)

        scan_lens = [l for l in lenses if "Scan now" in l.command.title]
        assert len(scan_lens) == 1
        assert scan_lens[0].command.command == "security-lsp.scanFile"

        # Clean up
        del server._diagnostics[test_uri]

    def test_code_lens_non_supported_file(self):
        """Test code lens not shown for non-supported files."""
        from security_lsp.server import code_lens

        params = lsp.CodeLensParams(
            text_document=lsp.TextDocumentIdentifier(uri="file:///test/README.md")
        )
        lenses = code_lens(params)
        assert len(lenses) == 0
