"""Tests for IaC vulnerability diagnostics."""

import pytest
from lsprotocol import types as lsp

from security_lsp.scanner import IaCScanner, IaCVulnerability
from security_lsp.diagnostics import create_iac_diagnostics, severity_to_lsp


class TestIaCScanner:
    """Tests for IaC vulnerability scanner."""

    def test_scan_terraform_returns_list(self):
        """Test that scanning Terraform files returns a list."""
        scanner = IaCScanner()
        content = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
'''
        results = scanner.scan("file:///test.tf", content)
        assert isinstance(results, list)

    def test_scan_terraform_stub_public_acl(self):
        """Test stub scanner detects public S3 bucket ACL."""
        scanner = IaCScanner()
        # Force use of stub scanner
        scanner._security_use_available = False

        content = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
'''
        results = scanner.scan("file:///test.tf", content)

        assert len(results) >= 1
        public_acl_vuln = next(
            (v for v in results if v.rule_id == "CKV_AWS_19"),
            None
        )
        assert public_acl_vuln is not None
        assert public_acl_vuln.severity == "HIGH"

    def test_scan_terraform_stub_hardcoded_secret(self):
        """Test stub scanner detects hardcoded secrets."""
        scanner = IaCScanner()
        # Force use of stub scanner
        scanner._security_use_available = False

        content = '''
resource "aws_db_instance" "example" {
  identifier = "mydb"
  password   = "supersecretpassword123"
}
'''
        results = scanner.scan("file:///test.tf", content)

        secret_vuln = next(
            (v for v in results if "secret" in v.rule_id.lower() or "secret" in v.title.lower()),
            None
        )
        assert secret_vuln is not None
        assert secret_vuln.severity == "CRITICAL"

    def test_scan_non_terraform_file(self):
        """Test that non-TF files are handled gracefully."""
        scanner = IaCScanner()
        content = "This is just a text file"

        results = scanner.scan("file:///readme.md", content)
        assert isinstance(results, list)

    def test_scan_cloudformation_returns_list(self):
        """Test that scanning CloudFormation files returns a list."""
        scanner = IaCScanner()
        content = '''
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
'''
        results = scanner.scan("file:///template.yaml", content)
        assert isinstance(results, list)

    def test_get_file_type_terraform(self):
        """Test file type detection for Terraform."""
        scanner = IaCScanner()
        assert scanner._get_file_type("file:///main.tf") == "terraform"
        assert scanner._get_file_type("file:///variables.tf") == "terraform"

    def test_get_file_type_cloudformation(self):
        """Test file type detection for CloudFormation."""
        scanner = IaCScanner()
        assert scanner._get_file_type("file:///template.yaml") == "cloudformation"
        assert scanner._get_file_type("file:///stack.yml") == "cloudformation"
        assert scanner._get_file_type("file:///template.json") == "cloudformation"


class TestIaCDiagnostics:
    """Tests for IaC diagnostic creation."""

    def test_create_iac_diagnostics(self):
        """Test creating LSP diagnostics from IaC vulnerabilities."""
        vulnerabilities = [
            IaCVulnerability(
                rule_id="CKV_AWS_19",
                title="S3 Bucket has public ACL",
                severity="HIGH",
                resource_type="aws_s3_bucket",
                resource_path="aws_s3_bucket.example.acl",
                description="S3 bucket ACL allows public access",
                remediation='Set acl = "private"',
                line_number=3,
            )
        ]
        content = '''resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}'''

        diagnostics = create_iac_diagnostics(vulnerabilities, content)

        assert len(diagnostics) == 1
        diag = diagnostics[0]
        assert diag.severity == lsp.DiagnosticSeverity.Error
        assert "CKV_AWS_19" in diag.message
        assert diag.source == "security-lsp"

    def test_severity_mapping(self):
        """Test severity mapping to LSP diagnostic severity."""
        assert severity_to_lsp("CRITICAL") == lsp.DiagnosticSeverity.Error
        assert severity_to_lsp("HIGH") == lsp.DiagnosticSeverity.Error
        assert severity_to_lsp("MEDIUM") == lsp.DiagnosticSeverity.Warning
        assert severity_to_lsp("LOW") == lsp.DiagnosticSeverity.Information
        assert severity_to_lsp("UNKNOWN") == lsp.DiagnosticSeverity.Hint

    def test_diagnostic_includes_remediation(self):
        """Test that diagnostics include remediation info."""
        vulnerabilities = [
            IaCVulnerability(
                rule_id="CKV_AWS_18",
                title="S3 Bucket encryption not enabled",
                severity="MEDIUM",
                resource_type="aws_s3_bucket",
                resource_path="aws_s3_bucket.example",
                remediation="Add server_side_encryption_configuration",
            )
        ]
        content = 'resource "aws_s3_bucket" "example" {}'

        diagnostics = create_iac_diagnostics(vulnerabilities, content)

        assert len(diagnostics) == 1
        assert "encryption" in diagnostics[0].message.lower()
