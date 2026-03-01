"""Security scanner with background execution and caching."""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)

# Cache TTL in seconds
CACHE_TTL = 300  # 5 minutes


@dataclass
class DependencyVulnerability:
    """Represents a vulnerability in a dependency."""

    vulnerability_id: str
    package_name: str
    installed_version: str
    severity: str
    description: str = ""
    cve_id: str | None = None
    fix_version: str | None = None
    reference_url: str | None = None


@dataclass
class IaCVulnerability:
    """Represents a vulnerability in Infrastructure as Code."""

    rule_id: str
    title: str
    severity: str
    resource_type: str
    resource_path: str
    description: str = ""
    remediation: str = ""
    line_number: int | None = None
    fix_code: str | None = None
    reference_url: str | None = None
    # Compliance framework mappings (optional)
    compliance_frameworks: list[str] = field(default_factory=list)


@dataclass
class CacheEntry:
    """Cache entry with TTL."""

    data: Any
    timestamp: float
    ttl: float = CACHE_TTL

    def is_valid(self) -> bool:
        """Check if cache entry is still valid."""
        return (time.time() - self.timestamp) < self.ttl


class SecurityScanner:
    """Scanner for security vulnerabilities with caching."""

    def __init__(self) -> None:
        self._cache: dict[str, CacheEntry] = {}
        self._dependency_scanner: DependencyScanner | None = None
        self._iac_scanner: IaCScanner | None = None

    def _get_cache_key(self, uri: str, content: str) -> str:
        """Generate cache key from URI and content hash."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        return f"{uri}:{content_hash}"

    def _get_cached(self, cache_key: str) -> Any | None:
        """Get cached result if valid."""
        entry = self._cache.get(cache_key)
        if entry and entry.is_valid():
            logger.debug(f"Cache hit for {cache_key}")
            return entry.data
        return None

    def _set_cached(self, cache_key: str, data: Any) -> None:
        """Cache result with TTL."""
        self._cache[cache_key] = CacheEntry(data=data, timestamp=time.time())

    def clear_cache(self) -> None:
        """Clear all cached results."""
        self._cache.clear()

    @property
    def dependency_scanner(self) -> DependencyScanner:
        """Lazy-load dependency scanner."""
        if self._dependency_scanner is None:
            self._dependency_scanner = DependencyScanner()
        return self._dependency_scanner

    @property
    def iac_scanner(self) -> IaCScanner:
        """Lazy-load IaC scanner."""
        if self._iac_scanner is None:
            self._iac_scanner = IaCScanner()
        return self._iac_scanner

    def scan_dependencies(self, uri: str, content: str) -> list[DependencyVulnerability]:
        """Scan dependency file for vulnerabilities."""
        cache_key = self._get_cache_key(f"dep:{uri}", content)

        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        logger.info(f"Scanning dependencies in {uri}")
        results = self.dependency_scanner.scan(uri, content)

        self._set_cached(cache_key, results)
        return results

    def scan_iac(self, uri: str, content: str) -> list[IaCVulnerability]:
        """Scan IaC file for vulnerabilities."""
        cache_key = self._get_cache_key(f"iac:{uri}", content)

        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        logger.info(f"Scanning IaC in {uri}")
        results = self.iac_scanner.scan(uri, content)

        self._set_cached(cache_key, results)
        return results

    def get_fix_for_vulnerability(
        self, vuln_id: str, vuln_type: str
    ) -> dict[str, Any] | None:
        """Get fix information for a vulnerability."""
        if vuln_type == "dependency":
            return self.dependency_scanner.get_fix(vuln_id)
        elif vuln_type == "iac":
            return self.iac_scanner.get_fix(vuln_id)
        return None


class DependencyScanner:
    """Scanner for dependency vulnerabilities using security-use package."""

    def __init__(self) -> None:
        self._security_use_available = False
        self._scan_deps = None
        self._get_fix = None
        try:
            from security_use import scan_dependencies as _scan_deps
            from security_use.scanner import get_vulnerability_fix as _get_fix

            self._scan_deps = _scan_deps
            self._get_fix = _get_fix
            self._security_use_available = True
            logger.info("security-use package loaded successfully")
        except ImportError:
            logger.warning("security-use package not available, using stub scanner")

    def _get_file_type(self, uri: str) -> str:
        """Determine file type from URI."""
        uri_lower = uri.lower()
        if "requirements" in uri_lower or uri_lower.endswith(".txt"):
            return "requirements.txt"
        elif "pyproject" in uri_lower:
            return "pyproject.toml"
        elif "pipfile.lock" in uri_lower:
            return "Pipfile.lock"
        elif "pipfile" in uri_lower:
            return "Pipfile"
        elif "poetry.lock" in uri_lower:
            return "poetry.lock"
        elif "package-lock" in uri_lower:
            return "package-lock.json"
        elif "package.json" in uri_lower:
            return "package.json"
        elif "go.mod" in uri_lower:
            return "go.mod"
        elif "cargo.toml" in uri_lower:
            return "Cargo.toml"
        elif "gemfile.lock" in uri_lower:
            return "Gemfile.lock"
        elif "gemfile" in uri_lower:
            return "Gemfile"
        elif "pom.xml" in uri_lower:
            return "pom.xml"
        return "requirements.txt"

    def scan(self, uri: str, content: str) -> list[DependencyVulnerability]:
        """Scan content for dependency vulnerabilities."""
        if self._security_use_available and self._scan_deps:
            try:
                file_type = self._get_file_type(uri)
                result = self._scan_deps(file_content=content, file_type=file_type)
                return [
                    DependencyVulnerability(
                        vulnerability_id=v.id,
                        package_name=v.package,
                        installed_version=v.installed_version,
                        severity=v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                        description=v.description,
                        cve_id=v.id if v.id.startswith("CVE-") else None,
                        fix_version=v.fixed_version,
                        reference_url=v.references[0] if v.references else None,
                    )
                    for v in result.vulnerabilities
                ]
            except Exception as e:
                logger.error(f"Error scanning dependencies: {e}")

        # Stub implementation for development/testing
        return self._stub_scan(uri, content)

    def _stub_scan(self, uri: str, content: str) -> list[DependencyVulnerability]:
        """Stub scanner for testing without security-use package."""
        vulnerabilities = []

        # Parse requirements.txt format
        if "requirements" in uri.lower() or uri.endswith(".txt"):
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse package==version or package>=version
                import re

                match = re.match(r"^([a-zA-Z0-9_-]+)([=<>!~]+)?(.+)?", line)
                if match:
                    package = match.group(1).lower()
                    version = match.group(3) or "unknown"

                    # Check against known vulnerable packages (stub data)
                    if package in KNOWN_VULNERABLE_PACKAGES:
                        vuln_info = KNOWN_VULNERABLE_PACKAGES[package]
                        vulnerabilities.append(
                            DependencyVulnerability(
                                vulnerability_id=vuln_info["id"],
                                package_name=package,
                                installed_version=version.strip(),
                                severity=vuln_info["severity"],
                                description=vuln_info["description"],
                                cve_id=vuln_info.get("cve_id"),
                                fix_version=vuln_info.get("fix_version"),
                                reference_url=vuln_info.get("reference_url"),
                            )
                        )

        return vulnerabilities

    def get_fix(self, vuln_id: str, package_name: str | None = None) -> dict[str, Any] | None:
        """Get fix information for a vulnerability.

        Args:
            vuln_id: Vulnerability ID (CVE or GHSA).
            package_name: Package name (required by security-use API).

        Returns:
            Fix information dict or None.
        """
        if self._security_use_available and self._get_fix and package_name:
            try:
                fix_version = self._get_fix(vuln_id, package_name)
                if fix_version:
                    return {"fix_version": fix_version}
            except Exception as e:
                logger.error(f"Error getting fix: {e}")
        return None


class IaCScanner:
    """Scanner for IaC vulnerabilities using security-use package."""

    def __init__(self) -> None:
        self._security_use_available = False
        self._compliance_available = False
        self._scan_iac = None
        self._compliance_mapper = None
        try:
            from security_use import scan_iac as _scan_iac

            self._scan_iac = _scan_iac
            self._security_use_available = True
            logger.info("security-use IaC scanner loaded successfully")

            # Try to load compliance mapper
            try:
                from security_use.compliance import ComplianceMapper

                self._compliance_mapper = ComplianceMapper()
                self._compliance_available = True
                logger.info("Compliance mapping loaded successfully")
            except ImportError:
                logger.debug("Compliance mapping not available")
        except ImportError:
            logger.warning("security-use IaC scanner not available, using stub scanner")

    def _get_file_type(self, uri: str) -> str:
        """Determine file type from URI."""
        uri_lower = uri.lower()
        if uri_lower.endswith(".tf"):
            return "terraform"
        elif uri_lower.endswith((".yaml", ".yml")):
            return "cloudformation"
        elif uri_lower.endswith(".json"):
            return "cloudformation"
        return "terraform"

    def scan(self, uri: str, content: str) -> list[IaCVulnerability]:
        """Scan content for IaC vulnerabilities."""
        if self._security_use_available and self._scan_iac:
            try:
                file_type = self._get_file_type(uri)
                result = self._scan_iac(file_content=content, file_type=file_type)
                vulnerabilities = []
                for f in result.iac_findings:
                    # Get compliance frameworks if available
                    compliance_frameworks: list[str] = []
                    if self._compliance_available and self._compliance_mapper:
                        try:
                            mapping = self._compliance_mapper.get_mapping(f.rule_id)
                            if mapping and mapping.frameworks:
                                compliance_frameworks = [
                                    fw.value if hasattr(fw, 'value') else str(fw)
                                    for fw in mapping.frameworks
                                ]
                        except Exception as e:
                            logger.debug(f"Could not get compliance mapping: {e}")

                    vulnerabilities.append(
                        IaCVulnerability(
                            rule_id=f.rule_id,
                            title=f.title,
                            severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                            resource_type=f.resource_type,
                            resource_path=f"{f.resource_type}.{f.resource_name}",
                            description=f.description,
                            remediation=f.remediation,
                            line_number=f.line_number,
                            fix_code=f.fix_code,
                            reference_url=None,
                            compliance_frameworks=compliance_frameworks,
                        )
                    )
                return vulnerabilities
            except Exception as e:
                logger.error(f"Error scanning IaC: {e}")

        # Stub implementation for development/testing
        return self._stub_scan(uri, content)

    def _stub_scan(self, uri: str, content: str) -> list[IaCVulnerability]:
        """Stub scanner for testing without security-use package."""
        vulnerabilities = []

        # Check for common Terraform misconfigurations
        if uri.endswith(".tf"):
            vulnerabilities.extend(self._scan_terraform(content))

        # Check for CloudFormation/YAML misconfigurations
        elif uri.endswith((".yaml", ".yml")):
            vulnerabilities.extend(self._scan_cloudformation(content))

        return vulnerabilities

    def _scan_terraform(self, content: str) -> list[IaCVulnerability]:
        """Stub Terraform scanner."""
        vulnerabilities = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines):
            # Check for public S3 bucket ACL
            if "acl" in line.lower() and "public" in line.lower():
                vulnerabilities.append(
                    IaCVulnerability(
                        rule_id="CKV_AWS_19",
                        title="S3 Bucket has public ACL",
                        severity="HIGH",
                        resource_type="aws_s3_bucket",
                        resource_path="aws_s3_bucket.acl",
                        description="S3 bucket ACL allows public access",
                        remediation='Set acl = "private"',
                        line_number=line_num,
                        fix_code='  acl = "private"',
                    )
                )

            # Check for unencrypted S3 bucket
            if "aws_s3_bucket" in line and "encryption" not in content.lower():
                vulnerabilities.append(
                    IaCVulnerability(
                        rule_id="CKV_AWS_18",
                        title="S3 Bucket encryption is not enabled",
                        severity="MEDIUM",
                        resource_type="aws_s3_bucket",
                        resource_path="aws_s3_bucket.encryption",
                        description="S3 bucket does not have server-side encryption enabled",
                        remediation="Add server_side_encryption_configuration block",
                        line_number=line_num,
                    )
                )

            # Check for hardcoded secrets
            if any(
                secret_pattern in line.lower()
                for secret_pattern in ["password", "secret", "api_key", "access_key"]
            ):
                if "=" in line and ('"' in line or "'" in line):
                    vulnerabilities.append(
                        IaCVulnerability(
                            rule_id="CKV_SECRET_1",
                            title="Hardcoded secret detected",
                            severity="CRITICAL",
                            resource_type="secret",
                            resource_path="hardcoded_secret",
                            description="Hardcoded secrets should be stored in a secrets manager",
                            remediation="Use AWS Secrets Manager or environment variables",
                            line_number=line_num,
                        )
                    )

        return vulnerabilities

    def _scan_cloudformation(self, content: str) -> list[IaCVulnerability]:
        """Stub CloudFormation scanner."""
        vulnerabilities = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines):
            # Check for public access in CloudFormation
            if "PublicAccessBlock" in line and "false" in line.lower():
                vulnerabilities.append(
                    IaCVulnerability(
                        rule_id="CKV_AWS_53",
                        title="S3 bucket PublicAccessBlock is disabled",
                        severity="HIGH",
                        resource_type="AWS::S3::Bucket",
                        resource_path="PublicAccessBlockConfiguration",
                        description="S3 bucket should block public access",
                        remediation="Set all PublicAccessBlock properties to true",
                        line_number=line_num,
                    )
                )

        return vulnerabilities

    def get_fix(self, rule_id: str) -> dict[str, Any] | None:
        """Get fix information for an IaC rule.

        Note: IaC fixes are typically embedded in the scan results (fix_code field).
        This method is a placeholder for future API support.
        """
        # IaC fixes are returned inline with findings (fix_code field)
        # No separate API call needed currently
        return None


# Stub data for known vulnerable packages (for testing without security-use package)
KNOWN_VULNERABLE_PACKAGES: dict[str, dict[str, Any]] = {
    "requests": {
        "id": "GHSA-j8r2-6x86-q33q",
        "cve_id": "CVE-2023-32681",
        "severity": "MEDIUM",
        "description": "Unintended leak of Proxy-Authorization header in requests",
        "fix_version": "2.31.0",
        "reference_url": "https://github.com/advisories/GHSA-j8r2-6x86-q33q",
    },
    "django": {
        "id": "GHSA-h8gc-pgj2-vjm3",
        "cve_id": "CVE-2023-46695",
        "severity": "HIGH",
        "description": "Potential denial of service in UsernameField",
        "fix_version": "4.2.7",
        "reference_url": "https://github.com/advisories/GHSA-h8gc-pgj2-vjm3",
    },
    "flask": {
        "id": "GHSA-m2qf-hxjv-5gpq",
        "cve_id": "CVE-2023-30861",
        "severity": "HIGH",
        "description": "Cookie header parsing vulnerability",
        "fix_version": "2.3.2",
        "reference_url": "https://github.com/advisories/GHSA-m2qf-hxjv-5gpq",
    },
    "pillow": {
        "id": "GHSA-3f63-hfp8-52jq",
        "cve_id": "CVE-2023-50447",
        "severity": "CRITICAL",
        "description": "Arbitrary code execution via malicious image",
        "fix_version": "10.2.0",
        "reference_url": "https://github.com/advisories/GHSA-3f63-hfp8-52jq",
    },
    "urllib3": {
        "id": "GHSA-v845-jxx5-vc9f",
        "cve_id": "CVE-2023-45803",
        "severity": "MEDIUM",
        "description": "Cookie handling vulnerability",
        "fix_version": "2.0.7",
        "reference_url": "https://github.com/advisories/GHSA-v845-jxx5-vc9f",
    },
}
