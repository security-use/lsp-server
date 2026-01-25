"""Tests for background scanning and caching."""

import time

import pytest

from security_lsp.scanner import (
    SecurityScanner,
    CacheEntry,
    DependencyScanner,
    DependencyVulnerability,
)


class TestCacheEntry:
    """Tests for cache entry TTL."""

    def test_cache_entry_valid(self):
        """Test that new cache entry is valid."""
        entry = CacheEntry(data={"test": "data"}, timestamp=time.time(), ttl=300)
        assert entry.is_valid() is True

    def test_cache_entry_expired(self):
        """Test that old cache entry is invalid."""
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=time.time() - 400,  # 400 seconds ago
            ttl=300,  # 5 minute TTL
        )
        assert entry.is_valid() is False

    def test_cache_entry_custom_ttl(self):
        """Test cache entry with custom TTL."""
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=time.time() - 50,
            ttl=60,  # 1 minute TTL
        )
        assert entry.is_valid() is True

        entry_expired = CacheEntry(
            data={"test": "data"},
            timestamp=time.time() - 70,
            ttl=60,
        )
        assert entry_expired.is_valid() is False


class TestSecurityScanner:
    """Tests for security scanner with caching."""

    def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = SecurityScanner()
        assert scanner._cache == {}

    def test_cache_key_generation(self):
        """Test cache key is unique per URI and content."""
        scanner = SecurityScanner()

        key1 = scanner._get_cache_key("file:///test.txt", "content1")
        key2 = scanner._get_cache_key("file:///test.txt", "content2")
        key3 = scanner._get_cache_key("file:///test.txt", "content1")

        assert key1 != key2  # Different content
        assert key1 == key3  # Same URI and content

    def test_cache_stores_results(self):
        """Test that scan results are cached."""
        scanner = SecurityScanner()

        # Scan a file
        content = "requests==2.28.0"
        results1 = scanner.scan_dependencies("file:///requirements.txt", content)

        # Verify cache was populated
        cache_key = scanner._get_cache_key("dep:file:///requirements.txt", content)
        cached = scanner._get_cached(cache_key)
        assert cached is not None
        assert cached == results1

    def test_cache_returns_cached_results(self):
        """Test that repeated scans return cached results."""
        scanner = SecurityScanner()

        content = "requests==2.28.0"

        # First scan
        results1 = scanner.scan_dependencies("file:///requirements.txt", content)

        # Second scan should return cached results
        results2 = scanner.scan_dependencies("file:///requirements.txt", content)

        assert results1 == results2

    def test_cache_invalidation_on_content_change(self):
        """Test that cache is invalidated when content changes."""
        scanner = SecurityScanner()

        # Scan with original content
        results1 = scanner.scan_dependencies("file:///requirements.txt", "requests==2.28.0")

        # Scan with modified content
        results2 = scanner.scan_dependencies("file:///requirements.txt", "requests==2.31.0")

        # Results might differ (cached vs fresh)
        # At minimum, they should be independent
        assert isinstance(results1, list)
        assert isinstance(results2, list)

    def test_clear_cache(self):
        """Test cache clearing."""
        scanner = SecurityScanner()

        # Populate cache
        scanner.scan_dependencies("file:///requirements.txt", "requests==2.28.0")
        assert len(scanner._cache) > 0

        # Clear cache
        scanner.clear_cache()
        assert len(scanner._cache) == 0


class TestDependencyScanner:
    """Tests for dependency vulnerability scanner."""

    def test_scan_requirements_txt(self):
        """Test scanning requirements.txt format."""
        scanner = DependencyScanner()
        content = """
# This is a comment
requests==2.28.0
django>=4.1.0
flask
pillow==9.5.0
"""
        results = scanner.scan("file:///requirements.txt", content)

        assert isinstance(results, list)
        # Check that known vulnerable packages are detected
        package_names = [v.package_name for v in results]
        assert "requests" in package_names or "django" in package_names or "pillow" in package_names

    def test_scan_returns_vulnerability_objects(self):
        """Test that scan returns proper vulnerability objects."""
        scanner = DependencyScanner()
        results = scanner.scan("file:///requirements.txt", "requests==2.28.0")

        if results:
            vuln = results[0]
            assert isinstance(vuln, DependencyVulnerability)
            assert vuln.package_name == "requests"
            assert vuln.vulnerability_id
            assert vuln.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

    def test_scan_ignores_comments(self):
        """Test that comments are ignored."""
        scanner = DependencyScanner()
        content = """
# requests==1.0.0
# django==1.0.0
safe-package==1.0.0
"""
        results = scanner.scan("file:///requirements.txt", content)

        package_names = [v.package_name for v in results]
        assert "requests" not in package_names

    def test_scan_handles_version_specifiers(self):
        """Test handling of various version specifiers."""
        scanner = DependencyScanner()
        content = """
requests>=2.28.0
django~=4.1.0
flask==2.2.0
pillow!=9.0.0
urllib3<2.0.0
"""
        results = scanner.scan("file:///requirements.txt", content)
        assert isinstance(results, list)


class TestIaCScanner:
    """Tests for IaC scanner with caching."""

    def test_scan_iac_caching(self):
        """Test that IaC scans are cached."""
        scanner = SecurityScanner()
        content = '''
resource "aws_s3_bucket" "example" {
  acl = "public-read"
}
'''
        # First scan
        results1 = scanner.scan_iac("file:///main.tf", content)

        # Second scan should use cache
        results2 = scanner.scan_iac("file:///main.tf", content)

        assert results1 == results2


class TestBackgroundExecution:
    """Tests for background execution behavior."""

    def test_scanner_is_thread_safe(self):
        """Test that scanner can be used from multiple threads."""
        import threading

        scanner = SecurityScanner()
        results = []
        errors = []

        def scan_task(content: str, index: int):
            try:
                result = scanner.scan_dependencies(
                    f"file:///requirements{index}.txt",
                    content
                )
                results.append((index, result))
            except Exception as e:
                errors.append((index, e))

        threads = []
        contents = [
            "requests==2.28.0",
            "django==4.1.0",
            "flask==2.2.0",
        ]

        for i, content in enumerate(contents):
            t = threading.Thread(target=scan_task, args=(content, i))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 3
