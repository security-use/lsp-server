"""Ignore/suppress vulnerability management."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IgnoreRule:
    """Represents a vulnerability ignore rule."""

    id: str  # CVE ID or rule ID
    reason: str = ""
    expires: date | None = None
    paths: list[str] = field(default_factory=list)


@dataclass
class IgnoreConfig:
    """Configuration for ignored vulnerabilities."""

    rules: list[IgnoreRule] = field(default_factory=list)

    def is_ignored(self, vuln_id: str, file_path: str | None = None) -> tuple[bool, str]:
        """Check if a vulnerability is ignored.

        Returns (is_ignored, reason).
        """
        today = date.today()

        for rule in self.rules:
            if rule.id != vuln_id:
                continue

            # Check if expired
            if rule.expires and rule.expires < today:
                continue

            # Check path filter
            if rule.paths and file_path:
                import fnmatch

                path_matches = any(fnmatch.fnmatch(file_path, pattern) for pattern in rule.paths)
                if not path_matches:
                    continue

            return (True, rule.reason)

        return (False, "")


def load_ignore_config(workspace_root: str | None) -> IgnoreConfig:
    """Load ignore configuration from workspace."""
    config = IgnoreConfig()

    if not workspace_root:
        return config

    root_path = Path(workspace_root.replace("file://", ""))

    # Try to load ignore config file
    config_names = [
        ".security-use-ignore.yaml",
        ".security-use-ignore.yml",
        ".securityignore.yaml",
        ".securityignore.yml",
    ]

    for config_name in config_names:
        config_path = root_path / config_name
        if config_path.exists():
            try:
                config = _parse_ignore_file(config_path)
                logger.info(f"Loaded ignore config from {config_path}")
                break
            except Exception as e:
                logger.warning(f"Error loading ignore config from {config_path}: {e}")

    return config


def _parse_ignore_file(config_path: Path) -> IgnoreConfig:
    """Parse an ignore configuration file."""
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, cannot parse ignore config")
        return IgnoreConfig()

    content = config_path.read_text()
    data = yaml.safe_load(content)

    if not data or not isinstance(data, dict):
        return IgnoreConfig()

    rules: list[IgnoreRule] = []
    ignores = data.get("ignores", [])

    for item in ignores:
        if not isinstance(item, dict):
            continue

        vuln_id = item.get("id", "")
        if not vuln_id:
            continue

        reason = item.get("reason", "")
        paths = item.get("paths", [])

        # Parse expiration date
        expires = None
        expires_str = item.get("expires")
        if expires_str:
            try:
                if isinstance(expires_str, date):
                    expires = expires_str
                else:
                    expires = date.fromisoformat(str(expires_str))
            except ValueError:
                logger.warning(f"Invalid expires date for {vuln_id}: {expires_str}")

        rules.append(
            IgnoreRule(
                id=vuln_id,
                reason=reason,
                expires=expires,
                paths=paths if isinstance(paths, list) else [],
            )
        )

    return IgnoreConfig(rules=rules)


# Inline comment patterns for different file types
INLINE_IGNORE_PATTERNS = {
    # requirements.txt: package==1.0.0  # security-use: ignore CVE-2024-1234
    "requirements": re.compile(
        r"#\s*security-use:\s*ignore\s+([\w\-,\s]+)",
        re.IGNORECASE,
    ),
    # Terraform: # security-use: ignore CKV_AWS_19
    "terraform": re.compile(
        r"#\s*security-use:\s*ignore\s+([\w\-,\s]+)",
        re.IGNORECASE,
    ),
    # YAML: # security-use: ignore CKV_AWS_53
    "yaml": re.compile(
        r"#\s*security-use:\s*ignore\s+([\w\-,\s]+)",
        re.IGNORECASE,
    ),
    # JSON (in comments is not standard, but some tools support it)
    "json": re.compile(
        r"//\s*security-use:\s*ignore\s+([\w\-,\s]+)",
        re.IGNORECASE,
    ),
}


def parse_inline_ignores(content: str, file_type: str) -> dict[int, list[str]]:
    """Parse inline ignore comments from file content.

    Returns a mapping of line number to list of ignored vulnerability IDs.
    """
    ignores: dict[int, list[str]] = {}

    # Determine pattern based on file type
    if file_type in ("requirements.txt", "pyproject.toml", "Pipfile"):
        pattern = INLINE_IGNORE_PATTERNS["requirements"]
    elif file_type == "terraform":
        pattern = INLINE_IGNORE_PATTERNS["terraform"]
    elif file_type in ("yaml", "yml", "cloudformation"):
        pattern = INLINE_IGNORE_PATTERNS["yaml"]
    elif file_type == "json":
        pattern = INLINE_IGNORE_PATTERNS["json"]
    else:
        pattern = INLINE_IGNORE_PATTERNS["requirements"]

    lines = content.split("\n")
    for line_num, line in enumerate(lines):
        match = pattern.search(line)
        if match:
            # Parse comma-separated IDs
            ids_str = match.group(1)
            ids = [id.strip() for id in ids_str.split(",") if id.strip()]
            if ids:
                ignores[line_num] = ids

    return ignores


def create_inline_ignore_comment(
    file_type: str,
    vuln_id: str,
    existing_line: str,
) -> str:
    """Create an inline ignore comment for a vulnerability.

    Returns the line with the ignore comment appended.
    """
    existing_line = existing_line.rstrip()

    # Check if there's already an ignore comment
    for pattern in INLINE_IGNORE_PATTERNS.values():
        match = pattern.search(existing_line)
        if match:
            # Append to existing ignore list
            ids_str = match.group(1)
            existing_ids = [id.strip() for id in ids_str.split(",")]
            if vuln_id not in existing_ids:
                existing_ids.append(vuln_id)
                new_ids = ", ".join(existing_ids)
                return pattern.sub(f"# security-use: ignore {new_ids}", existing_line)
            return existing_line  # Already ignored

    # Add new ignore comment
    if file_type == "json":
        return f"{existing_line}  // security-use: ignore {vuln_id}"
    else:
        return f"{existing_line}  # security-use: ignore {vuln_id}"


def create_ignore_config_entry(
    vuln_id: str, reason: str = "", paths: list[str] | None = None
) -> str:
    """Create a YAML entry for the ignore config file."""
    lines = [f"  - id: {vuln_id}"]
    if reason:
        lines.append(f'    reason: "{reason}"')
    if paths:
        lines.append("    paths:")
        for path in paths:
            lines.append(f'      - "{path}"')
    return "\n".join(lines)
