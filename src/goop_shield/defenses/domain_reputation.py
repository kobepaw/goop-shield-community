# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Domain Reputation Defense

Checks URLs in prompts against known-bad domains and IOC feeds.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

logger = logging.getLogger(__name__)

# URL extraction regex (simplified but effective)
_URL_RE = re.compile(
    r"https?://([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}[^\s\"'<>]*",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"https?://([^/\s:]+)",
    re.IGNORECASE,
)

# IP-based URL pattern (these don't match _URL_RE which requires domain TLDs)
_IP_URL_RE = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE)

# Known ClawHavoc C2 IPs (Antiy/Koi reports, Feb 2026)
_CLAWHAVOC_C2_IPS: set[str] = {
    "91.92.242.30",
    "95.92.242.30",
    "96.92.242.30",
    "202.161.50.59",
    "54.91.154.110",
}

# Seed blocklist — known exfil/phishing domains from field analysis
_DEFAULT_BLOCKLIST: set[str] = {
    "webhook.site",
    "requestbin.com",
    "hookbin.com",
    "pipedream.com",
    "burpcollaborator.net",
    "interact.sh",
    "canarytokens.com",
    "ngrok.io",
    "ngrok-free.app",
    # URL shortener domains — commonly abused for redirect-based attacks
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "short.io",
}


class DomainReputationDefense(InlineDefense):
    """Block prompts containing URLs to known-bad domains.

    Ships with a seed blocklist of exfil/phishing domains and supports
    loading additional IOC feeds from YAML files.
    """

    def __init__(self) -> None:
        self._blocklist: set[str] = set(_DEFAULT_BLOCKLIST)
        self._ip_blocklist: set[str] = set(_CLAWHAVOC_C2_IPS)

    @property
    def name(self) -> str:
        return "domain_reputation"

    def load_ioc_feed(self, path: str) -> int:
        """Load additional domains from a YAML or text file.

        Returns number of domains loaded.
        """
        import yaml

        p = Path(path)
        if not p.exists():
            logger.warning("IOC feed file not found: %s", path)
            return 0

        content = p.read_text()
        if p.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content) or {}
            domains = data.get("domains", [])

            for ip in data.get("c2_ips", []):
                if isinstance(ip, str):
                    self._ip_blocklist.add(ip)
        else:
            # Plain text, one domain per line
            domains = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]

        count = 0
        for domain in domains:
            if domain and isinstance(domain, str):
                self._blocklist.add(domain.lower())
                count += 1

        logger.info("Loaded %d domains from IOC feed: %s", count, path)
        return count

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt

        # Check IP-based URLs (these don't match _URL_RE which requires domain TLDs)
        if self._ip_blocklist:
            for match in _IP_URL_RE.finditer(prompt):
                ip = match.group(1)
                if ip in self._ip_blocklist:
                    return InlineVerdict(
                        defense_name=self.name,
                        blocked=True,
                        filtered_prompt=prompt,
                        confidence=0.9,
                        threat_confidence=0.9,
                        details=f"URL contains blocklisted C2 IP: {ip}",
                    )

        # Extract all URLs
        urls = _URL_RE.findall(prompt)
        if not urls:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=1.0,
            )

        # Extract domains from URLs
        for match in _DOMAIN_RE.finditer(prompt):
            domain = match.group(1).lower()
            # Check exact match and parent domains
            parts = domain.split(".")
            for i in range(len(parts) - 1):
                check = ".".join(parts[i:])
                if check in self._blocklist:
                    return InlineVerdict(
                        defense_name=self.name,
                        blocked=True,
                        filtered_prompt=prompt,
                        confidence=0.9,
                        threat_confidence=0.9,
                        details=f"URL contains blocklisted domain: {check}",
                    )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )
