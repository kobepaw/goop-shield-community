# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
IOC Matcher Defense

Matches Indicators of Compromise: wallet addresses, exfil endpoints,
and known injection signatures.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

logger = logging.getLogger(__name__)

# Cryptocurrency wallet patterns
_ETH_WALLET_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_BTC_WALLET_RE = re.compile(r"\b[13][a-zA-Z0-9]{25,34}\b")

# Default injection signatures (from field analysis)
_DEFAULT_SIGNATURES: list[str] = [
    "SYSTEM OVERRIDE",
    "<use_tool_send_eth>",
    "<system_instruction>",
    "ignore all previous instructions",
    "you are now DAN",
    "<|im_start|>system",
]


class IOCMatcherDefense(InlineDefense):
    """Match known Indicators of Compromise in prompts.

    Detects:
    - Cryptocurrency wallet addresses (ETH, BTC)
    - Known injection signatures
    - Known exfil endpoints
    """

    def __init__(self) -> None:
        self._bad_wallets: set[str] = set()
        self._signatures: list[str] = list(_DEFAULT_SIGNATURES)
        self._signature_patterns: list[re.Pattern] = []
        self._exfil_endpoints: set[str] = set()
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile signature patterns for efficient matching."""
        self._signature_patterns = [
            re.compile(re.escape(sig), re.IGNORECASE) for sig in self._signatures
        ]

    @property
    def name(self) -> str:
        return "ioc_matcher"

    def load_iocs(self, path: str) -> None:
        """Load IOCs from a YAML file."""
        import yaml

        p = Path(path)
        if not p.exists():
            logger.warning("IOC file not found: %s", path)
            return

        data = yaml.safe_load(p.read_text()) or {}

        for wallet in data.get("wallets", []):
            if isinstance(wallet, str):
                self._bad_wallets.add(wallet.lower())

        new_sigs = data.get("injection_signatures", [])
        for sig in new_sigs:
            if isinstance(sig, str) and sig not in self._signatures:
                self._signatures.append(sig)

        for endpoint in data.get("exfil_endpoints", []):
            if isinstance(endpoint, str):
                self._exfil_endpoints.add(endpoint.lower())

        self._compile_patterns()
        logger.info(
            "Loaded IOCs: %d wallets, %d signatures, %d endpoints",
            len(self._bad_wallets),
            len(self._signatures),
            len(self._exfil_endpoints),
        )

    def execute(self, context: DefenseContext) -> InlineVerdict:
        # Check both original (pre-HTML-escape) and current (post-normalization)
        # to avoid InputValidator's html.escape() breaking IOC signatures
        # that contain angle brackets (e.g. <use_tool_send_eth>).
        prompt = context.current_prompt
        original = context.original_prompt
        texts_to_check = [prompt] if original == prompt else [prompt, original]

        # Check injection signatures against both texts
        for text in texts_to_check:
            for pattern in self._signature_patterns:
                if pattern.search(text):
                    return InlineVerdict(
                        defense_name=self.name,
                        blocked=True,
                        filtered_prompt=prompt,
                        confidence=0.95,
                        threat_confidence=0.95,
                        details=f"Matched IOC injection signature: {pattern.pattern}",
                    )

        # Check wallet addresses against both texts
        if self._bad_wallets:
            for text in texts_to_check:
                for match in _ETH_WALLET_RE.finditer(text):
                    if match.group().lower() in self._bad_wallets:
                        return InlineVerdict(
                            defense_name=self.name,
                            blocked=True,
                            filtered_prompt=prompt,
                            confidence=0.95,
                            threat_confidence=0.95,
                            details=f"Matched known bad wallet: {match.group()[:10]}...",
                        )

        # Check for any wallet addresses (alert, don't block by default)
        eth_wallets: list[str] = []
        btc_wallets: list[str] = []
        for text in texts_to_check:
            eth_wallets.extend(_ETH_WALLET_RE.findall(text))
            btc_wallets.extend(_BTC_WALLET_RE.findall(text))
        if eth_wallets or btc_wallets:
            # If wallets found in combination with exfil patterns, block
            for text in texts_to_check:
                text_lower = text.lower()
                for endpoint in self._exfil_endpoints:
                    if endpoint in text_lower:
                        return InlineVerdict(
                            defense_name=self.name,
                            blocked=True,
                            filtered_prompt=prompt,
                            confidence=0.9,
                            threat_confidence=0.9,
                            details="Wallet address + exfil endpoint detected",
                        )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )
